package endpoints

import (
	"net/url"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

type constSlot struct {
	val     string
	clashed bool
}

type resolvedScriptAuthz struct {
	routeRoles map[string][]string
	routePerms map[string][]string
	roles      []string
	perms      []string
	rules      []jsapi.AuthzRule
}

func normalizeESMURL(raw string) string {
	base, _, _ := strings.Cut(raw, "#")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

func scriptOrigins(urls []string) []string {
	if len(urls) == 0 {
		return []string{""}
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range urls {
		o := originOf(raw)
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func isValidLinkedAuthzToken(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	first, last := s[0], s[len(s)-1]
	if first == ':' || first == '.' || first == '-' || last == ':' || last == '.' || last == '-' {
		return false
	}
	hasAlpha := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasAlpha = true
		case c >= '0' && c <= '9', c == '_', c == ':', c == '.', c == '*', c == '-':
		default:
			return false
		}
	}
	if !hasAlpha && s != "*:*" {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "false", "null", "undefined", "nan", "infinity":
		return false
	}
	return true
}

func isValidLinkedRouteToken(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	return !strings.ContainsAny(s, " \t\r\n<>\"'`\\{}")
}

// resolveScriptAuthzConsts links cross-chunk constant/enum exports across
// same-origin scripts (with clash detection and CJS module.exports fallback)
// without mutating any cached Script/jsapi.Result structs.
func resolveScriptAuthzConsts(scripts []Script) map[int]*resolvedScriptAuthz {
	need := false
	for i := range scripts {
		if len(scripts[i].UnresolvedRoutePerms) > 0 || len(scripts[i].UnresolvedAuthzRules) > 0 {
			need = true
			break
		}
	}
	if !need {
		return nil
	}

	table := map[[4]string]constSlot{}
	put := func(scope, mod, exp, key, val string) {
		if val == "" {
			return
		}
		tk := [4]string{scope, mod, exp, key}
		if cur, exists := table[tk]; exists {
			if cur.val != val {
				cur.clashed = true
				table[tk] = cur
			}
			return
		}
		table[tk] = constSlot{val: val}
	}

	for i := range scripts {
		s := &scripts[i]
		if len(s.ConstExports) == 0 || isTrackerScript(*s) {
			continue
		}
		origs := scriptOrigins(s.URLs)
		for _, cd := range s.ConstExports {
			if cd.Module == "" {
				// ES module export: key by normalized script URL (plus empty scope for unit tests without URLs).
				if len(s.URLs) == 0 {
					for k, v := range cd.Values {
						put("esm:", "", cd.Export, k, v)
					}
					if cd.Scalar != "" {
						put("esm:", "", cd.Export, "", cd.Scalar)
					}
					continue
				}
				for _, rawU := range s.URLs {
					nu := normalizeESMURL(rawU)
					if nu == "" {
						continue
					}
					for k, v := range cd.Values {
						put("esm:"+nu, "", cd.Export, k, v)
					}
					if cd.Scalar != "" {
						put("esm:"+nu, "", cd.Export, "", cd.Scalar)
					}
				}
				continue
			}
			for _, orig := range origs {
				for k, v := range cd.Values {
					put(orig, cd.Module, cd.Export, k, v)
				}
				if cd.Scalar != "" {
					put(orig, cd.Module, cd.Export, "", cd.Scalar)
				}
			}
		}
	}
	if len(table) == 0 {
		return nil
	}

	lookupInScope := func(scope, mod, exp, key string) (string, bool) {
		if sl, exists := table[[4]string{scope, mod, exp, key}]; exists {
			if sl.clashed {
				return "", false
			}
			return sl.val, true
		}
		// Webpack CJS interop (`o = n.n(n("1234")); o.a.READ` or `import d from ...`)
		// accesses Export "a" or "default" on a `module.exports = {...}` ("*") export.
		if exp == "a" || exp == "default" {
			if sl, exists := table[[4]string{scope, mod, "*", key}]; exists && !sl.clashed {
				return sl.val, true
			}
		}
		return "", false
	}

	lookup := func(s *Script, ref *jsapi.ConstRef) (string, bool) {
		if ref == nil {
			return "", false
		}
		if strings.HasPrefix(ref.Module, "./") || strings.HasPrefix(ref.Module, "../") || strings.HasPrefix(ref.Module, "/") {
			if len(s.URLs) == 0 {
				return lookupInScope("esm:", "", ref.Export, ref.Key)
			}
			var resolved string
			for _, rawU := range s.URLs {
				base, err := url.Parse(normalizeESMURL(rawU))
				if err != nil {
					continue
				}
				rel, err := base.Parse(ref.Module)
				if err != nil {
					continue
				}
				v, ok := lookupInScope("esm:"+normalizeESMURL(rel.String()), "", ref.Export, ref.Key)
				if !ok {
					continue
				}
				if resolved != "" && resolved != v {
					return "", false
				}
				resolved = v
			}
			return resolved, resolved != ""
		}

		origs := scriptOrigins(s.URLs)
		var resolved string
		for _, orig := range origs {
			v, ok := lookupInScope(orig, ref.Module, ref.Export, ref.Key)
			if !ok {
				continue
			}
			if resolved != "" && resolved != v {
				return "", false
			}
			resolved = v
		}
		return resolved, resolved != ""
	}

	out := map[int]*resolvedScriptAuthz{}
	getAcc := func(idx int) *resolvedScriptAuthz {
		acc := out[idx]
		if acc == nil {
			acc = &resolvedScriptAuthz{
				routeRoles: map[string][]string{},
				routePerms: map[string][]string{},
			}
			out[idx] = acc
		}
		return acc
	}

	for i := range scripts {
		s := &scripts[i]
		if isTrackerScript(*s) {
			continue
		}
		for _, urp := range s.UnresolvedRoutePerms {
			if urp.Path == "" {
				continue
			}
			act := urp.ActionLit
			if urp.Action != nil {
				v, ok := lookup(s, urp.Action)
				if !ok {
					continue
				}
				act = v
			}
			subj := urp.SubjectLit
			if urp.Subject != nil {
				v, ok := lookup(s, urp.Subject)
				if !ok {
					continue
				}
				subj = v
			}
			if urp.IsRole {
				if isValidLinkedRouteToken(act) {
					acc := getAcc(i)
					acc.routeRoles[urp.Path] = append(acc.routeRoles[urp.Path], act)
				}
				continue
			}
			var tok string
			switch {
			case act != "" && subj != "":
				tok = act + ":" + subj
			case act != "":
				tok = act
			case subj != "":
				tok = subj
			}
			if isValidLinkedRouteToken(tok) {
				acc := getAcc(i)
				acc.routePerms[urp.Path] = append(acc.routePerms[urp.Path], tok)
			}
		}

		for _, uar := range s.UnresolvedAuthzRules {
			act := uar.ActionLit
			if uar.Action != nil {
				v, ok := lookup(s, uar.Action)
				if !ok {
					continue
				}
				act = v
			}
			subj := uar.SubjectLit
			if uar.Subject != nil {
				v, ok := lookup(s, uar.Subject)
				if !ok {
					continue
				}
				subj = v
			}
			switch uar.Kind {
			case "role":
				if isValidLinkedAuthzToken(act) {
					acc := getAcc(i)
					acc.roles = append(acc.roles, act)
				}
			case "perm":
				if isValidLinkedAuthzToken(act) {
					acc := getAcc(i)
					acc.perms = append(acc.perms, act)
				}
			case "rule":
				if !isValidLinkedAuthzToken(act) {
					continue
				}
				if subj != "" && !isValidLinkedAuthzToken(subj) {
					continue
				}
				acc := getAcc(i)
				acc.rules = append(acc.rules, jsapi.AuthzRule{Action: act, Subject: subj})
			}
		}
	}
	return out
}
