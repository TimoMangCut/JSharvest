package replay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/session"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// jwtClaims reads the claims of a JWT held by a header value (Bearer or
// bare); nil when it is none.
func jwtClaims(v string) map[string]any {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "Bearer "), "bearer "))
	parts := strings.Split(v, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func jwtSubject(v string) string {
	s, _ := jwtClaims(v)["sub"].(string)
	return s
}

func jwtExp(v string) time.Time {
	if f, ok := jwtClaims(v)["exp"].(float64); ok && f > 0 {
		return time.Unix(int64(f), 0)
	}
	return time.Time{}
}

// jwtLifetimes warns of a token that will not live as long as the run may.
func jwtLifetimes(id *Identity, now time.Time, run time.Duration) []string {
	names := make([]string, 0, len(id.Creds))
	for n := range id.Creds {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		if exp := jwtExp(id.Creds[n]); !exp.IsZero() && exp.Sub(now) < run {
			out = append(out, fmt.Sprintf("%s holds a token that expires in %s, before the run may end (%s at -max and -rate)", n, exp.Sub(now).Round(time.Second), run.Round(time.Second)))
		}
	}
	return out
}

type storageLeaf struct{ key, val string }

// storageLeaves are the string values of a snapshot's localStorage and
// sessionStorage, those of a JSON value one by one (a token kept inside
// an object), under the leaf's own name.
func storageLeaves(snap *session.Snapshot) []storageLeaf {
	if snap == nil {
		return nil
	}
	var out []storageLeaf
	var add func(key string, v any, depth int)
	add = func(key string, v any, depth int) {
		if depth > 6 {
			return
		}
		switch x := v.(type) {
		case string:
			if t := strings.TrimSpace(x); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
				var in any
				if json.Unmarshal([]byte(t), &in) == nil {
					add(key, in, depth+1)
					return
				}
			}
			out = append(out, storageLeaf{key, x})
		case map[string]any:
			for k, y := range x {
				add(k, y, depth+1)
			}
		case []any:
			for _, y := range x {
				add(key, y, depth+1)
			}
		}
	}
	origins := make([]string, 0, len(snap.Storage))
	for o := range snap.Storage {
		origins = append(origins, o)
	}
	sort.Strings(origins)
	for _, o := range origins {
		st := snap.Storage[o]
		for _, m := range []map[string]string{st.Local, st.Session} {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				add(k, m[k], 0)
			}
		}
	}
	return out
}

// resolveStorageCreds brings the credential headers of an identity up to
// what the live snapshot's storage holds (docs/gd7-bola-design.md 2.2 and 8,
// point 11): a JWT that expired (or is not the newest) is replaced by one in
// the storage of the same issuer and subject that expires later; an opaque
// token is replaced by the value now under the storage key that held it.
// The key is found by the value (the recorded one equal to a storage
// value), else, when only one storage value of a credential's name has the
// token's shape, by that. What cannot be found is left as recorded, and said.
func resolveStorageCreds(id *Identity, snap *session.Snapshot, entries []traffic.Entry, now time.Time, note func(string)) {
	leaves := storageLeaves(snap)
	if len(leaves) == 0 {
		return
	}
	// A header whose newest value was an expired token is not in id.Creds:
	// NewIdentity noted it. Find it again.
	expired := map[string]string{}
	for i := len(entries) - 1; i >= 0; i-- {
		for k, v := range entries[i].Headers {
			n := strings.ToLower(k)
			if _, have := id.Creds[n]; !have && credential(n) && expiredJWT(v, now) {
				if _, ok := expired[n]; !ok {
					expired[n] = v
				}
			}
		}
	}
	for n, v := range expired {
		if nv, ok := freshJWT(leaves, v, now); ok {
			id.Creds[n] = nv
			note(n + " was an expired token: the storage of the snapshot holds a later one")
		}
	}
	names := make([]string, 0, len(id.Creds))
	for n := range id.Creds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := id.Creds[n]
		prefix, tok := "", strings.TrimSpace(v)
		// A scheme word and a space (Bearer, Token, ApiKey) is not the token.
		if i := strings.Index(tok, " "); i > 0 && i < 16 && !strings.ContainsAny(tok[:i], ".=:/") {
			prefix, tok = tok[:i+1], strings.TrimSpace(tok[i+1:])
		}
		if jwtClaims(tok) != nil {
			if nv, ok := freshJWT(leaves, v, now); ok {
				id.Creds[n] = nv
				note(n + ": a later token from the storage of the snapshot")
			}
			continue
		}
		found := false
		var same []storageLeaf
		for _, l := range leaves {
			// The token as the whole value, or a long storage value inside
			// a header of parameters (Jellyfin/Emby: Authorization:
			// MediaBrowser Client="…", Token="<in jellyfin_credentials>").
			if l.val == tok || (len(l.val) >= 16 && strings.Contains(v, l.val)) {
				found = true
			}
			if l.val != tok && jwtClaims(l.val) == nil && len(l.val) == len(tok) && traffic.Sensitive(l.key) {
				same = append(same, l)
			}
		}
		switch {
		case found:
		case len(same) == 1:
			id.Creds[n] = prefix + same[0].val
			note(fmt.Sprintf("%s: the token now under storage key %q (the recorded one is not in the storage)", n, same[0].key))
		default:
			// The recorded token may be a rotated, dead one: it is not sent.
			// Requests that need it say so (no equivalent credential).
			delete(id.Creds, n)
			note(n + ": the recorded token is not in the storage of the snapshot, which may have rotated it: not used")
		}
	}
}

// freshJWT finds in storage a JWT of the same subject and issuer as old
// (those it has) that has not expired and expires after it.
func freshJWT(leaves []storageLeaf, old string, now time.Time) (string, bool) {
	oc := jwtClaims(old)
	prefix := ""
	if strings.HasPrefix(strings.TrimSpace(old), "Bearer ") {
		prefix = "Bearer "
	}
	oexp := jwtExp(old)
	var best string
	var bexp time.Time
	for _, l := range leaves {
		c := jwtClaims(l.val)
		if c == nil {
			continue
		}
		exp := jwtExp(l.val)
		if exp.IsZero() || !exp.After(now) || (!oexp.IsZero() && !exp.After(oexp)) {
			continue
		}
		if s, ok := oc["sub"]; ok && c["sub"] != s {
			continue
		}
		if s, ok := oc["iss"]; ok && c["iss"] != s {
			continue
		}
		if best == "" || exp.After(bexp) {
			best, bexp = strings.TrimSpace(l.val), exp
		}
	}
	if best == "" {
		return "", false
	}
	return prefix + best, true
}
