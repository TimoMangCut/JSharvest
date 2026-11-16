package replay

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Relation is what the user says the two peers are to each other.
type Relation string

const (
	RelSameOrg  Relation = "same-org"
	RelCrossOrg Relation = "cross-org"
)

// EvidencePair is a value of A's, at a place of the JSON, that the trial's
// answer under B's identity also has.
type EvidencePair struct {
	Path   string `json:"path"`
	Value  string `json:"value"`
	RefVal string `json:"ref_value,omitempty"`
	Short  bool   `json:"short,omitempty"`
}

// PeerCase is one authz -peers trial and what it is judged against. A is the
// owner of the request, B the identity it is sent under.
type PeerCase struct {
	Write    bool
	Relation Relation
	// Private: -private matched the URL or the endpoint key.
	Private bool
	Mode    string // main, substitute:<place>
	// IDCount is how many ids the trial changed hands with (the ones B has
	// not seen): two or more and a refusal says only that the parent was
	// refused.
	IDCount int

	Trial    Answer
	Controls []Answer // A's, sent after the trial: the first, the second
	// Self is B's own request to the endpoint, sent live; Bogus the trial
	// with an id that names nothing. Nil: not sent (or not a 2xx).
	Self, Bogus *Answer
	// BogusTried: a Bogus was sent, whatever it answered.
	BogusTried bool
	NoIdentity *Answer

	Sent      []string // the values the trial carries that are no credential
	SentBogus []string // those of the Bogus request
	Seen      *SeenSet // what B and anon already show
	OwnerIDs  []string // the identifiers of A
	PeerIDs   []string // those of B

	Stale, Kept bool
	IsLogin     func(string) bool
	// RecordedOK: the crawl's answer to A's request was a clean 2xx.
	RecordedOK bool
	// AliveA: A's session lives (meaningful when A's control failed).
	AliveA bool
}

// PeerJudgement is a verdict and what it rests on.
type PeerJudgement struct {
	Judgement
	Evidence []EvidencePair
	// NeedNoID, NeedBogus: the verdict waits for that answer (send it and
	// judge again).
	NeedNoID, NeedBogus bool
	// StopEndpoint: a Bogus id was answered with data: nothing more is
	// concluded from this endpoint.
	StopEndpoint bool
	// Private says why a same-org finding is a bypass, "" when it is not.
	Private string
}

func (p PeerJudgement) with(v Verdict, why string) PeerJudgement {
	p.Judgement = Judgement{v, why}
	return p
}

// evidenceExcluded are the keys (lower-case) of a leaf that is no data: a
// code, a message, a time stamp, a trace id. It is not bodyErrors' metaKeys:
// a note's title, description, path or url is data.
var evidenceExcluded = map[string]bool{
	"code": true, "status": true, "statuscode": true, "errcode": true, "msg": true, "message": true, "error": true, "errors": true,
	"success": true, "ok": true, "timestamp": true, "trace_id": true, "traceid": true, "request_id": true, "requestid": true,
	"span_id": true, "spanid": true,
}

func trivialValue(v string) bool {
	switch v {
	case "", "null", "<nil>", "true", "false", "{}", "[]", "0", "1", "-1":
		return true
	}
	return false
}

var (
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
	enumUpper  = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	enumLower  = regexp.MustCompile(`^[a-z]+(?:[-_][a-z]+)*$`)
	tzRe       = regexp.MustCompile(`^[A-Za-z]+/[A-Za-z_+-]+(/[A-Za-z_+-]+)?$`)
	weakWords  = map[string]bool{"active": true, "inactive": true, "enabled": true, "disabled": true, "pending": true, "none": true,
		"default": true, "member": true, "admin": true, "user": true, "public": true, "ok": true, "yes": true, "no": true,
		"male": true, "female": true, "en": true, "vi": true, "utc": true}
)

// weakDefault: a value many objects have (a currency, a status word, 0, 1).
func weakDefault(v string) bool {
	return trivialValue(v) || currencyRe.MatchString(v) || weakWords[strings.ToLower(v)]
}

// isStrongValue: a value long enough, and with a digit or high entropy, to
// be a single proof of whose it is: not an enum name, a time zone, ROLE_*.
func isStrongValue(v string) bool {
	if len(v) < 8 || enumUpper.MatchString(v) || enumLower.MatchString(v) || tzRe.MatchString(v) || weakDefault(v) {
		return false
	}
	if strings.ContainsAny(v, "0123456789") {
		return true
	}
	e := entropy(v)
	if strings.Contains(v, " ") {
		return e >= 3.0
	}
	return e >= 3.5
}

// reflector finds in a value what the request sent: a value that contains
// (case-insensitively, URL-decoded) a sent value of 3 characters or more is
// the request echoed, not data. A sent number is found only as a whole
// number inside the value.
type reflector struct {
	plain, digits []string
}

func newReflector(lists ...[]string) *reflector {
	r := &reflector{}
	seen := map[string]bool{}
	for _, l := range lists {
		for _, v := range l {
			if d, err := url.QueryUnescape(v); err == nil {
				v = d
			}
			v = strings.ToLower(strings.TrimSpace(v))
			if len(v) < 3 || seen[v] || v == "true" || v == "false" || v == "null" {
				continue
			}
			seen[v] = true
			if strings.Trim(v, "0123456789") == "" {
				r.digits = append(r.digits, v)
			} else {
				r.plain = append(r.plain, v)
			}
		}
	}
	return r
}

func (r *reflector) hit(v string) bool {
	if r == nil {
		return false
	}
	l := strings.ToLower(v)
	if d, err := url.QueryUnescape(v); err == nil && d != v {
		// A leaf holding an escaped copy of what was sent is the echo too.
		if r.hit(d) {
			return true
		}
	}
	for _, s := range r.plain {
		if strings.Contains(l, s) {
			return true
		}
	}
	for _, s := range r.digits {
		for i := 0; ; {
			j := strings.Index(l[i:], s)
			if j < 0 {
				break
			}
			j += i
			before := j == 0 || l[j-1] < '0' || l[j-1] > '9'
			after := j+len(s) == len(l) || l[j+len(s)] < '0' || l[j+len(s)] > '9'
			if before && after {
				return true
			}
			i = j + 1
		}
	}
	return false
}

// dataLeaves are the leaves of a JSON body that are data: not a code, a
// message or a time stamp, not empty, not the request echoed, not one of the
// paths that change from call to call.
func dataLeaves(body []byte, refl *reflector, vol map[string]bool) (map[string]string, bool) {
	f, ok := flatten(body)
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	for p, v := range f {
		if vol[p] || evidenceExcluded[strings.ToLower(lastKey(p))] || trivialValue(v) || refl.hit(v) {
			continue
		}
		out[p] = v
	}
	return out, true
}

// volatilePaths are the leaves that differ between A's two controls.
func volatilePaths(c1, c2 []byte) map[string]bool {
	f1, ok1 := flatten(c1)
	f2, ok2 := flatten(c2)
	if !ok1 || !ok2 {
		return nil
	}
	vol := map[string]bool{}
	for k, v := range f1 {
		if o, ok := f2[k]; !ok || o != v {
			vol[k] = true
		}
	}
	for k := range f2 {
		if _, ok := f1[k]; !ok {
			vol[k] = true
		}
	}
	return vol
}

// sameData says whether two answers carry the same data (what each echoes
// of its own request, and what changes from call to call, set aside).
func sameData(a, b Answer, refl *reflector, vol map[string]bool) bool {
	la, ja := dataLeaves(a.Body, refl, vol)
	lb, jb := dataLeaves(b.Body, refl, vol)
	if ja && jb {
		if len(la) != len(lb) {
			return false
		}
		for k, v := range la {
			if lb[k] != v {
				return false
			}
		}
		return true
	}
	if ja != jb || kind(a) != kind(b) {
		return false
	}
	return string(maskText(a.Body)) == string(maskText(b.Body))
}

type pair struct{ path, val string }

// evidenceCandidates are the values of A's answer that would prove it is
// A's: stable between the two controls, data, not echoed from the request,
// not shown to B or anon before, not B's own (at that place or anywhere in
// what Self or Bogus answered).
func evidenceCandidates(c1, c2 []byte, refs []Answer, refl *reflector, seen *SeenSet) []pair {
	f1, ok1 := flatten(c1)
	f2, ok2 := flatten(c2)
	if !ok1 || !ok2 {
		return nil
	}
	refVals := map[string]bool{}
	for _, r := range refs {
		if f, ok := flatten(r.Body); ok {
			for _, v := range f {
				refVals[v] = true
			}
		}
	}
	var out []pair
	for p, v := range f1 {
		key := strings.ToLower(lastKey(p))
		if evidenceExcluded[key] || trivialValue(v) || f2[p] != v || refl.hit(v) || refVals[v] {
			continue
		}
		if isStrongValue(v) {
			if seen.Has(v) {
				continue
			}
		} else if weakDefault(v) || seen.HasKV(key, v) {
			continue
		}
		out = append(out, pair{p, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// textEvidence is the evidence of an answer that is no JSON: the lines of 8
// characters or more that A's two controls have (stable) and the answer
// has too, that the request did not send and neither Self, Bogus, B's own
// responses nor anon's show.
func textEvidence(c1, c2, answer []byte, refs []Answer, refl *reflector, seen *SeenSet) []pair {
	lines := func(b []byte) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				m[l] = true
			}
		}
		return m
	}
	l2, la := lines(c2), lines(answer)
	refLines := map[string]bool{}
	for _, r := range refs {
		for l := range lines(r.Body) {
			refLines[l] = true
		}
	}
	var out []pair
	for _, l := range strings.Split(string(c1), "\n") {
		l = strings.TrimSpace(l)
		if len(l) >= 8 && isStrongValue(l) && l2[l] && la[l] && !refLines[l] && !refl.hit(l) && !seen.Has(l) {
			out = append(out, pair{"$text", l})
			if len(out) == 3 {
				break
			}
		}
	}
	return out
}

// pickEvidence keeps the pairs that the answer has at their place (or under
// the same leaf name and value, a list having been filtered), and says
// whether they prove it: one strong value does; otherwise two pairs (three
// when every value is one or two characters, or when nothing 2xx stands as
// the reference).
func pickEvidence(cands []pair, answer []byte, refOK bool, refs []Answer) []EvidencePair {
	f, ok := flatten(answer)
	if !ok {
		return nil
	}
	byKV := map[string]bool{}
	for p, v := range f {
		byKV[strings.ToLower(lastKey(p))+"="+v] = true
	}
	var refFlat []map[string]string
	for _, r := range refs {
		if m, ok := flatten(r.Body); ok {
			refFlat = append(refFlat, m)
		}
	}
	refVal := func(path string) string {
		for _, m := range refFlat {
			if v, ok := m[path]; ok {
				return v
			}
		}
		return ""
	}
	var strong, weak []EvidencePair
	for _, c := range cands {
		strongVal := isStrongValue(c.val)
		// A strong value may have moved (a list filtered); a short one is
		// found at its own path or not at all.
		if f[c.path] != c.val && !(strongVal && byKV[strings.ToLower(lastKey(c.path))+"="+c.val]) {
			continue
		}
		e := EvidencePair{Path: c.path, Value: c.val, RefVal: refVal(c.path)}
		if strongVal {
			strong = append(strong, e)
		} else {
			e.Short = true
			weak = append(weak, e)
		}
	}
	if len(strong) > 0 {
		return append(strong, weak...)
	}
	need := 3
	distinct := map[string]bool{}
	for _, e := range weak {
		distinct[e.Value] = true
		if len(e.Value) >= 3 {
			need = 2
		}
	}
	if !refOK {
		need = 3
	}
	if len(distinct) >= need {
		return weak
	}
	return nil
}

var ownerPathRe = regexp.MustCompile(`(?i)owner|createdby|created_by|userid|user_id|authorid|author_id`)

// privateMarker says why an object B read is private to A, though the two
// share an org: an explicit flag in A's answer, or the object being marked
// as A's own (an owner or creator that is A's identifier, not B's). "" when
// nothing says so.
func privateMarker(body []byte, ownerIDs, peerIDs []string) string {
	f, ok := flatten(body)
	if !ok {
		return ""
	}
	isA := map[string]bool{}
	for _, v := range ownerIDs {
		isA[v] = true
	}
	for _, v := range peerIDs {
		delete(isA, v)
	}
	paths := make([]string, 0, len(f))
	for p := range f {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		v := f[p]
		switch k := strings.ToLower(lastKey(p)); k {
		case "private", "is_private", "isprivate":
			if v == "true" {
				return "the answer says " + lastKey(p) + ": true"
			}
		case "visibility", "access", "scope":
			switch strings.ToLower(v) {
			case "private", "personal", "only_me", "secret":
				return fmt.Sprintf("the answer says %s: %s", lastKey(p), strings.ToLower(v))
			}
		}
		if ownerPathRe.MatchString(p) && isA[v] {
			return "the object is marked as A's own (" + p + ")"
		}
	}
	return ""
}

// JudgePeer concludes one trial of authz -peers: the verdict, and the proof
// when it is a finding. It is the table of docs/gd7-bola-design.md 4.4 as
// section 8 amends it. It sends nothing: the caller sends what NeedNoID and
// NeedBogus ask for and judges again.
func JudgePeer(c PeerCase) PeerJudgement {
	var out PeerJudgement
	t := c.Trial
	if t.Err != "" {
		return out.with(Unclear, "no answer: "+t.Err)
	}
	if b := blockOf(t); b != nil {
		if b.Kind == BlockRate {
			return out.with(Unclear, "rate limited: "+b.String())
		}
		return out.with(Blocked, "a WAF answered: "+b.String())
	}
	others := append([]Answer{}, c.Controls...)
	for _, a := range []*Answer{c.Self, c.Bogus, c.NoIdentity} {
		if a != nil && a.Err == "" {
			others = append(others, *a)
		}
	}
	for _, a := range others {
		if b := blockOf(a); b != nil {
			return out.with(Unclear, "a WAF answered a control of the trial: "+b.String())
		}
	}
	if cached(t) {
		return out.with(Unclear, "a shared cache answered the trial")
	}
	refuse := func(why string) PeerJudgement {
		if c.Stale || c.Kept {
			return out.with(Unclear, why+", with a CSRF token or credential not taken fresh")
		}
		if c.IDCount >= 2 && !strings.HasPrefix(c.Mode, "substitute") {
			return out.with(EnforcedParent, why+": only the parent level was tried; -substitute tries the leaf id under B's own parent")
		}
		return out.with(Enforced, why)
	}
	status := t.Status

	if c.Write {
		switch {
		case status == 401 || status == 403:
			if c.Stale || c.Kept {
				return out.with(Unclear, fmt.Sprintf("%d, with a CSRF token or credential not taken fresh", status))
			}
			return refuse(strconv.Itoa(status))
		case status >= 300 && status < 400 && c.IsLogin != nil && c.IsLogin(t.Header["location"]):
			return refuse("sent to the login page")
		case status >= 200 && status < 300:
			if bodyErrors(t.Body, nil) != errNone {
				return out.with(NeedsReview, "a success with an error in its body")
			}
			return out.with(NeedsReview, fmt.Sprintf("blind-write: the write was accepted (%d); nothing in the answer proves whose object it changed", status))
		}
		return out.with(Unclear, strconv.Itoa(status))
	}

	// A's control.
	if len(c.Controls) == 0 {
		return out.with(Unclear, "A's control was not sent")
	}
	c1 := c.Controls[0]
	if !c1.ok() {
		if !c.AliveA {
			return out.with(Unclear, "peer A's session is dead, or cannot be checked: "+describe(c1))
		}
		if c.RecordedOK && c1.Err == "" {
			return out.with(ReplayBroken, fmt.Sprintf("A's own request answers %d now, as it did not when recorded: request signing, a one-time nonce or a session bound to the browser? Nothing is concluded of the server's check", c1.Status))
		}
		return out.with(Unclear, "A's control failed: "+describe(c1))
	}
	if bodyErrors(c1.Body, nil) == errAll {
		return out.with(Unclear, "A's control has an error in its body")
	}

	switch {
	case status == 401 || status == 403:
		if c.Stale || c.Kept {
			return out.with(Unclear, fmt.Sprintf("%d, with a CSRF token or credential not taken fresh", status))
		}
		return refuse(strconv.Itoa(status))
	case status == 419:
		return out.with(Unclear, "419: a CSRF token refused")
	case status >= 300 && status < 400:
		loc := t.Header["location"]
		if c.IsLogin != nil && c.IsLogin(loc) {
			return refuse("sent to the login page")
		}
		return out.with(Unclear, fmt.Sprintf("%d to %s", status, loc))
	case status == 404:
		return refuse("404, where A gets it")
	case status < 200 || status >= 300:
		return out.with(Unclear, strconv.Itoa(status))
	}

	// A success.
	switch bodyErrors(t.Body, c1.Body) {
	case errAll:
		return refuse("a success whose body says it failed")
	case errSome:
		return out.with(NeedsReview, "a success, some of its batch with an error in the body")
	}
	if kind(t) != kind(c1) {
		return out.with(Unclear, fmt.Sprintf("a %s answer, where A gets %s (a fallback page?)", kind(t), kind(c1)))
	}
	if len(c.Controls) < 2 {
		return out.with(Unclear, "A's second control was not sent")
	}
	c2 := c.Controls[1]
	vol := volatilePaths(c1.Body, c2.Body)
	refl := newReflector(c.Sent)
	var refs []Answer
	if c.Self != nil {
		refs = append(refs, *c.Self)
	}
	if c.Bogus != nil {
		refs = append(refs, *c.Bogus)
	}
	// B's own object, or the answer for an id that names nothing: B got
	// nothing of A's.
	if c.Self != nil && sameData(t, *c.Self, newReflector(c.Sent), vol) {
		return out.with(Enforced, "the server ignores the id: the answer is B's own object")
	}
	if c.Bogus != nil && c.Bogus.ok() {
		br := newReflector(c.Sent, c.SentBogus)
		if sameData(t, *c.Bogus, br, vol) {
			return out.with(Enforced, "the same answer as for an id that names nothing")
		}
		if bogusHasData(*c.Bogus, c1, br, vol) {
			out.StopEndpoint = true
			return out.with(Unclear, "an id that names nothing was answered 200 with data: the endpoint answers any id; nothing more is tried on it")
		}
	}

	if kind(c1) == "json" {
		cands := evidenceCandidates(c1.Body, c2.Body, refs, refl, c.Seen)
		out.Evidence = pickEvidence(cands, t.Body, refsOK(refs), refs)
	} else {
		for _, p := range textEvidence(c1.Body, c2.Body, t.Body, refs, refl, c.Seen) {
			out.Evidence = append(out.Evidence, EvidencePair{Path: p.path, Value: p.val})
		}
	}
	if len(out.Evidence) == 0 {
		// Nothing of A's. What is left of the answer: values B shows or has
		// anyway are nothing; others are for a person to look at.
		left := 0
		if f, ok := dataLeaves(t.Body, refl, vol); ok {
			refVals := map[string]bool{}
			for _, r := range refs {
				if m, ok := flatten(r.Body); ok {
					for _, v := range m {
						refVals[v] = true
					}
				}
			}
			for p, v := range f {
				if !weakDefault(v) && !c.Seen.Has(v) && !c.Seen.HasKV(lastKey(p), v) && !refVals[v] {
					left++
				}
			}
		} else if len(strings.TrimSpace(string(t.Body))) > 0 {
			left = 1
			for _, r := range refs {
				if r.ok() && string(maskText(r.Body)) == string(maskText(t.Body)) {
					left = 0
				}
			}
		}
		switch {
		case left == 0:
			return out.with(Enforced, "an answer with nothing of A's in it")
		case !c.BogusTried:
			out.NeedBogus = true
			return out.with(NeedsReview, "an answer with data that is not A's proof: asking for an id that names nothing")
		}
		return out.with(NeedsReview, "a success with data of its own (public fields? a list filtered by owner?), none of it A's proof")
	}

	// Proof of A's data in B's answer.
	if c.NoIdentity == nil {
		out.NeedNoID = true
		out.Private = c.privateWhy(c1)
		return out.with(Bypass, "A's data under B's identity")
	}
	if n := *c.NoIdentity; n.Err == "" && n.ok() && kind(n) == kind(c1) {
		proved := false
		if kind(c1) == "json" {
			cands := evidenceCandidates(c1.Body, c2.Body, refs, refl, c.Seen)
			proved = len(pickEvidence(cands, n.Body, true, refs)) > 0
		} else {
			proved = len(textEvidence(c1.Body, c2.Body, n.Body, refs, refl, c.Seen)) > 0
		}
		if proved {
			return out.with(Unauthenticated, "a request with no identity gets A's data too")
		}
	}
	if p := c.privateWhy(c1); p != "" {
		out.Private = p
		return out.with(Bypass, "B reads what is private to A: "+p)
	}
	if c.Relation == RelCrossOrg {
		return out.with(Bypass, "B, of another org, reads A's data")
	}
	return out.with(Shared, "B, of A's org, reads A's data; nothing says it is private (-private REGEX says which endpoints are)")
}

// refsOK says a reference answered 2xx (a Self or a Bogus that failed is no
// reference: more proof is wanted).
func refsOK(refs []Answer) bool {
	for _, r := range refs {
		if r.ok() {
			return true
		}
	}
	return false
}

func (c PeerCase) privateWhy(c1 Answer) string {
	if c.Private {
		return "-private matches"
	}
	return privateMarker(c1.Body, c.OwnerIDs, c.PeerIDs)
}

// bogusHasData: an id that names nothing got a 2xx answer with data (not an
// error in its body, not the id echoed).
func bogusHasData(b, c1 Answer, refl *reflector, vol map[string]bool) bool {
	if !b.ok() || kind(b) != kind(c1) || bodyErrors(b.Body, c1.Body) != errNone {
		return false
	}
	if f, ok := dataLeaves(b.Body, refl, vol); ok {
		return len(f) > 0
	}
	return len(strings.TrimSpace(string(b.Body))) > 0
}
