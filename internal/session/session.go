// Package session keeps a role's login: what jsharvest login saved (the
// cookies, the storage of each origin, the signs of being logged in, the
// login script), and puts it back into a browser. Chrome keeps neither
// session cookies nor sessionStorage in a profile across runs, so a profile
// alone does not keep a login; the snapshot does.
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"

	"github.com/TimoMangCut/JSharvest/internal/marker"
)

// File is the snapshot's name in a profile directory.
const File = "jsharvest-session.json"

// Snapshot is what a login left: enough to be logged in again.
type Snapshot struct {
	Target   string            `json:"target"`
	Role     string            `json:"role"`
	Saved    time.Time         `json:"saved"`
	LoginURL string            `json:"login_url"` // where the login began: a page that comes back here was logged out
	FinalURL string            `json:"final_url"`
	Cookies  []*network.Cookie `json:"cookies"`
	// Storage is each origin's localStorage and sessionStorage.
	Storage map[string]Storage `json:"storage,omitempty"`
	Signs   Signs              `json:"signs"`
	// Steps is the login script's path, to log in again; its secrets come
	// from the environment and are not saved.
	Steps string `json:"steps,omitempty"`
	// UserAgent is the browser's at the login: a crawl presents it again,
	// since a session may be tied to it (Cloudflare's cf_clearance is).
	UserAgent string `json:"user_agent,omitempty"`
	// GuardAllow are the -guard-allow regexps given at login (anchored to
	// the target's origin: guard.AnchoredAllow); crawl -role adds them to
	// its own.
	GuardAllow []string `json:"guard_allow,omitempty"`
}

type Storage struct {
	Local   map[string]string `json:"local,omitempty"`
	Session map[string]string `json:"session,omitempty"`
}

// Signs tell a logged-in browser from a logged-out one.
type Signs struct {
	// Cookies are the cookies the login set or changed, by name; Keys the
	// same as "domain|name", so that a cookie of that name on another
	// host of the target does not hide the loss of the login's own.
	Cookies []string `json:"cookies"`
	Keys    []string `json:"cookie_keys,omitempty"`
	// CheckURL answers 2xx when logged in (an /api/me), and CheckText is
	// on the page when logged in; both optional.
	CheckURL  string `json:"check_url,omitempty"`
	CheckText string `json:"check_text,omitempty"`
}

// Load reads a profile's snapshot; it reports os.ErrNotExist when there is
// none.
func Load(profile string) (*Snapshot, error) {
	b, err := os.ReadFile(filepath.Join(profile, File))
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", File, err)
	}
	return &s, nil
}

// Exists reports whether a profile has a snapshot.
func Exists(profile string) bool {
	_, err := os.Stat(filepath.Join(profile, File))
	return err == nil
}

// Save writes the snapshot, 0600: it holds live cookies.
func (s *Snapshot) Save(profile string) error {
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(profile, File+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(profile, File))
}

// NewCookies names the cookies that are in after and not, or not the
// same, in before: those the login set.
func NewCookies(before, after []*network.Cookie) []string {
	was := map[string]string{}
	for _, c := range before {
		was[c.Domain+"|"+c.Name] = c.Value
	}
	var out []string
	for _, c := range after {
		if v, ok := was[c.Domain+"|"+c.Name]; (!ok || v != c.Value) && c.Value != "" && !slices.Contains(out, c.Name) {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

// NewCookieKeys is NewCookies as "domain|name".
func NewCookieKeys(before, after []*network.Cookie) []string {
	was := map[string]string{}
	for _, c := range before {
		was[c.Domain+"|"+c.Name] = c.Value
	}
	var out []string
	for _, c := range after {
		k := c.Domain + "|" + c.Name
		if v, ok := was[k]; (!ok || v != c.Value) && c.Value != "" && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Missing returns the names of the sign cookies that are not in cookies
// (or empty): by domain and name, or by name for a snapshot saved before
// the keys.
func (s *Snapshot) Missing(cookies []*network.Cookie) []string {
	have := map[string]bool{}
	for _, c := range cookies {
		if c.Value != "" {
			have[c.Name] = true
			have[c.Domain+"|"+c.Name] = true
		}
	}
	signs := s.Signs.Keys
	if len(signs) == 0 {
		signs = s.Signs.Cookies
	}
	var out []string
	for _, k := range signs {
		if !have[k] {
			_, name, _ := strings.Cut(k, "|")
			if name == "" {
				name = k
			}
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// Params turns the saved cookies into what Storage.setCookies takes.
func (s *Snapshot) Params() []*network.CookieParam {
	out := make([]*network.CookieParam, 0, len(s.Cookies))
	for _, c := range s.Cookies {
		p := &network.CookieParam{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Secure: c.Secure,
			HTTPOnly: c.HTTPOnly, SameSite: c.SameSite, Priority: c.Priority, SourceScheme: c.SourceScheme}
		if !c.Session && c.Expires > 0 {
			p.Expires = cdp.TimeSinceEpoch(c.Expires)
		}
		out = append(out, p)
	}
	return out
}

// RestoreScript is a script for Page.addScriptToEvaluateOnNewDocument: in
// a document of a saved origin, it puts back the storage keys that are
// missing, before the page's own scripts run. It never overwrites what
// the page has.
func (s *Snapshot) RestoreScript() string { return s.restoreScript(false) }

// OverrideScript is RestoreScript that sets every key the snapshot has,
// whatever the browser holds: for the first documents of a run, when the
// snapshot is the better word (a profile's localStorage may keep a token an
// earlier run used up). Keys the snapshot does not have are left alone.
func (s *Snapshot) OverrideScript() string { return s.restoreScript(true) }

func (s *Snapshot) restoreScript(force bool) string {
	if len(s.Storage) == 0 {
		return ""
	}
	b, _ := json.Marshal(s.Storage)
	cond := "area.getItem(k) === null"
	if force {
		cond = "true"
	}
	return `(() => {
  try {
    const all = ` + string(b) + `;
    const mine = all[location.origin];
    if (!mine) return;
    for (const [area, items] of [[localStorage, mine.local || {}], [sessionStorage, mine.session || {}]]) {
      for (const k of Object.keys(items)) if (` + cond + `) area.setItem(k, items[k]);
    }
  } catch (_) {}
})()
//# sourceURL=` + marker.Internal
}

// StorageScript reads the current document's storage, for a snapshot.
const StorageScript = `(() => {
  const read = (a) => { const o = {}; for (let i = 0; i < a.length; i++) { const k = a.key(i); o[k] = a.getItem(k); } return o; };
  try { return {origin: location.origin, local: read(localStorage), session: read(sessionStorage)}; } catch (_) { return {origin: location.origin}; }
})()
//# sourceURL=` + marker.Internal

// InScope keeps the cookies of the target's hosts.
func InScope(cookies []*network.Cookie, inScope func(host string) bool) []*network.Cookie {
	var out []*network.Cookie
	for _, c := range cookies {
		if inScope(strings.TrimPrefix(c.Domain, ".")) {
			out = append(out, c)
		}
	}
	return out
}

// Refresh is what a browser holds now, for Snapshot.Refresh.
type Refresh struct {
	Cookies []*network.Cookie  // the context's cookies, in scope
	Storage map[string]Storage // storage read now, by origin (those readable)
}

// Refresh puts into s what the browser holds now (a refresh token the app
// rotated, a cookie the server set again), and reports whether it did.
// It does nothing, and says why, for a browser that does not look logged
// in: a snapshot with no sign cookies cannot tell (so a logged-out state
// is never taken for the session), and one whose sign cookies are missing
// has lost it. Only what the snapshot already knew changes: cookies in
// scope are replaced by the current ones (those out of scope stay as
// saved; a nil inScope has none); storage only of origins the snapshot has, and an origin read
// empty keeps what it had (an empty read is a page not yet loaded, or a
// logged-out one). The slices and maps are replaced, never edited, so a
// shallow copy of s stays valid.
func (s *Snapshot) Refresh(r Refresh, inScope func(host string) bool, now time.Time) (bool, string) {
	if len(s.Signs.Keys) == 0 && len(s.Signs.Cookies) == 0 {
		// A login kept in storage (an SPA's token, no cookie): the keys the
		// last live state had are the signs. A logout removes its token's
		// key; a read that saw none of the snapshot's origins tells nothing.
		if why := s.storageSigns(r.Storage); why != "" {
			return false, why
		}
	} else if miss := s.Missing(r.Cookies); len(miss) > 0 {
		return false, "sign cookies missing: " + strings.Join(miss, ",")
	}
	cookies := slices.Clone(r.Cookies)
	for _, c := range s.Cookies {
		if inScope != nil && !inScope(strings.TrimPrefix(c.Domain, ".")) {
			cookies = append(cookies, c)
		}
	}
	storage := make(map[string]Storage, len(s.Storage))
	for o, st := range s.Storage {
		storage[o] = st
	}
	for o, st := range r.Storage {
		if _, known := s.Storage[o]; known && (len(st.Local) > 0 || len(st.Session) > 0) {
			storage[o] = st
		}
	}
	s.Cookies, s.Storage, s.Saved = cookies, storage, now
	return true, ""
}

// storageSigns checks a read of storage against the snapshot's when there
// is no sign cookie: at least one origin of the snapshot was read, and every
// localStorage key that origin had is still there. "" when it holds.
func (s *Snapshot) storageSigns(read map[string]Storage) string {
	seen := false
	for o, old := range s.Storage {
		cur, ok := read[o]
		if !ok || len(old.Local) == 0 {
			continue
		}
		seen = true
		for k := range old.Local {
			if _, ok := cur.Local[k]; !ok {
				return "storage key gone: " + o + " " + k
			}
		}
	}
	if !seen {
		return "no sign cookie, and none of the snapshot's storage was read"
	}
	return ""
}

// SaveState writes the cookies and storage of s into the profile's
// snapshot, leaving every other field as the file has it (read, change,
// write): another tool may have added one. With no file, it saves s.
func (s *Snapshot) SaveState(profile string) error {
	raw, err := os.ReadFile(filepath.Join(profile, File))
	if err != nil {
		return s.Save(profile)
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return s.Save(profile)
	}
	for k, v := range map[string]any{"cookies": s.Cookies, "storage": s.Storage, "saved": s.Saved} {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		m[k] = b
	}
	if len(s.Storage) == 0 {
		delete(m, "storage")
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(profile, File+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(profile, File))
}
