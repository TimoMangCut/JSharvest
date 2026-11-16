package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WebRTCPolicy keeps WebRTC from sending UDP outside the proxy: with a
// proxy set, no ICE candidate of type host or srflx (which carry the
// machine's real addresses) is gathered.
//
// It is a profile preference (webrtc.ip_handling_policy), written before
// Chrome starts. The command-line switch --force-webrtc-ip-handling-policy
// is not used: Chrome 156 takes it without a word and gathers host
// candidates all the same (measured: testbed/webrtc-check.sh). The fixture
// is the proof that the preference works.
const WebRTCPolicy = "disable_non_proxied_udp"

// webrtcMarker is the file in a profile that says jsharvest set the policy
// there. It holds the JSON of the value the preference had before ("null":
// none), which is put back when a run without a proxy uses the profile.
// Chrome owns Preferences and rewrites it, so the mark is a file of ours.
const webrtcMarker = "jsharvest-webrtc-policy"

// proxyFlags are the Chrome switches that follow from a proxy (none
// without one, or in an attached Chrome, whose switches are not ours).
func proxyFlags(o Options) map[string]any {
	if o.Proxy == "" || o.Attach != "" {
		return nil
	}
	return map[string]any{"proxy-server": o.Proxy}
}

// AttachProxyWarning is the line for run.json when a proxy was asked for
// and the browser is the user's own: its settings are not ours to change,
// so neither the proxy nor the WebRTC policy applies, and WebRTC in a page
// may show the machine's real address. "" when there is nothing to say.
func AttachProxyWarning(o Options) string {
	if o.Attach == "" || o.Proxy == "" {
		return ""
	}
	return "-proxy with -attach: the attached Chrome is not behind the proxy, and WebRTC in it is not restricted, so a page may learn the machine's real address. Start that Chrome with the proxy and set its WebRTC policy yourself (the preference webrtc.ip_handling_policy=" + WebRTCPolicy + ", or the enterprise policy WebRtcIPHandlingPolicy)."
}

// readPrefs reads a profile's Preferences ({} when there is none). A file
// that is not JSON is an error: nothing is written over it.
func readPrefs(path string) (map[string]any, error) {
	prefs := map[string]any{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &prefs); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON, left as it is: %w", path, err)
		}
		if prefs == nil {
			prefs = map[string]any{} // JSON null: an empty file
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return prefs, nil
}

// writeFileAtomic writes through a temporary file and a rename, 0600; the
// directory is made 0700.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".jsharvest-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writePrefs(path string, prefs map[string]any) error {
	out, err := json.Marshal(prefs)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, out)
}

// webrtcPolicy settles a profile before Chrome starts. With a proxy the
// policy is set (every other key of Preferences kept); a Preferences that
// is not JSON is an error, and the run must not start: a proxy with
// WebRTC leaking around it is what this is for. Without a proxy, a policy
// that jsharvest set (the marker file) and the user has not changed is
// taken out again, the earlier value put back; one the user set is left.
func webrtcPolicy(profile string, proxy bool) error {
	dirs := []string{"Default"}
	// Chrome opens the profile it last used, which is not "Default" when
	// the user (or a run of Chrome by hand) changed it: Local State says.
	// With a proxy a Local State that is not JSON stops the run, as a
	// Preferences does; without one it is left alone.
	ls, err := readPrefs(filepath.Join(profile, "Local State"))
	switch {
	case err != nil && proxy:
		return err
	case err == nil:
		if p, _ := ls["profile"].(map[string]any); p != nil {
			if last, _ := p["last_used"].(string); validProfileDir(last) && last != "Default" {
				dirs = append(dirs, last)
			}
		}
	}
	for _, d := range dirs {
		if err := webrtcPolicyIn(profile, d, proxy); err != nil {
			return err
		}
	}
	return nil
}

// validProfileDir: a plain directory name inside the user data dir.
func validProfileDir(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`)
}

func webrtcPolicyIn(profile, sub string, proxy bool) error {
	path := filepath.Join(profile, sub, "Preferences")
	marker := filepath.Join(profile, sub, webrtcMarker)
	if !proxy {
		mb, err := os.ReadFile(marker)
		if err != nil {
			return nil // not ours
		}
		prefs, err := readPrefs(path)
		if err != nil {
			return err
		}
		w, _ := prefs["webrtc"].(map[string]any)
		if w != nil && w["ip_handling_policy"] == WebRTCPolicy {
			var prev any
			if json.Unmarshal(mb, &prev) != nil || prev == nil {
				delete(w, "ip_handling_policy")
				if len(w) == 0 {
					delete(prefs, "webrtc")
				}
			} else {
				w["ip_handling_policy"] = prev
			}
			if err := writePrefs(path, prefs); err != nil {
				return err
			}
		}
		return os.Remove(marker)
	}
	prefs, err := readPrefs(path)
	if err != nil {
		return err
	}
	w, _ := prefs["webrtc"].(map[string]any)
	if w == nil {
		w = map[string]any{}
	}
	if w["ip_handling_policy"] == WebRTCPolicy {
		return nil // already so: the user's, or ours from before
	}
	prev, err := json.Marshal(w["ip_handling_policy"])
	if err != nil {
		return err
	}
	if err := writeFileAtomic(marker, prev); err != nil {
		return err
	}
	w["ip_handling_policy"] = WebRTCPolicy
	prefs["webrtc"] = w
	return writePrefs(path, prefs)
}
