package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyFlags(t *testing.T) {
	f := proxyFlags(Options{Proxy: "http://127.0.0.1:8899"})
	if f["proxy-server"] != "http://127.0.0.1:8899" || len(f) != 1 {
		t.Errorf("with proxy: %v (the WebRTC switch is not used: Chrome 156 ignores it)", f)
	}
	if f := proxyFlags(Options{}); len(f) != 0 {
		t.Errorf("without proxy: %v", f)
	}
	if f := proxyFlags(Options{Proxy: "http://p:1", Attach: "http://127.0.0.1:9222"}); len(f) != 0 {
		t.Errorf("attach: %v", f)
	}
}

func TestAttachProxyWarning(t *testing.T) {
	w := AttachProxyWarning(Options{Proxy: "http://p:1", Attach: "http://127.0.0.1:9222"})
	if !strings.Contains(w, "WebRTC") || !strings.Contains(w, "WebRtcIPHandlingPolicy") {
		t.Errorf("attach + proxy: %q", w)
	}
	for _, o := range []Options{{Proxy: "http://p:1"}, {Attach: "http://127.0.0.1:9222"}, {}} {
		if w := AttachProxyWarning(o); w != "" {
			t.Errorf("%+v: %q", o, w)
		}
	}
}

func prefsOf(t *testing.T, profile string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(profile, "Default", "Preferences"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func policyOf(m map[string]any) any {
	w, _ := m["webrtc"].(map[string]any)
	return w["ip_handling_policy"]
}

func seed(t *testing.T, profile, content string) {
	t.Helper()
	p := filepath.Join(profile, "Default", "Preferences")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWebRTCPolicyFreshProfile(t *testing.T) {
	dir := t.TempDir()
	if err := webrtcPolicy(dir, true); err != nil {
		t.Fatal(err)
	}
	if got := policyOf(prefsOf(t, dir)); got != WebRTCPolicy {
		t.Fatalf("policy: %v", got)
	}
	for _, p := range []string{"Default/Preferences", "Default/" + webrtcMarker} {
		st, err := os.Stat(filepath.Join(dir, p))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	if st, _ := os.Stat(filepath.Join(dir, "Default")); st.Mode().Perm() != 0o700 {
		t.Errorf("Default is %v", st.Mode().Perm())
	}
}

func TestWebRTCPolicyKeepsOtherKeys(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, `{"net":{"network_prediction_options":2},"webrtc":{"multiple_routes_enabled":false},"strange":{"k":[1,2]}}`)
	if err := webrtcPolicy(dir, true); err != nil {
		t.Fatal(err)
	}
	m := prefsOf(t, dir)
	if policyOf(m) != WebRTCPolicy {
		t.Errorf("policy not set: %v", m)
	}
	if w := m["webrtc"].(map[string]any); w["multiple_routes_enabled"] != false {
		t.Errorf("a webrtc key lost: %v", w)
	}
	if _, ok := m["strange"]; !ok || m["net"] == nil {
		t.Errorf("other keys lost: %v", m)
	}
}

func TestWebRTCPolicyCorruptFile(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, `{not json`)
	if err := webrtcPolicy(dir, true); err == nil {
		t.Fatal("a corrupt Preferences must stop the run")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "Default", "Preferences"))
	if string(b) != `{not json` {
		t.Errorf("the file was written over: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "Default", webrtcMarker)); err == nil {
		t.Error("a marker was left")
	}
}

func TestWebRTCPolicyRemovedWithoutProxy(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, `{"strange":1,"webrtc":{"ip_handling_policy":"default_public_interface_only"}}`)
	if err := webrtcPolicy(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := webrtcPolicy(dir, false); err != nil {
		t.Fatal(err)
	}
	m := prefsOf(t, dir)
	if policyOf(m) != "default_public_interface_only" || m["strange"] == nil {
		t.Errorf("earlier value not restored: %v", m)
	}
	if _, err := os.Stat(filepath.Join(dir, "Default", webrtcMarker)); err == nil {
		t.Error("marker kept")
	}
	// A profile that had none: the key goes, and the empty webrtc with it.
	dir2 := t.TempDir()
	seed(t, dir2, `{"strange":1}`)
	webrtcPolicy(dir2, true)
	if err := webrtcPolicy(dir2, false); err != nil {
		t.Fatal(err)
	}
	if m := prefsOf(t, dir2); m["webrtc"] != nil || m["strange"] == nil {
		t.Errorf("not taken out: %v", m)
	}
}

func TestWebRTCPolicyUsersOwnKept(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, `{"webrtc":{"ip_handling_policy":"disable_non_proxied_udp"}}`)
	// The user's, with a proxy: nothing of ours is written, so no marker.
	if err := webrtcPolicy(dir, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Default", webrtcMarker)); err == nil {
		t.Error("a marker for the user's own setting")
	}
	// Without a proxy it stays.
	if err := webrtcPolicy(dir, false); err != nil {
		t.Fatal(err)
	}
	if policyOf(prefsOf(t, dir)) != WebRTCPolicy {
		t.Error("the user's policy was taken out")
	}
	// Ours, but the user has changed it since: left, the marker dropped.
	dir2 := t.TempDir()
	webrtcPolicy(dir2, true)
	seed(t, dir2, `{"webrtc":{"ip_handling_policy":"default"}}`)
	if err := webrtcPolicy(dir2, false); err != nil {
		t.Fatal(err)
	}
	if policyOf(prefsOf(t, dir2)) != "default" {
		t.Error("the user's later value was overwritten")
	}
	if _, err := os.Stat(filepath.Join(dir2, "Default", webrtcMarker)); err == nil {
		t.Error("marker kept")
	}
}

func TestWebRTCPolicyNoProxyNothingToDo(t *testing.T) {
	dir := t.TempDir()
	if err := webrtcPolicy(dir, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Default")); err == nil {
		t.Error("a profile without a proxy or a marker was touched")
	}
	// A corrupt file with no marker is none of our business.
	seed(t, dir, `{bad`)
	if err := webrtcPolicy(dir, false); err != nil {
		t.Errorf("no marker, no proxy: %v", err)
	}
}

func TestWebRTCPolicyLastUsedProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Local State"), []byte(`{"profile":{"last_used":"Profile 2"},"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := webrtcPolicy(dir, true); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"Default", "Profile 2"} {
		b, err := os.ReadFile(filepath.Join(dir, sub, "Preferences"))
		if err != nil || !strings.Contains(string(b), WebRTCPolicy) {
			t.Errorf("%s: %v %s", sub, err, b)
		}
	}
	// Taken out of both without a proxy.
	if err := webrtcPolicy(dir, false); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"Default", "Profile 2"} {
		b, _ := os.ReadFile(filepath.Join(dir, sub, "Preferences"))
		if strings.Contains(string(b), WebRTCPolicy) {
			t.Errorf("%s kept it: %s", sub, b)
		}
	}
	// A last_used that is a path is not followed.
	dir2 := t.TempDir()
	os.WriteFile(filepath.Join(dir2, "Local State"), []byte(`{"profile":{"last_used":"../evil"}}`), 0o600)
	if err := webrtcPolicy(dir2, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "..", "evil")); err == nil {
		t.Error("followed a path out of the profile")
	}
}

func TestWebRTCPolicyCorruptLocalState(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Local State"), []byte(`{oops`), 0o600)
	if err := webrtcPolicy(dir, true); err == nil {
		t.Error("a Local State that is not JSON must stop a run with a proxy")
	}
	if _, err := os.Stat(filepath.Join(dir, "Default", "Preferences")); err == nil {
		t.Error("written despite the error")
	}
	if err := webrtcPolicy(dir, false); err != nil {
		t.Errorf("without a proxy it is none of our business: %v", err)
	}
}

func TestPreferencesJSONNull(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, `null`)
	if err := noPrediction(dir); err != nil { // panicked on a nil map
		t.Fatal(err)
	}
	if m := prefsOf(t, dir); m["net"] == nil {
		t.Errorf("not written: %v", m)
	}
	seed(t, dir, `null`)
	if err := webrtcPolicy(dir, true); err != nil || policyOf(prefsOf(t, dir)) != WebRTCPolicy {
		t.Errorf("webrtc on null: %v", err)
	}
}
