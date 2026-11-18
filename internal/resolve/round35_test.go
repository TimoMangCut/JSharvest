package resolve

import (
	"slices"
	"testing"
)

func TestWebpack5SubTermTernaryNameAndHash(t *testing.T) {
	srcOneSide := []byte(`(()=>{var t={};t.p="";t.u=e=>(76===e?"common":592===e?"shared":e)+"."+{13:"3e2040617982a516",76:"eddd5f048c35007b",592:"aa11bb22cc33dd44"}[e]+".js";})();`)
	rt := ExtractWebpackRuntime(srcOneSide, "https://app.example.test/runtime.8f12a3.js", "https://app.example.test/")
	if rt == nil {
		t.Fatal("ExtractWebpackRuntime returned nil on Webpack 5 sub-term ternary name builder")
	}
	var urls []string
	for _, c := range rt.StaticCandidates() {
		urls = append(urls, c.URL)
	}
	slices.Sort(urls)
	want := []string{
		"https://app.example.test/13.3e2040617982a516.js",
		"https://app.example.test/common.eddd5f048c35007b.js",
		"https://app.example.test/shared.aa11bb22cc33dd44.js",
	}
	if !slices.Equal(urls, want) {
		t.Fatalf("got %v, want %v", urls, want)
	}

	srcBothSides := []byte(`(()=>{var r={};r.p="/assets/";r.u=e=>(76===e?"common":e)+"."+(13===e?"3e204061":76===e?"eddd5f04":e)+".js";})();`)
	rt2 := ExtractWebpackRuntime(srcBothSides, "https://app.example.test/assets/runtime.js", "https://app.example.test/")
	if rt2 == nil {
		t.Fatal("ExtractWebpackRuntime returned nil when both name and hash slots are sub-term ternaries")
	}
	var urls2 []string
	for _, c := range rt2.StaticCandidates() {
		urls2 = append(urls2, c.URL)
	}
	slices.Sort(urls2)
	want2 := []string{
		"https://app.example.test/assets/13.3e204061.js",
		"https://app.example.test/assets/common.eddd5f04.js",
	}
	if !slices.Equal(urls2, want2) {
		t.Fatalf("got %v, want %v", urls2, want2)
	}
}
