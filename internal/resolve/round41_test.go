package resolve

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime/debug"
	"testing"
	"time"
)

func isRaceBuild() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" && s.Value == "true" {
			return true
		}
	}
	return false
}

func TestRound41ManifestCapDeterministicAndLinear(t *testing.T) {
	const total = 50_000
	var viteBuf, assetBuf, ngswBuf bytes.Buffer
	viteBuf.WriteByte('{')
	assetBuf.WriteString(`{"files":{`)
	ngswBuf.WriteString(`{"assetGroups":[{"name":"app","urls":[`)
	for i := range total {
		if i > 0 {
			viteBuf.WriteByte(',')
			assetBuf.WriteByte(',')
			ngswBuf.WriteByte(',')
		}
		fmt.Fprintf(&viteBuf, `"src/p_%05d.ts":{"file":"assets/c_%05d.js"}`, i, total-1-i)
		fmt.Fprintf(&assetBuf, `"k_%05d.js":"/static/js/c_%05d.js"`, i, total-1-i)
		fmt.Fprintf(&ngswBuf, `"/chunk_%05d.js"`, i)
	}
	viteBuf.WriteByte('}')
	assetBuf.WriteString(`}}`)
	ngswBuf.WriteString(`]}]}`)

	maxDur := 300 * time.Millisecond
	if isRaceBuild() {
		maxDur = 3 * time.Second
	}

	t0 := time.Now()
	v1 := ViteManifest(viteBuf.Bytes(), "https://app.example/build/")
	dVite := time.Since(t0)
	if dVite > maxDur {
		t.Fatalf("ViteManifest(50k) took %s > %s (regressed from O(N log N))", dVite, maxDur)
	}
	v2 := ViteManifest(viteBuf.Bytes(), "https://app.example/build/")
	if len(v1) != MaxManifestEntries || !reflect.DeepEqual(v1, v2) {
		t.Fatalf("ViteManifest non-deterministic or uncapped: len=%d equal=%v", len(v1), reflect.DeepEqual(v1, v2))
	}
	if v1[0] != "https://app.example/build/assets/c_00000.js" {
		t.Fatalf("ViteManifest did not sort before slicing: v1[0]=%q", v1[0])
	}

	t1 := time.Now()
	a1 := AssetManifest(assetBuf.Bytes(), "https://app.example/asset-manifest.json")
	if d := time.Since(t1); d > maxDur {
		t.Fatalf("AssetManifest(50k) took %s > %s", d, maxDur)
	}
	a2 := AssetManifest(assetBuf.Bytes(), "https://app.example/asset-manifest.json")
	if len(a1) != MaxManifestEntries || !reflect.DeepEqual(a1, a2) {
		t.Fatalf("AssetManifest non-deterministic or uncapped: len=%d", len(a1))
	}

	t2 := time.Now()
	n1 := NgswURLs(ngswBuf.Bytes(), "https://app.example/ngsw.json")
	if d := time.Since(t2); d > maxDur {
		t.Fatalf("NgswURLs(50k) took %s > %s", d, maxDur)
	}
	if len(n1) != MaxManifestEntries || n1[0].URL != "https://app.example/chunk_00000.js" {
		t.Fatalf("NgswURLs cap/order mismatch: len=%d first=%+v", len(n1), n1[0])
	}
}
