package sourcemap

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestRound41SourcemapCapsKeepAppAfterLargeVendor(t *testing.T) {
	// 1. 12,000 node_modules/ entries before 200 src/ entries: all 200 app
	// sources must survive, and vendor entries are capped at 5,000.
	m1 := &Map{Version: 3}
	m1.Sources = make([]string, 0, 12_200)
	m1.SourcesContent = make([]*string, 0, 12_200)
	vBody := "module.exports = 1;"
	for i := range 12_000 {
		m1.Sources = append(m1.Sources, fmt.Sprintf("webpack:///./node_modules/pkg-%d/index.js", i))
		m1.SourcesContent = append(m1.SourcesContent, &vBody)
	}
	for i := range 200 {
		body := fmt.Sprintf("fetch('/api/v1/item/%d')", i)
		m1.Sources = append(m1.Sources, fmt.Sprintf("webpack:///./src/api/item-%d.ts", i))
		m1.SourcesContent = append(m1.SourcesContent, &body)
	}
	files1 := m1.FilesFor("https://app.example/assets/main.js")
	own1, vendor1 := 0, 0
	for _, f := range files1 {
		if f.Vendor {
			vendor1++
		} else {
			own1++
		}
	}
	if own1 != 200 {
		t.Fatalf("expected all 200 app sources after 12k vendor entries, got own=%d (vendor=%d)", own1, vendor1)
	}
	if vendor1 != maxVendorSourcesPerMap {
		t.Fatalf("expected vendor capped at %d, got %d", maxVendorSourcesPerMap, vendor1)
	}
	if m1.Truncated != "" {
		t.Fatalf("expected Truncated empty when own <= %d, got %q", maxOwnSourcesPerMap, m1.Truncated)
	}

	// 2. 8,000 own src/ entries -> capped at maxOwnSourcesPerMap (5,000) and marked truncated.
	m2 := &Map{Version: 3}
	appBody := "fetch('/api/orders')"
	for i := range 8_000 {
		m2.Sources = append(m2.Sources, fmt.Sprintf("src/mod_%d.ts", i))
		m2.SourcesContent = append(m2.SourcesContent, &appBody)
	}
	files2 := m2.FilesFor("https://app.example/app.js")
	if len(files2) != maxOwnSourcesPerMap || m2.Truncated != "own_sources>5000" {
		t.Fatalf("expected %d own files and own_sources>5000, got len=%d truncated=%q",
			maxOwnSourcesPerMap, len(files2), m2.Truncated)
	}
	if !m2.CompleteSourcesContent() {
		t.Fatal("complete sourcesContent map capped at 5000 own files should still dedup across hosts")
	}

	// 3. Indexed map whose sections exceed maxTotalMapSources (100,000) is bounded in Parse.
	secSources := make([]string, 10_000)
	for i := range secSources {
		secSources[i] = fmt.Sprintf("src/s_%d.js", i)
	}
	type rawSection struct {
		Map map[string]any `json:"map"`
	}
	sections := make([]rawSection, 12) // 120,000 total
	for i := range sections {
		sections[i] = rawSection{Map: map[string]any{"version": 3, "sources": secSources}}
	}
	rawJSON, err := json.Marshal(map[string]any{"version": 3, "sections": sections})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(rawJSON)
	if err != nil {
		t.Fatalf("Parse indexed map failed: %v", err)
	}
	if len(parsed.Sources) != maxTotalMapSources || len(parsed.SourcesContent) != maxTotalMapSources {
		t.Fatalf("expected Sources and SourcesContent capped at %d, got %d and %d",
			maxTotalMapSources, len(parsed.Sources), len(parsed.SourcesContent))
	}
	if parsed.Truncated != "total_sources>100000" {
		t.Fatalf("expected Truncated=total_sources>100000, got %q", parsed.Truncated)
	}
}
