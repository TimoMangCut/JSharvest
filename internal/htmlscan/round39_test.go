package htmlscan_test

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/htmlscan"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
)

func makeRSCPush(t *testing.T, rows ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(strings.Join(rows, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
	strLit := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	return append(append([]byte("self.__next_f.push([1,"), strLit...), []byte("])")...)
}

func TestRound39RSCDeduperLosslessAndDeterministic(t *testing.T) {
	// Build a >20 KiB shared i18n dictionary row with nested escaped quotes & newlines.
	i18nBody := strings.Repeat(`\"fieldLabel\":\"Giá trị mẫu\\nDòng 2\",`, 600)
	rowFragment := `1:"$Sreact.fragment"`
	rowRootChunk := `4:"/_next/static/chunks/root-layout.js"`
	rowConfig := `8:["$","$L9",null,{"config":{"AUTH_API_URL":"https://api.portal.example.test/v1"}}]`
	rowI18nPage1 := `1a:{"messages":{` + i18nBody + `"end":"ok"}}`
	rowI18nPage2 := `2c:{"messages":{` + i18nBody + `"end":"ok"}}` // renumbered hex ID, identical payload
	rowAdminChunk := `17:I[339756,["/_next/static/chunks/admin-orders.js"],"default"]`
	rowAdminData := `18:["$","$L17",null,{"config":{"ADMIN_API_URL":"https://api.portal.example.test/admin/v2"}}]`

	page1 := makeRSCPush(t, rowFragment, rowRootChunk, rowConfig, rowI18nPage1)
	if len(page1) < 16<<10 {
		t.Fatalf("expected synthetic RSC payload >= 16 KiB, got %d", len(page1))
	}
	page2 := makeRSCPush(t, rowFragment, rowRootChunk, rowI18nPage2, rowAdminChunk, rowAdminData)
	page3Dup := makeRSCPush(t, rowFragment, rowRootChunk, rowI18nPage2)

	var d htmlscan.RSCDeduper
	const orig1 = "https://portal.example.test"
	const orig2 = "https://partner.example.test"

	// 1. Page 1 on orig1 keeps 100% of original bytes untouched.
	out1, keep1 := d.Compact(orig1, page1)
	if !keep1 || !bytes.Equal(out1, page1) {
		t.Fatalf("page1 should be kept byte-for-byte intact (keep=%v, len=%d vs %d)", keep1, len(out1), len(page1))
	}
	r1 := jsapi.Extract(out1)
	if !slices.Contains(r1.Bases, "https://api.portal.example.test/v1") {
		t.Fatalf("page1 lost RSC config base: %v", r1.Bases)
	}

	// 2. Page 2 on orig1 strips >95% duplicated i18n/layout rows while preserving novel route chunks & endpoints.
	out2, keep2 := d.Compact(orig1, page2)
	if !keep2 {
		t.Fatal("page2 has novel route rows and must be kept")
	}
	if len(out2) >= len(page2)/20 {
		t.Fatalf("expected >95%% compaction on page2, got %d bytes from %d bytes", len(out2), len(page2))
	}
	cands2 := resolve.Static(out2, orig1+"/admin", orig1+"/admin")
	var urls2 []string
	for _, c := range cands2 {
		urls2 = append(urls2, c.URL)
	}
	if !slices.Contains(urls2, orig1+"/_next/static/chunks/admin-orders.js") {
		t.Fatalf("compacted page2 lost novel Next.js chunk: got %v", urls2)
	}
	r2 := jsapi.Extract(out2)
	if !slices.Contains(r2.Bases, "https://api.portal.example.test/admin/v2") {
		t.Fatalf("compacted page2 failed AST parse or lost RSC config base: got %v", r2.Bases)
	}

	// 3. Page 3 with 0 novel rows is skipped completely.
	if out3, keep3 := d.Compact(orig1, page3Dup); keep3 || out3 != nil {
		t.Fatalf("expected duplicate RSC block to return keep=false, got keep=%v len=%d", keep3, len(out3))
	}

	// 4. A different origin gets its own full Page 1 so root-relative chunk URLs resolve on orig2.
	outOrig2, keepOrig2 := d.Compact(orig2, page1)
	if !keepOrig2 || !bytes.Equal(outOrig2, page1) {
		t.Fatal("distinct origin must keep its own full first RSC payload")
	}

	// 5. Freeze() keeps stripping already-learned rows without mutating state across concurrent tabs.
	var frozen htmlscan.RSCDeduper
	frozen.Compact(orig1, page1)
	frozen.Freeze()
	a, okA := frozen.Compact(orig1, page2)
	b, okB := frozen.Compact(orig1, page2)
	if !okA || !okB || !bytes.Equal(a, b) {
		t.Fatalf("frozen deduper must be idempotent across repeated calls: okA=%v okB=%v equal=%v", okA, okB, bytes.Equal(a, b))
	}
}
