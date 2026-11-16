package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSampleDICOMAndExploreShared(t *testing.T) {
	dcm := sampleDICOM()
	if len(dcm) < 132+26 {
		t.Fatalf("sampleDICOM len = %d, too short", len(dcm))
	}
	for i, b := range dcm[:128] {
		if b != 0 {
			t.Fatalf("preamble byte %d = %x, want 0", i, b)
		}
	}
	if string(dcm[128:132]) != "DICM" {
		t.Fatalf("magic = %q, want DICM", dcm[128:132])
	}
	if !bytes.Contains(dcm[132:], []byte("1.2.840.10008.1.2")) {
		t.Fatalf("TransferSyntaxUID missing in sampleDICOM")
	}

	sh, err := newExploreShared()
	if err != nil {
		t.Fatal(err)
	}
	defer sh.close()
	for _, name := range []string{"document.txt", "image.png", "IM000001"} {
		if st, err := os.Stat(filepath.Join(sh.dir, name)); err != nil || st.Size() == 0 {
			t.Errorf("%s in %s: st=%v err=%v", name, sh.dir, st, err)
		}
	}
}
