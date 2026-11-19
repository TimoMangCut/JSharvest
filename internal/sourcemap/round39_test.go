package sourcemap

import "testing"

func TestRound39VendorMapAdminLTEAndHybridGuard(t *testing.T) {
	rawPure := []byte(`{
		"version": 3,
		"sources": ["build/js/CardRefresh.js", "build/js/Treeview.js"],
		"sourcesContent": ["export class CardRefresh {}", "export class Treeview {}"]
	}`)
	smPure, err := Parse(rawPure)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range smPure.FilesFor("https://portal.example.test/assets/cms/dist/js/adminlte.min.js") {
		if !f.Vendor {
			t.Fatalf("expected AdminLTE widget %q to be marked Vendor=true", f.Path)
		}
	}

	// Hybrid bundle served under a library name must still preserve explicit app sources.
	rawHybrid := []byte(`{
		"version": 3,
		"sources": ["build/js/CardRefresh.js", "resources/js/admin/orders.js"],
		"sourcesContent": ["export class CardRefresh {}", "axios.get('/api/v1/orders')"]
	}`)
	smHybrid, err := Parse(rawHybrid)
	if err != nil {
		t.Fatal(err)
	}
	files := smHybrid.FilesFor("https://portal.example.test/assets/cms/dist/js/adminlte.min.js")
	if len(files) != 2 || files[0].Path != "resources/js/admin/orders.js" || files[0].Vendor {
		t.Fatalf("expected explicit app source resources/js/admin/orders.js to remain own file first, got %+v", files)
	}
}
