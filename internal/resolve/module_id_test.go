package resolve

import "testing"

// A bundled module's id (what __webpack_require__ or require is given,
// a key of the module map) is no file on the server; a path a loader is
// given still is.
func TestModuleIDsAreNotFiles(t *testing.T) {
	src := `(function(){var __webpack_modules__ = ({
/***/ "./imageLoader/index.js"
/*!******************************!*\
  !*** ./imageLoader/index.js ***!
  \******************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {
var a = __webpack_require__(/*! ./imageLoader/registerLoaders.js */ "./imageLoader/registerLoaders.js");
var b = require("./lib/inflate.js");
__webpack_require__.e(1).then(__webpack_require__.bind(__webpack_require__, /*! ../codecs/pdf.mjs */ "../codecs/pdf.mjs"));
},
/***/ "./imageLoader/colorSpace.js": (function(module, exports) {}),
"./imageLoader/arrow.js": (e, t) => {},
});
var locales = {"./af.js": 522, "./ar.js": 523};
__mfImport("./remote.js");
import("./lazy.js");
var cfg = {webWorkerPath: "../dist/worker.js"};
})()`
	got := map[string]bool{}
	for _, c := range Static([]byte(src), "https://app.local/libs/wado.js", "https://app.local/") {
		if c.Method == "js-string" {
			got[c.URL] = true
		}
	}
	for _, u := range []string{"https://app.local/libs/imageLoader/index.js", "https://app.local/libs/imageLoader/registerLoaders.js",
		"https://app.local/libs/lib/inflate.js", "https://app.local/codecs/pdf.mjs", "https://app.local/libs/imageLoader/colorSpace.js",
		"https://app.local/libs/imageLoader/arrow.js", "https://app.local/libs/af.js", "https://app.local/libs/ar.js"} {
		if got[u] {
			t.Errorf("module id taken for a file: %s", u)
		}
	}
	for _, u := range []string{"https://app.local/libs/remote.js", "https://app.local/dist/worker.js"} {
		if !got[u] {
			t.Errorf("a loader's path lost: %s (got %v)", u, got)
		}
	}
}
