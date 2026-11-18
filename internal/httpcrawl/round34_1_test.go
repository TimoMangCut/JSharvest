package httpcrawl

import (
	"fmt"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/frontier"
)

func TestSkeletonControllerIgnoresOutOfScopeAndNonHTTPLinks(t *testing.T) {
	sc := newSkeletonController()
	cr := &crawler{o: Options{InScope: func(h string) bool { return h == "app.example.test" }}}

	// Feed 20 non-visitable / external / javascript: links under /account/*;
	// they must NOT collapse /account/<tab> into /account/{slug}!
	var noisy []frontier.Found
	for i := 0; i < 20; i++ {
		noisy = append(noisy,
			frontier.Found{URL: fmt.Sprintf("https://app.example.test/account/ext-%d", i), Visit: false, How: frontier.Link},
			frontier.Found{URL: fmt.Sprintf("https://ads.other.example/account/ad-%d", i), Visit: false, How: frontier.Form, Method: "POST"},
			frontier.Found{URL: "javascript:void(0)", Visit: false, How: frontier.Form, Method: "GET"},
		)
	}
	sc.observe(cr, "https://app.example.test/", 200, nil, nil, noisy, nil)

	key, dynamic := sc.skeletonKey("https://app.example.test/account/billing", false)
	if dynamic || key != "https://app.example.test/account/billing" {
		t.Errorf("non-visitable/out-of-scope links polluted Prefix Trie: key=%q dynamic=%v", key, dynamic)
	}
}
