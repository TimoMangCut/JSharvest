package frontier

import "testing"

func TestLinkRelAlternateMIMEGatePreservesFeedRoutes(t *testing.T) {
	rawHTML := `<!doctype html><html><head>
<link rel="alternate" href="/alt">
<link rel="alternate" hreflang="tr" type="text/html; charset=utf-8" href="/tr/home">
<link rel="alternate" type="application/json" href="/api/feed.json">
<link rel="alternate" type="application/vnd.api+json" href="/api/v2/items">
<link rel="alternate" type="application/rss+xml; charset=UTF-8" href="/feed/">
<link rel="alternate" type="application/atom+xml" href="/comments/feed/">
<link rel="alternate" type="application/opensearchdescription+xml" href="/opensearch.xml">
</head><body>
<a href="/feed">App Feed Tab</a>
<a href="/api/v1/feed">Internal Feed Endpoint</a>
</body></html>`

	pageURL := "https://portal.example.test/index.html"
	gotHTML := keys(FromHTML(rawHTML, pageURL))
	has(t, gotHTML,
		"link visit https://portal.example.test/alt",
		"link visit https://portal.example.test/tr/home",
		"link visit https://portal.example.test/api/feed.json",
		"link visit https://portal.example.test/api/v2/items",
		"link visit https://portal.example.test/feed",
		"link visit https://portal.example.test/api/v1/feed",
		"resource name https://portal.example.test/feed/",
		"resource name https://portal.example.test/comments/feed/",
		"resource name https://portal.example.test/opensearch.xml",
	)

	root := doc(pageURL,
		el("html", nil,
			el("head", nil,
				el("link", []string{"rel", "alternate", "href", "/alt"}),
				el("link", []string{"rel", "alternate", "type", "text/html; charset=utf-8", "href", "/tr/home"}),
				el("link", []string{"rel", "alternate", "type", "application/json", "href", "/api/feed.json"}),
				el("link", []string{"rel", "alternate", "type", "application/rss+xml; charset=UTF-8", "href", "/feed/"}),
				el("link", []string{"rel", "alternate", "type", "application/atom+xml", "href", "/comments/feed/"}),
			),
			el("body", nil,
				el("a", []string{"href", "/feed"}),
				el("a", []string{"href", "/api/v1/feed"}),
			),
		),
	)
	gotDOM := keys(FromDOM(root, pageURL))
	has(t, gotDOM,
		"link visit https://portal.example.test/alt",
		"link visit https://portal.example.test/tr/home",
		"link visit https://portal.example.test/api/feed.json",
		"link visit https://portal.example.test/feed",
		"link visit https://portal.example.test/api/v1/feed",
		"resource name https://portal.example.test/feed/",
		"resource name https://portal.example.test/comments/feed/",
	)
}
