package jsapi

import (
	"slices"
	"testing"
)

func TestRound33WebpackModuleExportsAndJSONParse(t *testing.T) {
	src := `
(self.webpackChunkapp = self.webpackChunkapp || []).push([[792], {
  77747: (yn, lt, I) => {
    "use strict";
    I.d(lt, { c: () => r });
    const i = JSON.parse('{"url":"https://sso.example.com","realm":"corp","clientId":"portal-fe"}'),
          e = JSON.parse('{"$y":"2026-01-01","kY":"1"}'),
          r = {
            production: !0,
            gateway: "https://app.example.com/api",
            websocketUrl: "https://ws.example.com",
            keycloakConfig: i,
            buildDate: e.$y
          };
  },
  39921: (yn, lt, I) => {
    "use strict";
    I.d(lt, { H: () => S });
    const r = I(77747).c.keycloakConfig.url + "/realms/corp/userrolegroup",
          S = {
            save: r + "/save",
            list: r + "/byuser",
            remove: r + "/remove"
          };
  },
  8330: yn => {
    "use strict";
    yn.exports = { apiBase: "https://cjs.example.com/v2" };
  },
  38410: (yn, lt, I) => {
    "use strict";
    var P = I(77747), Y = I(39921), C = I(8330);
    const Tokens = {};
    Tokens.REFRESH_TOKEN = "refresh_token";
    class AuthSvc {
      constructor(http) {
        this.http = http;
        this.client = "portal-frontend";
        this.clientSecret = "b9d2f011-0000-4000-8000-000000000001";
        this.authUrl = P.c.keycloakConfig.url + "/realms/corp/protocol/openid-connect/token";
        this.notifyHost = P.c.gateway + "/notify-svc";
      }
      login(payload) {
        return this.http.post(this.authUrl, payload);
      }
      saveRole(body) {
        return this.http.post(Y.H.save, body);
      }
      fetchNotifications() {
        return this.http.get(this.notifyHost + "/notifications/unread");
      }
      fetchLegacy() {
        return this.http.get(C.apiBase + "/items");
      }
    }
    new AuthSvc(null);
  }
}]);
`
	res := Extract([]byte(src))
	if res.Error != "" {
		t.Fatalf("unexpected parse error: %s", res.Error)
	}

	var urls []string
	for _, ep := range res.Endpoints {
		urls = append(urls, ep.Method+" "+ep.URL)
	}
	wantURLs := []string{
		"POST https://sso.example.com/realms/corp/protocol/openid-connect/token",
		"POST https://sso.example.com/realms/corp/userrolegroup/save",
		"GET https://app.example.com/api/notify-svc/notifications/unread",
		"GET https://cjs.example.com/v2/items",
	}
	for _, want := range wantURLs {
		if !slices.Contains(urls, want) {
			t.Errorf("missing endpoint %q in %v", want, urls)
		}
	}

	foundSecret := false
	for _, k := range res.Keys {
		if k.Name == "clientSecret" && k.Value == "b9d2f011-0000-4000-8000-000000000001" {
			foundSecret = true
		}
		if k.Name == "REFRESH_TOKEN" && k.Value == "refresh_token" {
			t.Errorf("self-named enum constant leaked into Keys: %+v", k)
		}
	}
	if !foundSecret {
		t.Errorf("expected clientSecret in Keys, got %+v", res.Keys)
	}
}

func TestRound33TemplatePathNamesWithBaseAndQuery(t *testing.T) {
	src := `
const baseUrl = ` + "`${window.location.origin}/${drupalSettings.path.currentLanguage}/api/announcements`" + `;
function loadPage(page) {
  return jQuery.get(` + "`${baseUrl}?page=${page}`" + `);
}
`
	res := Extract([]byte(src))
	if res.Error != "" {
		t.Fatalf("unexpected parse error: %s", res.Error)
	}
	var target *Endpoint
	for i := range res.Endpoints {
		if res.Endpoints[i].URL == "/{}/api/announcements" {
			target = &res.Endpoints[i]
			break
		}
	}
	if target == nil {
		t.Fatalf("expected endpoint /{}/api/announcements, got %+v", res.Endpoints)
	}
	if !slices.Contains(target.Query, "page") {
		t.Errorf("expected query param 'page', got %v", target.Query)
	}
	foundLangPath := false
	for _, p := range target.Params {
		if p.In == "path" && p.Name == "page" {
			t.Errorf("query param 'page' misattributed to path slot: %+v", target.Params)
		}
		if p.In == "path" && p.Name == "currentLanguage" {
			foundLangPath = true
		}
	}
	if !foundLangPath {
		t.Errorf("expected path param 'currentLanguage', got %+v", target.Params)
	}
}
