// Command testbed serves the testbed apps and scores jsharvest output against
// each app's ground truth.
//
//	testbed serve -app testbed/apps/webpack-vanilla [-addr 127.0.0.1:8770]
//	testbed score -app testbed/apps/webpack-vanilla -out output/127.0.0.1/anon
//	testbed reqcheck -log server.log -requests output/127.0.0.1/anon/requests.jsonl
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: testbed serve|score|reqcheck|drive|flowscore|epscore|mcpcall|mazescore|frontscore [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "score":
		err = score(os.Args[2:])
	case "reqcheck":
		err = reqcheck(os.Args[2:])
	case "drive":
		err = drive(os.Args[2:])
	case "flowscore":
		err = flowscore(os.Args[2:])
	case "epscore":
		err = epscore(os.Args[2:])
	case "mcpcall":
		err = mcpcall(os.Args[2:])
	case "mazescore":
		err = mazescore(os.Args[2:])
	case "archivecheck":
		err = archivecheck(os.Args[2:])
	case "authzscore":
		err = authzscore(os.Args[2:])
	case "exportcheck":
		err = exportcheck(os.Args[2:])
	case "rolescore":
		err = rolescore(os.Args[2:])
	case "explorescore":
		err = explorescore(os.Args[2:])
	case "frontscore":
		err = frontscore(os.Args[2:])
	case "pipecheck":
		err = pipecheck(os.Args[2:])
	case "verifycheck":
		err = verifycheck(os.Args[2:])
	case "crossserve":
		err = crossserve(os.Args[2:])
	case "crosscheck":
		err = crosscheck(os.Args[2:])
	case "logproxy":
		err = logproxy(os.Args[2:])
	case "perfgate":
		err = perfgate(os.Args[2:])
	case "peerscore":
		err = peerscore(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(args []string) error {
	fset := flag.NewFlagSet("serve", flag.ExitOnError)
	app := fset.String("app", "", "app directory (with dist/ and private/)")
	addr := fset.String("addr", "127.0.0.1:8770", "listen address")
	fset.Parse(args)
	if *app == "" {
		return fmt.Errorf("-app is required")
	}
	// TESTBED_DIST picks another build of the app (monitor-app's dist-v2).
	distName := os.Getenv("TESTBED_DIST")
	if distName == "" {
		distName = "dist"
	}
	dist := filepath.Join(*app, distName)
	private := filepath.Join(*app, "private")

	mux := http.NewServeMux()

	// Sessions live on the server, so that one can end there (expire) and
	// a client keeping its cookie is logged out all the same.
	var sessMu sync.Mutex
	sessions := map[string]string{} // token -> role
	sessionRole := func(r *http.Request) (string, bool) {
		c, err := r.Cookie("session")
		if err != nil {
			return "", false
		}
		sessMu.Lock()
		defer sessMu.Unlock()
		role, ok := sessions[c.Value]
		return role, ok
	}

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		email := r.FormValue("email")
		if email == "" || len(r.FormValue("password")) < 6 {
			http.Error(w, `{"error":"bad credentials"}`, http.StatusUnauthorized)
			return
		}
		role := "user"
		if strings.HasPrefix(email, "admin") {
			role = "admin"
		}
		t := token()
		sessMu.Lock()
		sessions[t] = role
		sessMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: t, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "role", Value: role, Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"role":%q,"token":%q}`, role, t)
	})

	// A login a person did by hand, for the container gate: opening the
	// page logs in, as a person through noVNC would.
	mux.HandleFunc("GET /dev/hand-login", func(w http.ResponseWriter, r *http.Request) {
		t := token()
		sessMu.Lock()
		sessions[t] = "user"
		sessMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: t, Path: "/"})
		http.Redirect(w, r, "/?in=1", http.StatusFound)
	})
	mux.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		role, ok := sessionRole(r)
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"not logged in"}`)
			return
		}
		fmt.Fprintf(w, `{"role":%q}`, role)
	})

	// session-app: a page that wipes the client's cookies and storage, and
	// one that ends the session on the server. Neither name reads as a
	// logout, or as anything destructive, as such pages often do not
	// (/account/wipe was its name, until the guard learnt "wipe").
	mux.HandleFunc("/account/privacy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
		fmt.Fprint(w, `<!doctype html><title>wiped</title><p>Your data was cleared.</p>`)
	})
	mux.HandleFunc("/account/expire", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			sessMu.Lock()
			delete(sessions, c.Value)
			sessMu.Unlock()
		}
		http.Redirect(w, r, "/members/home", http.StatusFound)
	})
	// Members' pages and scripts: only for a session the server knows.
	mux.HandleFunc("/members/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := sessionRole(r); !ok {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusFound)
			return
		}
		// A logged-in page is not to be kept: a browser would show it from
		// its cache after the session ended.
		w.Header().Set("Cache-Control", "no-store")
		p := filepath.Join(dist, path.Clean(r.URL.Path))
		for _, c := range []string{p, p + ".html"} {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				serveFile(w, r, c)
				return
			}
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		for _, n := range []string{"session", "role"} {
			http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", MaxAge: -1})
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})

	// role-app (4.7): API and pages that answer by role. /api/ra/me/ needs a
	// login (401), /api/ra/admin/ an admin (401, then 403); /ra/config.js
	// says which role asked; /ra/admin sends anon to the login and refuses
	// a user.
	jsonError := func(w http.ResponseWriter, code int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":%q}`, http.StatusText(code))
	}
	mux.HandleFunc("/api/ra/me/", func(w http.ResponseWriter, r *http.Request) {
		role, ok := sessionRole(r)
		if !ok {
			jsonError(w, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"role":%q}`, role)
	})
	mux.HandleFunc("/api/ra/admin/", func(w http.ResponseWriter, r *http.Request) {
		switch role, ok := sessionRole(r); {
		case !ok:
			jsonError(w, http.StatusUnauthorized)
		case role != "admin" && r.URL.Path != "/api/ra/admin/summary": // the summary forgets to check the role
			jsonError(w, http.StatusForbidden)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	})
	// A login redirect for an API call; a legacy endpoint that refuses a
	// user but not anon; and a vendor bundle whose build hash differs by
	// role, as after a deploy between two crawls.
	mux.HandleFunc("/api/ra/me/inbox", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := sessionRole(r); !ok {
			http.Redirect(w, r, "/login?next=/inbox", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"messages":[]}`)
	})
	mux.HandleFunc("/api/ra/pub/legacy", func(w http.ResponseWriter, r *http.Request) {
		if role, ok := sessionRole(r); ok && role == "user" {
			jsonError(w, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("GET /ra/js/{file}", func(w http.ResponseWriter, r *http.Request) {
		if f := r.PathValue("file"); strings.HasPrefix(f, "vendor.") {
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprintf(w, "// vendor bundle, build %s\nwindow.VENDOR = %q;\n", f, f)
			return
		}
		serveFile(w, r, filepath.Join(dist, "ra", "js", path.Clean(r.PathValue("file"))))
	})
	mux.HandleFunc("GET /ra/config.js", func(w http.ResponseWriter, r *http.Request) {
		role, ok := sessionRole(r)
		if !ok {
			role = "anon"
		}
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "window.CONFIG = {role: %q, flags: %q};\n", role, map[string][]string{"anon": {}, "user": {"orders"}, "admin": {"orders", "audit", "keys"}}[role])
		build := map[string]string{"anon": "a1b2c3d4", "user": "e5f6a7b8", "admin": "c9d0e1f2"}[role]
		fmt.Fprintf(w, "document.write('<script src=\"/ra/js/vendor.%s.js\"><\\/script>');\n", build)
	})
	mux.HandleFunc("/ra/admin", func(w http.ResponseWriter, r *http.Request) {
		switch role, ok := sessionRole(r); {
		case !ok:
			http.Redirect(w, r, "/login?next=/ra/admin", http.StatusFound)
		case role != "admin":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			w.Header().Set("Cache-Control", "no-store")
			serveFile(w, r, filepath.Join(dist, "ra", "admin.html"))
		}
	})

	// Server-gated JS: only an admin session gets these files.
	mux.HandleFunc("/private/", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("role"); err != nil || c.Value != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.ServeFile(w, r, filepath.Join(private, path.Clean(strings.TrimPrefix(r.URL.Path, "/private/"))))
	})

	// Files that the bundler does not touch: workers, service workers, frames.
	mux.Handle("/extra/", http.StripPrefix("/extra/", http.FileServer(http.Dir(filepath.Join(*app, "extra")))))

	// A script larger than Chrome's default 20 MB per-resource buffer, made on
	// the fly so the repository does not hold it. The marker is at the end.
	mux.HandleFunc("/gen/big.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		line := []byte("// " + strings.Repeat("x", 1021) + "\n")
		for range 25 << 10 { // 25 MiB
			w.Write(line)
		}
		fmt.Fprint(w, "console.debug('JSHMARK:big:tail');\n")
	})

	// A page that looks like a bot challenge, to test detection only. It is a
	// local fixture and imitates no live service.
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `<!doctype html><title>Just a moment...</title><p>checking</p>`)
	})

	// A healthy 200 page that still loads a challenge-platform script, as
	// sites with bot management do on every page. Detection must not call
	// this blocked.
	mux.HandleFunc("/jsd-ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Welcome</title><p>ok</p><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>`)
	})
	mux.HandleFunc("/cdn-cgi/challenge-platform/scripts/jsd/main.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprint(w, "window.__jsd = 1;\n")
	})

	// A challenge page as a real one runs (CF-01, CF-02; a local fixture that
	// imitates no live service): a 403 whose inline loader sets
	// _cf_chl_opt and loads the platform script, which evaluates a large
	// block (with no URL; its initiator is the platform) and posts its
	// telemetry to /cdn-cgi/. A site script on the page is the page's, and
	// the page is a challenge: none of it may reach the store or the
	// endpoint catalog, and the posts must pass the guard.
	mux.HandleFunc("/cf-challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><title>Just a moment...</title><p>checking</p>
<script>(function(){window._cf_chl_opt={cvId:'3',cType:'managed'};var s=document.createElement('script');s.src='/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=1';document.head.appendChild(s);})();</script>
<script src="/cf-on-blocked.js"></script>`)
	})
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		block := "var __vm=[" + strings.Repeat("0x1f,", 40000) + "0];fetch('/api/vm-junk');"
		fmt.Fprintf(w, `(function(){for(var i=0;i<3;i++){eval(%q+'//'+i);}
fetch('/cdn-cgi/challenge-platform/h/b/flow/ov1/713:179:_Iz/a563/N.lD-1.2.1.1-XN',{method:'POST',body:'x'});
fetch('/cdn-cgi/challenge-platform/h/b/fo/x-Delete-y/managed',{method:'POST',body:'y'});})();`, block)
	})
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/b/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{}")
	})
	mux.HandleFunc("/cf-on-blocked.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "fetch('/api/on-blocked-page');\n")
	})
	// A healthy page behind the CDN: the injected jsd snippet, Cloudflare's
	// email decoder and RUM beacon, and the site's own script, which alone
	// is the site's.
	mux.HandleFunc("/cf-healthy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Admin</title><p>ok</p>
<script src="/cf-app.js"></script>
<script src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script>
<script>(function(){var a=document.createElement('iframe');a.height=1;a.width=1;a.style.display='none';document.body.appendChild(a);var c=a.contentDocument;if(c){var d=c.createElement('script');d.src='/cdn-cgi/challenge-platform/scripts/jsd/main.js';c.head.appendChild(d);}})();</script>`)
	})
	mux.HandleFunc("/cf-app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "fetch('/api/cf-real?x=1');\n")
	})
	mux.HandleFunc("/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "fetch('/cdn-cgi/rum?',{method:'POST',body:'{}'});\n")
	})
	mux.HandleFunc("/cdn-cgi/rum", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// A challenge that passes on its own (CF-06's grace; a local fixture):
	// the 403 page posts its answer to /cdn-cgi/, which sets a cookie, and
	// reloads; with the cookie the page is the site's.
	// The challenge answers after 2.5 s, longer than the crawl's -idle
	// (1.5 s): the tab goes quiet on the challenge first, so the pass is
	// seen by -challenge-wait's loop, not by the idle wait (NEW-D14-01).
	mux.HandleFunc("/cf-passes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		if c, err := r.Cookie("cf_pass"); err == nil && c.Value == "1" {
			fmt.Fprint(w, `<!doctype html><title>Admin</title><p>welcome</p><script src="/cf-passed-app.js"></script>`)
			return
		}
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><title>Just a moment...</title><script>window._cf_chl_opt={cvId:'3'};
setTimeout(function(){fetch('/cdn-cgi/challenge-platform/h/b/flow/ov1/pass',{method:'POST',body:'ok'}).then(function(){location.reload()})},2500);</script>`)
	})
	// A deny page that only its title tells (round 18): Cloudflare's
	// "Attention Required!" (a WAF rule's block) carries no cf-mitigated,
	// and its inline scripts are Cloudflare's. And a 403 of the site's own
	// behind the CDN, whose script is the site's.
	mux.HandleFunc("/cf-deny", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "8d0000000000000-SIN")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><html><head><title>Attention Required! | Cloudflare</title>
<script>if(!navigator.cookieEnabled){window.addEventListener('DOMContentLoaded',function(){document.getElementById('cookie-alert').style.display='block'})}</script>
<script>window._cf_translation = {};</script></head><body><h1>Sorry, you have been blocked</h1>
<span id="cf-footer-ip">127.0.0.1</span><script>(function(){var a=document;var b=a.getElementById("cf-footer-item-ip");b&&b.classList.remove("hidden")})();</script>
</body></html>`)
	})
	mux.HandleFunc("/cf-site-403", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "8d0000000000001-SIN")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><title>No access</title><p>members only</p><script>fetch('/api/site-403-inline')</script>`)
	})
	// A page whose link leads to that challenge (round 18): plain HTTP
	// meets it on the second page, and crawl -engine auto hands it to
	// Chrome.
	mux.HandleFunc("/cf-links", func(w http.ResponseWriter, r *http.Request) {
		// An application cookie Chrome must take on when the crawl
		// escalates, and a CDN's it must not (round 25L).
		http.SetCookie(w, &http.Cookie{Name: "app_region", Value: "vn", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "go-client", Path: "/"})
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>Home</title><a href="/cf-passes">admin</a><script src="/cf-app.js"></script>`)
	})
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/b/flow/ov1/pass", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "cf_pass", Value: "1", Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/cf-passed-app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "fetch('/api/after-challenge');\n")
	})

	// What the browser presents (CF-06): the page, its worker and their
	// fetches log their User-Agent, Sec-CH-UA and navigator.webdriver.
	mux.HandleFunc("/ua-page", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("UA page %q | CH %q", r.Header.Get("User-Agent"), r.Header.Get("Sec-Ch-Ua"))
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>ua</title><script>
fetch('/ua-check?from=page&wd=' + navigator.webdriver + '&uad=' + encodeURIComponent(JSON.stringify((navigator.userAgentData||{}).brands||[])));
new Worker('/ua-worker.js');
</script>`)
	})
	mux.HandleFunc("/ua-worker.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "setTimeout(() => fetch('/ua-check?from=worker'), 300);\n")
	})
	mux.HandleFunc("/ua-check", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("UA %s %q | CH %q", r.URL.Query().Get("from"), r.Header.Get("User-Agent"), r.Header.Get("Sec-Ch-Ua"))
		w.WriteHeader(http.StatusNoContent)
	})

	// Block pages of other vendors, for detection only. Each is a local
	// fixture and imitates no live service.
	mux.HandleFunc("/blocked-datadome", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Datadome", "protected")
		w.Header().Set("X-Dd-B", "1")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><title>blocked</title>`)
	})
	mux.HandleFunc("/blocked-akamai", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AkamaiGHost")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><title>Access Denied</title><p>You don't have permission. Reference #18.abcd</p>`)
	})
	mux.HandleFunc("/blocked-imperva", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Iinfo", "1-2-3")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<!doctype html><title>Request unsuccessful</title><p>Incapsula incident ID: 123-456</p>`)
	})

	// Moves a www. host to its apex, as many sites do: run the testbed under
	// host names with -host-resolver-rules "MAP *.jsh.test 127.0.0.1, MAP
	// jsh.test 127.0.0.1" and start at http://www.jsh.test:8770/to-apex.
	mux.HandleFunc("/to-apex", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+strings.TrimPrefix(r.Host, "www.")+"/", http.StatusFound)
	})

	// A chunk on another in-scope origin (run under *.jsh.test names), sent
	// with "Access-Control-Allow-Origin: *" as CDNs do: a credentialed
	// fetch of it fails CORS and loses the body without an error.
	mux.HandleFunc("/cdn-chunk.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/javascript")
		fmt.Fprint(w, "console.debug('JSHMARK:resolve:cross-origin');\n")
	})

	// An in-scope chunk URL that redirects out of scope: the resolver may
	// request this one, but must never follow it to the decoy.
	mux.HandleFunc("/redirect-bait.js", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:8770/decoy-redirected.js", http.StatusFound)
	})

	// Any other /api/ call answers OK, whatever the method: the guard
	// fixture uses it to see which writes reach the server.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	// flows-app: a session cookie, a CSRF token of that session that the
	// next request must carry, and items whose responses name their id. The
	// export gate replays the profile's save: it must carry both. A token
	// is signed for its session (nonce.mac), as frameworks sign theirs: it
	// stays good across the server's restarts, so a save recorded before
	// can be replayed.
	var csrfTTL time.Duration
	if n, err := strconv.Atoi(os.Getenv("TESTBED_CSRF_TTL")); err == nil && n > 0 {
		csrfTTL = time.Duration(n) * time.Second
	}
	csrfFor := func(sid, nonce string) string {
		m := hmac.New(sha256.New, []byte("jsharvest-testbed-csrf"))
		m.Write([]byte(sid + "." + nonce))
		return nonce + "." + hex.EncodeToString(m.Sum(nil))[:16]
	}
	// The session id is signed the same way: one the server did not give
	// (a redacted one) is no session.
	validSession := func(r *http.Request) (string, bool) {
		c, err := r.Cookie("fsid")
		if err != nil {
			return "", false
		}
		nonce, _, _ := strings.Cut(c.Value, ".")
		return c.Value, hmac.Equal([]byte(c.Value), []byte(csrfFor("session", nonce)))
	}
	flowSession := func(w http.ResponseWriter, r *http.Request) string {
		if sid, ok := validSession(r); ok {
			return sid
		}
		sid := csrfFor("session", token()[:12])
		http.SetCookie(w, &http.Cookie{Name: "fsid", Value: sid, Path: "/", HttpOnly: true})
		return sid
	}
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		flowSession(w, r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("GET /api/csrf", func(w http.ResponseWriter, r *http.Request) {
		// The nonce says when it was given: TESTBED_CSRF_TTL (seconds) makes
		// tokens expire, for the replay gate.
		t := csrfFor(flowSession(w, r), strconv.FormatInt(time.Now().Unix(), 36)+"-"+token()[:8])
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"csrf":%q}`, t)
	})
	// The export, which a worker fetches: only for the session.
	mux.HandleFunc("GET /api/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, ok := validSession(r); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"no session"}`)
			return
		}
		fmt.Fprintf(w, `{"format":%q}`, r.URL.Query().Get("format"))
	})
	mux.HandleFunc("POST /api/profile", func(w http.ResponseWriter, r *http.Request) {
		// The body must be JSON: a 200 tells a fuzzer's request was whole
		// (Reviewer round 4, NEW-5.1-06).
		if body, err := io.ReadAll(r.Body); err != nil || !json.Valid(body) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"bad json"}`)
			return
		}
		sid, ok := validSession(r)
		t := r.Header.Get("X-CSRF-Token")
		nonce, _, _ := strings.Cut(t, ".")
		ok = ok && t != "" && hmac.Equal([]byte(t), []byte(csrfFor(sid, nonce)))
		if issued, _, _ := strings.Cut(nonce, "-"); ok && csrfTTL > 0 {
			if at, err := strconv.ParseInt(issued, 36, 64); err != nil || time.Since(time.Unix(at, 0)) > csrfTTL {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":"csrf expired"}`)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"csrf"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	// authz-app (5.1): an admin's endpoints the server checks well, badly
	// or not at all, and traps for authz's verdicts (authz.truth.json).
	azJSON := func(w http.ResponseWriter, code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	}
	azRole := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		role, ok := sessionRole(r)
		if !ok {
			azJSON(w, http.StatusUnauthorized, `{"error":"not logged in"}`)
		}
		return role, ok
	}
	azCSRF := func(w http.ResponseWriter, r *http.Request) bool {
		c, err := r.Cookie("session")
		t := r.Header.Get("X-CSRF-Token")
		nonce, _, _ := strings.Cut(t, ".")
		if err != nil || t == "" || !hmac.Equal([]byte(t), []byte(csrfFor("az"+c.Value, nonce))) {
			azJSON(w, http.StatusForbidden, `{"error":"csrf"}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/az/pub/news", func(w http.ResponseWriter, r *http.Request) {
		azJSON(w, 200, `{"news":[{"id":1,"title":"Hello"}]}`)
	})
	mux.HandleFunc("GET /api/az/me", func(w http.ResponseWriter, r *http.Request) {
		if role, ok := azRole(w, r); ok {
			azJSON(w, 200, fmt.Sprintf(`{"role":%q,"name":"%s@authz.test"}`, role, role))
		}
	})
	mux.HandleFunc("GET /api/az/csrf", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := azRole(w, r); ok {
			c, _ := r.Cookie("session")
			azJSON(w, 200, fmt.Sprintf(`{"csrf":%q}`, csrfFor("az"+c.Value, token()[:12])))
		}
	})
	mux.HandleFunc("GET /api/az/admin/stats", func(w http.ResponseWriter, r *http.Request) { // checked well
		if role, ok := azRole(w, r); ok {
			if role != "admin" {
				azJSON(w, 403, `{"error":"forbidden"}`)
				return
			}
			azJSON(w, 200, `{"users":12,"orders":340}`)
		}
	})
	mux.HandleFunc("GET /api/az/admin/summary", func(w http.ResponseWriter, r *http.Request) { // any login: a bypass, with a time stamp
		if _, ok := azRole(w, r); ok {
			azJSON(w, 200, fmt.Sprintf(`{"orders":340,"revenue":1234,"generated":%d}`, time.Now().UnixNano()))
		}
	})
	mux.HandleFunc("GET /api/az/admin/export", func(w http.ResponseWriter, r *http.Request) { // no check at all
		azJSON(w, 200, `{"customers":[{"id":1,"email":"c1@authz.test"},{"id":2,"email":"c2@authz.test"}]}`)
	})
	mux.HandleFunc("GET /api/az/admin/report", func(w http.ResponseWriter, r *http.Request) { // 200 with an error body
		if role, _ := sessionRole(r); role == "admin" {
			azJSON(w, 200, `{"rows":[{"day":"mon","total":3}]}`)
			return
		}
		azJSON(w, 200, `{"error":"forbidden"}`)
	})
	mux.HandleFunc("GET /api/az/admin/flags", func(w http.ResponseWriter, r *http.Request) { // the SPA's page for others
		if role, _ := sessionRole(r); role == "admin" {
			azJSON(w, 200, `{"flags":{"beta":true}}`)
			return
		}
		serveFile(w, r, filepath.Join(dist, "index.html"))
	})
	mux.HandleFunc("GET /api/az/admin/orders", func(w http.ResponseWriter, r *http.Request) { // filtered by role
		if role, ok := azRole(w, r); ok {
			if role == "admin" {
				azJSON(w, 200, `{"orders":[{"id":1,"owner":"admin"},{"id":2,"owner":"user"},{"id":3,"owner":"other"}]}`)
				return
			}
			azJSON(w, 200, `{"orders":[{"id":2,"owner":"user"}]}`)
		}
	})
	mux.HandleFunc("GET /api/az/admin/accounts/{id}", func(w http.ResponseWriter, r *http.Request) { // its own object for others
		if role, ok := azRole(w, r); ok {
			if role == "admin" {
				id := r.PathValue("id")
				azJSON(w, 200, fmt.Sprintf(`{"id":%q,"email":"account%s@authz.test","name":"Account %s"}`, id, id, id))
				return
			}
			azJSON(w, 200, `{"id":"42","email":"user@authz.test","name":"User"}`)
		}
	})
	mux.HandleFunc("POST /api/az/admin/invite", func(w http.ResponseWriter, r *http.Request) { // CSRF, then the role
		if role, ok := azRole(w, r); ok && azCSRF(w, r) {
			if role != "admin" {
				azJSON(w, 403, `{"error":"forbidden"}`)
				return
			}
			azJSON(w, 201, `{"invited":true}`)
		}
	})
	mux.HandleFunc("POST /api/az/admin/notes", func(w http.ResponseWriter, r *http.Request) { // CSRF, no role check
		if _, ok := azRole(w, r); ok && azCSRF(w, r) {
			azJSON(w, 201, fmt.Sprintf(`{"id":"n_%s"}`, token()[:8]))
		}
	})
	mux.HandleFunc("/api/az/admin/cache", func(w http.ResponseWriter, r *http.Request) {
		azJSON(w, 200, `{"wiped":true}`)
	})
	// monitor-app: a report the server refuses in v1 and gives in v2 (a
	// change of its authorization monitor must call high).
	mux.HandleFunc("GET /api/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if distName != "dist-v2" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		fmt.Fprint(w, `{"rows":[]}`)
	})
	// A webhook's receiver, for monitor's gate: it keeps each body.
	mux.HandleFunc("POST /fake-webhook", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		dest := os.Getenv("TESTBED_WEBHOOK_LOG")
		if dest == "" {
			http.Error(w, "no TESTBED_WEBHOOK_LOG", http.StatusNotFound)
			return
		}
		f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			f.Write(append(bytes.TrimSpace(b), '\n'))
			f.Close()
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/notes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"note_%s"}`, token())
	})
	mux.HandleFunc("GET /api/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"name":"item %s"}`, r.PathValue("id"), r.PathValue("id"))
	})
	// A WebSocket echo, for the guard fixture: the guard stubs page sockets
	// out, so this should never be reached with the guard on.
	// The request log is written when a handler returns, which a socket
	// only does at the end, so the handshake is logged here.
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		log.Printf("101 GET /ws (websocket opened)")
		io.Copy(ws, ws)
	}))
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"me":{"id":"1"}}}`)
	})
	// A response that tells the browser to wipe the site's cookies and
	// storage, as some logout endpoints do.
	mux.HandleFunc("/csd", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})

	// A page whose network never goes quiet, to test the idle limit.
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>poll</title><script>setInterval(() => fetch('/api/ping'), 300)</script>`)
	})
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"pong":true}`)
	})

	// Static files, with the SPA fallback: an extensionless path that is not a
	// file gets index.html, as a client-side router expects.
	// frontier-app: an HTTP redirect, and a page whose headers name URLs.
	mux.HandleFunc("/fr/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/pages/redirected.html", http.StatusFound)
	})
	mux.HandleFunc("/fr/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</pages/link-header.html>; rel=next")
		w.Header().Set("Content-Location", "/pages/content-location.html")
		w.Header().Set("Refresh", "1; url=/pages/refresh-header.html")
		fmt.Fprint(w, `<!doctype html><title>headers</title><p>headers</p>`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dist, path.Clean(r.URL.Path))
		// A static export (Next.js) maps /about to about.html or about/index.html.
		for _, c := range []string{p, p + ".html", filepath.Join(p, "index.html")} {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				serveFile(w, r, c)
				return
			}
		}
		if path.Ext(r.URL.Path) == "" {
			serveFile(w, r, filepath.Join(dist, "index.html"))
			return
		}
		http.NotFound(w, r)
	})

	log.Printf("serving %s on http://%s", *app, *addr)
	return http.ListenAndServe(*addr, logRequests(verifyAppFor(*app, refreshAppFor(*app, peerAppFor(*app, pipeAppFor(*app, fakeArchiveFor(*app, mux)))))))
}

// serveFile serves one file without http.ServeFile's index.html redirects.
func serveFile(w http.ResponseWriter, r *http.Request, p string) {
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, filepath.Base(p), st.ModTime(), f)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

// Hijack lets a WebSocket handler take the connection over.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported")
	}
	s.status = http.StatusSwitchingProtocols
	return h.Hijack()
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if fl, ok := s.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// cfBlockRule reads TESTBED_CF_BLOCK (round 25H), the Cloudflare page the
// server answers in the application's place:
//
//	1006          every request: the client's IP banned
//	1006-after:N  the first N requests answered, then every one 1006
//	1020:REGEXP   the requests whose path and query match: a rule (1020)
//	1015:N        the Nth request: 429, Retry-After: 1 (a rate rule)
func cfBlockRule(spec string) func(n int64, r *http.Request) (status int, code string) {
	kind, arg, _ := strings.Cut(spec, ":")
	switch kind {
	case "":
		return nil
	case "1006":
		return func(int64, *http.Request) (int, string) { return http.StatusForbidden, "1006" }
	case "1006-after":
		after, _ := strconv.ParseInt(arg, 10, 64)
		return func(n int64, _ *http.Request) (int, string) {
			if n > after {
				return http.StatusForbidden, "1006"
			}
			return 0, ""
		}
	case "1020":
		re := regexp.MustCompile(arg)
		return func(_ int64, r *http.Request) (int, string) {
			if re.MatchString(r.URL.RequestURI()) {
				return http.StatusForbidden, "1020"
			}
			return 0, ""
		}
	case "1015":
		at, _ := strconv.ParseInt(arg, 10, 64)
		return func(n int64, _ *http.Request) (int, string) {
			if n == at {
				return http.StatusTooManyRequests, "1015"
			}
			return 0, ""
		}
	}
	log.Fatalf("TESTBED_CF_BLOCK=%q: not 1006, 1006-after:N, 1020:REGEXP or 1015:N", spec)
	return nil
}

func logRequests(h http.Handler) http.Handler {
	rule := cfBlockRule(os.Getenv("TESTBED_CF_BLOCK"))
	var count atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		if rule != nil {
			if status, code := rule(count.Add(1), r); status != 0 {
				title := "Access denied | 127.0.0.1 used Cloudflare to restrict access"
				what := "The owner of this website (127.0.0.1) has banned your IP address."
				switch code {
				case "1020":
					what = "This website is using a security service to protect itself from online attacks."
				case "1015":
					title, what = "Rate limited | 127.0.0.1 | Cloudflare", "You are being rate limited."
					rec.Header().Set("Retry-After", "1")
				}
				rec.Header().Set("Server", "cloudflare")
				rec.Header().Set("CF-Ray", "99aabbccddeeff00-SIN")
				rec.Header().Set("Content-Type", "text/html; charset=UTF-8")
				rec.WriteHeader(status)
				io.WriteString(rec, `<!DOCTYPE html><html><head><title>`+title+`</title></head><body><div id="cf-error-details"><h1>Access denied</h1><p>Error `+code+`: `+what+`</p><a href="https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-`+code+`/">Cloudflare 1xxx</a></div></body></html>`)
				log.Printf("%d %s %s", rec.status, r.Method, r.URL.RequestURI())
				return
			}
		}
		h.ServeHTTP(rec, r)
		log.Printf("%d %s %s", rec.status, r.Method, r.URL.RequestURI())
	})
}

func token() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var markerRe = regexp.MustCompile(`JSHMARK:[a-z-]+:[a-z0-9-]+`)

func score(args []string) error {
	fset := flag.NewFlagSet("score", flag.ExitOnError)
	app := fset.String("app", "", "app directory (with truth.txt)")
	out := fset.String("out", "", "jsharvest output dir for one target and role")
	gate := fset.Bool("gate", false, "fail when a marker listed in the app's baseline.txt is missed, or when the output holds capture artefacts")
	writeBaseline := fset.Bool("write-baseline", false, "record the markers found now as the app's baseline.txt")
	fset.Parse(args)
	if *app == "" || *out == "" {
		return fmt.Errorf("-app and -out are required")
	}

	truth, err := readTruth(filepath.Join(*app, "truth.txt"))
	if err != nil {
		return err
	}

	found := map[string]bool{}
	var artefacts []string
	err = filepath.WalkDir(*out, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".jsonl") || strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		// chromedp evaluates "self" on every target it attaches to; the
		// capture must never store it as page code.
		if strings.TrimSpace(string(b)) == "self" {
			artefacts = append(artefacts, p)
		}
		for _, m := range markerRe.FindAll(b, -1) {
			found[string(m)] = true
		}
		return nil
	})
	if err != nil {
		return err
	}

	type tally struct{ hit, total int }
	byCat := map[string]*tally{}
	var cats []string
	hits := 0
	for _, m := range truth {
		cat := strings.Split(m, ":")[1]
		t := byCat[cat]
		if t == nil {
			t = &tally{}
			byCat[cat] = t
			cats = append(cats, cat)
		}
		t.total++
		mark := "MISS"
		if found[m] {
			t.hit++
			hits++
			mark = "ok"
		}
		fmt.Printf("  %-4s  %s\n", mark, m)
	}

	fmt.Println()
	sort.Strings(cats)
	for _, c := range cats {
		t := byCat[c]
		fmt.Printf("  %-12s %d/%d\n", c, t.hit, t.total)
	}
	fmt.Printf("\n  recall: %d/%d (%.0f%%)\n", hits, len(truth), 100*float64(hits)/float64(len(truth)))

	for m := range found {
		if !slices.Contains(truth, m) {
			fmt.Printf("  unexpected marker in output: %s\n", m)
		}
	}

	baselinePath := filepath.Join(*app, "baseline.txt")
	if *writeBaseline {
		var lines []string
		for _, m := range truth {
			if found[m] {
				lines = append(lines, m)
			}
		}
		content := "# Markers the capture must keep finding; written by testbed score -write-baseline.\n" + strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(baselinePath, []byte(content), 0o644); err != nil {
			return err
		}
		fmt.Printf("  baseline written: %d markers\n", len(lines))
	}
	if !*gate {
		return nil
	}
	baseline, err := readTruth(baselinePath)
	if err != nil {
		return fmt.Errorf("gate: %w", err)
	}
	var lost []string
	for _, m := range baseline {
		if !found[m] {
			lost = append(lost, m)
		}
	}
	if len(lost) > 0 || len(artefacts) > 0 {
		return fmt.Errorf("gate failed: lost %v; artefacts %v", lost, artefacts)
	}
	fmt.Printf("  gate: ok (%d baseline markers)\n", len(baseline))
	return nil
}

func readTruth(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if m := markerRe.FindString(line); m != "" && !strings.HasPrefix(line, "#") {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}
