package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/detect"
	"github.com/TimoMangCut/JSharvest/internal/frontier"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
	"github.com/TimoMangCut/JSharvest/internal/resolve"
	"github.com/TimoMangCut/JSharvest/internal/store"
	"github.com/TimoMangCut/JSharvest/internal/uahints"
)

const specDirectTimeout = 10 * time.Second

func (c *crawl) getSpecPolicy(cfg Config) *resolve.Policy {
	c.specMu.Lock()
	defer c.specMu.Unlock()
	if c.specPol == nil {
		noDNS := cfg.Browser.Proxy != "" || cfg.Browser.HostRules != ""
		targetHost := ""
		if cfg.Target != nil {
			targetHost = cfg.Target.Hostname()
		}
		c.specPol = resolve.NewPolicy(targetHost, func(h string) bool { return !frontier.IsTrackerHost(h) }, noDNS)
	}
	return c.specPol
}

func (c *crawl) getSpecClient(e *engine) *http.Client {
	c.specMu.Lock()
	defer c.specMu.Unlock()
	if c.specHTTP != nil {
		return c.specHTTP
	}
	var proxyURL *url.URL
	if e.cfg.Browser.Proxy != "" {
		proxyURL, _ = url.Parse(e.cfg.Browser.Proxy)
	}
	dialer := &netsafe.Dialer{
		HostRules:    e.privRules,
		AllowPrivate: e.privOff,
		Proxy:        proxyURL,
		Timeout:      specDirectTimeout,
	}
	tr := &http.Transport{
		Proxy:              netsafe.ProxyFunc(proxyURL, e.privRules),
		DialContext:        dialer.DialContext,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: e.cfg.Browser.Insecure},
		DisableCompression: false,
		ForceAttemptHTTP2:  true,
	}
	if proxyURL == nil {
		tr.Proxy = nil
	}
	c.specTr = tr
	c.specHTTP = &http.Client{
		Transport: netsafe.Guard{
			Next:         tr,
			AllowPrivate: e.privOff,
			Rules:        e.privRules,
		},
		Timeout: specDirectTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c.specHTTP
}

func (c *crawl) closeSpecClient() {
	c.specMu.Lock()
	tr := c.specTr
	c.specTr = nil
	c.specHTTP = nil
	c.specMu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

// specProbeFetch fetches a candidate OpenAPI/Swagger/OIDC document.
// Same-origin URLs run through the tab's Isolated World so same-origin session
// cookies apply without CORS preflight; all cross-origin URLs (including in
// -attach mode) run strictly through a netsafe-guarded Go HTTP client so they
// never bypass private-IP/DNS-rebinding protections via the browser's network stack.
func (e *engine) specProbeFetch(ctx context.Context, c *crawl, targetURL string, hdrMap map[string]string) (fetchResult, error) {
	curPage := ""
	if e.harvest != nil {
		curPage = e.harvest.Page()
	}
	if curPage != "" && sameOrigin(targetURL, curPage) {
		if len(hdrMap) > 0 {
			return e.pageFetchHeaders(targetURL, hdrMap)
		}
		return e.pageFetch(targetURL, true)
	}
	return c.directSpecFetch(ctx, e, targetURL, hdrMap)
}

func (c *crawl) directSpecFetch(ctx context.Context, e *engine, targetURL string, hdrMap map[string]string) (fetchResult, error) {
	client := c.getSpecClient(e)
	reqCtx, cancel := context.WithTimeout(ctx, specDirectTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fetchResult{Status: -1}, err
	}
	ua := httpUA(e.cfg)
	if ua == "" {
		ua = marker.FallbackUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*;q=0.8")
	if strings.EqualFold(req.URL.Scheme, "https") {
		for k, v := range uahints.Hints(ua) {
			req.Header.Set(k, v)
		}
	}
	for k, v := range hdrMap {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{Status: -1}, err
	}
	defer resp.Body.Close()

	out := fetchResult{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Challenge:   strings.EqualFold(resp.Header.Get("Cf-Mitigated"), "challenge"),
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound {
		limit := int64(8192)
		if resp.StatusCode == http.StatusOK {
			limit = maxFetchText
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
		out.Text = string(b)
		if !out.Challenge && len(b) > 0 {
			lower := make(map[string]string, len(resp.Header))
			for k, vs := range resp.Header {
				if len(vs) > 0 {
					lower[strings.ToLower(k)] = vs[0]
				}
			}
			if detect.Check(detect.Doc{Status: int64(resp.StatusCode), Headers: lower, Body: out.Text}).Blocked {
				out.Challenge = true
			}
		}
	}
	return out, nil
}

// specFiles asks an origin or gateway base for its API's description
// (frontier.SpecPaths): an OpenAPI document or an OpenID Provider's
// configuration is stored with the tag openapi, for the catalog (PIP-03).
func (e *engine) specFiles(ctx context.Context, c *crawl, root, page string) {
	e.specFilesWithHeaders(ctx, c, root, page, nil, nil, nil)
}

func (e *engine) specFilesWithHeaders(ctx context.Context, c *crawl, base, page string, hdrs []jsapi.Header, seen map[string]bool, budget *int) {
	base = strings.TrimRight(base, "/")
	pol := c.getSpecPolicy(e.cfg)
	if _, err := url.Parse(base); err != nil || pol.Check(base+"/") != resolve.Allow {
		return
	}
	var hdrMap map[string]string
	if len(hdrs) > 0 {
		hdrMap = make(map[string]string, len(hdrs))
		for _, h := range hdrs {
			hdrMap[h.Name] = h.Value
		}
	}
	fetchOne := func(targetURL, pathHint string) (fetchResult, bool) {
		if ctx.Err() != nil {
			return fetchResult{}, false
		}
		if budget != nil && *budget <= 0 {
			return fetchResult{}, false
		}
		if seen != nil {
			if seen[targetURL] {
				return fetchResult{}, false
			}
			seen[targetURL] = true
		}
		if budget != nil {
			*budget--
		}
		r, err := e.specProbeFetch(ctx, c, targetURL, hdrMap)
		if err != nil || r.Status != 200 || r.Text == "" || r.Challenge {
			return r, false
		}
		body := []byte(r.Text)
		tags := []string{"openapi"}
		switch {
		case jsapi.IsOpenAPI(body):
		case pathHint == "/.well-known/openid-configuration" && jsapi.IsOIDC(body):
			tags = append(tags, "oidc")
		default:
			return r, false
		}
		key, isNew, err := e.st.Put(store.Record{Body: body, URL: targetURL, Kind: "file", Via: "probe", Target: "page", Page: page,
			Tags: tags, Source: "live"})
		if err != nil {
			return r, false
		}
		e.noteScript(key, isNew)
		slog.Info("an API description", "url", targetURL, "tags", strings.Join(tags, ","))
		return r, true
	}

	for _, p := range frontier.SpecPaths {
		if ctx.Err() != nil || (budget != nil && *budget <= 0) {
			return
		}
		targetURL := frontier.JoinSpecBase(base, p)
		r, stored := fetchOne(targetURL, p)
		if !stored && p == "/swagger-resources" && r.Status == 200 && r.Text != "" && !r.Challenge {
			for _, rel := range jsapi.SwaggerResources([]byte(r.Text)) {
				if ctx.Err() != nil || (budget != nil && *budget <= 0) {
					break
				}
				fetchOne(frontier.JoinSpecBase(base, rel), rel)
			}
		}
	}
}

func (e *engine) specFilesPhase2(ctx context.Context, c *crawl, page string) {
	pol := c.getSpecPolicy(e.cfg)
	plan := c.specCtx.Plan(c.seedOrigin, e.cfg.InScope)
	var budgetPtr *int
	if frontier.MaxPhase2SpecProbes > 0 {
		b := frontier.MaxPhase2SpecProbes
		budgetPtr = &b
	}
	seen := map[string]bool{}

	for _, base := range plan.Bases {
		if ctx.Err() != nil || (budgetPtr != nil && *budgetPtr <= 0) {
			return
		}
		hdrs := c.specCtx.HeadersFor(base, e.cfg.InScope)
		e.specFilesWithHeaders(ctx, c, base, page, hdrs, seen, budgetPtr)
	}

	type gateState struct {
		lastSig    string
		consec     int
		hadOpenAPI bool
		braked     bool
	}
	gates := map[string]*gateState{}
	for _, svc := range plan.Services {
		if ctx.Err() != nil || (budgetPtr != nil && *budgetPtr <= 0) {
			return
		}
		if pol.Check(svc.PrefixURL+"/") != resolve.Allow {
			continue
		}
		gs := gates[svc.GatewayBase]
		if gs == nil {
			gs = &gateState{}
			gates[svc.GatewayBase] = gs
		}
		if gs.braked {
			continue
		}
		hdrs := c.specCtx.HeadersFor(svc.PrefixURL, e.cfg.InScope)
		var hdrMap map[string]string
		if len(hdrs) > 0 {
			hdrMap = make(map[string]string, len(hdrs))
			for _, h := range hdrs {
				hdrMap[h.Name] = h.Value
			}
		}
		for _, p := range frontier.ServiceDocPaths {
			if ctx.Err() != nil || (budgetPtr != nil && *budgetPtr <= 0) || gs.braked {
				break
			}
			targetURL := frontier.JoinSpecBase(svc.PrefixURL, p)
			if seen[targetURL] {
				continue
			}
			seen[targetURL] = true
			if budgetPtr != nil {
				*budgetPtr--
			}
			r, err := e.specProbeFetch(ctx, c, targetURL, hdrMap)
			if err == nil && r.Status == 200 && r.Text != "" && !r.Challenge && jsapi.IsOpenAPI([]byte(r.Text)) {
				key, isNew, perr := e.st.Put(store.Record{Body: []byte(r.Text), URL: targetURL, Kind: "file", Via: "probe",
					Target: "page", Page: page, Tags: []string{"openapi"}, Source: "live"})
				if perr == nil {
					e.noteScript(key, isNew)
					slog.Info("an API description", "url", targetURL, "tags", "openapi")
				}
				gs.hadOpenAPI = true
				gs.lastSig = ""
				gs.consec = 0
				continue
			}
			sig, isGate := engineGateSig(r)
			if !isGate {
				gs.lastSig = ""
				gs.consec = 0
				continue
			}
			if sig == gs.lastSig {
				gs.consec++
			} else {
				gs.lastSig = sig
				gs.consec = 1
			}
			if gs.consec >= 2 && (!gs.hadOpenAPI || r.Status != 404) {
				gs.braked = true
				break
			}
		}
	}
}

func engineGateSig(r fetchResult) (string, bool) {
	if r.Challenge {
		return "", false
	}
	if r.Status <= 0 {
		return "neterr", true
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.ContentType, ";")[0]))
	trimmed := strings.TrimSpace(r.Text)
	lowHead := strings.ToLower(trimmed[:min(len(trimmed), 256)])
	if strings.Contains(ct, "html") || strings.HasPrefix(lowHead, "<!doctype html") || strings.HasPrefix(lowHead, "<html") {
		if r.Status == 200 || r.Status == 400 || r.Status == 401 || r.Status == 403 || r.Status == 404 {
			return fmt.Sprintf("html:%d:%d", r.Status, len(trimmed)/128), true
		}
		return "", false
	}
	if r.Status != 400 && r.Status != 401 && r.Status != 403 && r.Status != 404 {
		return "", false
	}
	return fmt.Sprintf("wall:%d:%s:%d", r.Status, ct, len(trimmed)/64), true
}
