package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/roles"
)

// --- get_intel ---

type getIntelIn struct {
	Section string `json:"section,omitempty" jsonschema:"only this section: bases, client_headers, cloud, keys, routes, client_authz, server_hints, security_notes, or auth_flows; default all"`
	Limit   int    `json:"limit,omitempty" jsonschema:"at most this many items per list (default 200, at most 1000)"`
}

type getIntelOut struct {
	Dir           string                   `json:"dir"`
	Bases         []string                 `json:"bases,omitempty"`
	Headers       []endpoints.IntelHeader  `json:"client_headers,omitempty"`
	Cloud         []endpoints.IntelURL     `json:"cloud,omitempty"`
	Keys          []endpoints.IntelHeader  `json:"keys,omitempty"`
	Routes        []endpoints.IntelRoute   `json:"routes,omitempty"`
	ClientAuthz   *endpoints.ClientAuthz   `json:"client_authz,omitempty"`
	ServerHints   []endpoints.ServerHint   `json:"server_hints,omitempty"`
	SecurityNotes []endpoints.SecurityNote `json:"security_notes,omitempty"`
	AuthFlows     []endpoints.AuthFlow     `json:"auth_flows,omitempty"`
	Truncated     bool                     `json:"truncated,omitempty"`
}

func (s *server) getIntel(ctx context.Context, _ *mcp.CallToolRequest, in getIntelIn) (*mcp.CallToolResult, any, error) {
	switch in.Section {
	case "", "bases", "client_headers", "cloud", "keys", "routes", "client_authz", "server_hints", "security_notes", "auth_flows":
	default:
		return nil, nil, fmt.Errorf("unknown section %q: want bases, client_headers, cloud, keys, routes, client_authz, server_hints, security_notes, or auth_flows", in.Section)
	}
	d, err := s.dir()
	if err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(filepath.Join(d.Path, endpoints.IntelFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			host, role := results.HostRole(d.Path)
			return nil, nil, fmt.Errorf("no %s in %s: run `jsharvest endpoints -target %s -role %s` (or a crawl) first", endpoints.IntelFile, d.Path, host, role)
		}
		return nil, nil, err
	}
	var intel endpoints.Intel
	if err := json.Unmarshal(b, &intel); err != nil {
		return nil, nil, err
	}
	limit := clamp(in.Limit, 200, 1000)
	out := getIntelOut{Dir: d.Path}
	want := func(sec string) bool { return in.Section == "" || in.Section == sec }

	if want("bases") {
		bs := take(intel.Bases, limit, &out.Truncated)
		out.Bases = make([]string, len(bs))
		for i, u := range bs {
			out.Bases[i] = s.url(u)
		}
	}
	if want("client_headers") {
		out.Headers = s.redactIntelHeaders(take(intel.Headers, limit, &out.Truncated))
	}
	if want("cloud") {
		cs := take(intel.Cloud, limit, &out.Truncated)
		out.Cloud = make([]endpoints.IntelURL, len(cs))
		for i, c := range cs {
			c.URL = s.url(c.URL)
			c.BucketRootURL = s.url(c.BucketRootURL)
			c.Sources = s.redactSources(c.Sources)
			out.Cloud[i] = c
		}
	}
	if want("keys") {
		out.Keys = s.redactIntelHeaders(take(intel.Keys, limit, &out.Truncated))
	}
	if want("routes") {
		rs := take(intel.Routes, limit, &out.Truncated)
		if len(rs) > 0 {
			out.Routes = make([]endpoints.IntelRoute, len(rs))
			for i, r := range rs {
				r.Path = s.text(r.Path)
				r.Redirect = s.text(r.Redirect)
				r.Sources = s.redactSources(r.Sources)
				out.Routes[i] = r
			}
		}
	}
	if want("client_authz") && intel.ClientAuthz != nil {
		ca := *intel.ClientAuthz
		ca.Roles = s.redactStrings(take(ca.Roles, limit, &out.Truncated))
		ca.Permissions = s.redactStrings(take(ca.Permissions, limit, &out.Truncated))
		ca.Rules = take(ca.Rules, limit, &out.Truncated)
		ca.PublicRoutes = s.redactStrings(take(ca.PublicRoutes, limit, &out.Truncated))
		grs := take(ca.GuardedRoutes, limit, &out.Truncated)
		if s.red != nil && len(grs) > 0 {
			cp := make([]endpoints.GuardedRoute, len(grs))
			for i, g := range grs {
				g.Path = s.text(g.Path)
				g.Roles = s.redactStrings(g.Roles)
				g.Permissions = s.redactStrings(g.Permissions)
				cp[i] = g
			}
			grs = cp
		}
		ca.GuardedRoutes = grs
		out.ClientAuthz = &ca
	}
	if want("server_hints") {
		hs := take(intel.ServerHints, limit, &out.Truncated)
		out.ServerHints = make([]endpoints.ServerHint, len(hs))
		for i, h := range hs {
			h.Evidence = s.text(h.Evidence)
			out.ServerHints[i] = h
		}
	}
	if want("security_notes") {
		ns := take(intel.SecurityNotes, limit, &out.Truncated)
		out.SecurityNotes = make([]endpoints.SecurityNote, len(ns))
		for i, n := range ns {
			n.Example = s.url(n.Example)
			out.SecurityNotes[i] = n
		}
	}
	if want("auth_flows") {
		fs := take(intel.AuthFlows, limit, &out.Truncated)
		if len(fs) > 0 {
			out.AuthFlows = make([]endpoints.AuthFlow, len(fs))
			for i, f := range fs {
				f.AuthorizationEndpoint = s.url(f.AuthorizationEndpoint)
				f.RedirectURI = s.url(f.RedirectURI)
				f.SourceURL = s.url(f.SourceURL)
				out.AuthFlows[i] = f
			}
		}
	}
	return s.reply(out)
}

func take[T any](items []T, limit int, truncated *bool) []T {
	if len(items) > limit {
		*truncated = true
		return items[:limit]
	}
	return items
}

func (s *server) headerValue(name, value string) string {
	if s.red == nil || value == "" || value == "{}" || strings.HasSuffix(value, " {}") {
		return value
	}
	return s.red.Headers(map[string]string{name: value})[name]
}

func (s *server) redactSources(srcs []endpoints.Source) []endpoints.Source {
	if s.red == nil || len(srcs) == 0 {
		return srcs
	}
	out := make([]endpoints.Source, len(srcs))
	for i, src := range srcs {
		src.Script = s.url(src.Script)
		src.Snippet = s.text(src.Snippet)
		out[i] = src
	}
	return out
}

func (s *server) redactIntelHeaders(hs []endpoints.IntelHeader) []endpoints.IntelHeader {
	if len(hs) == 0 {
		return nil
	}
	out := make([]endpoints.IntelHeader, len(hs))
	for i, h := range hs {
		h.Value = s.headerValue(h.Name, h.Value)
		h.Sources = s.redactSources(h.Sources)
		out[i] = h
	}
	return out
}

// --- get_diff ---

type getDiffIn struct {
	Layer       string `json:"layer,omitempty" jsonschema:"only this layer: endpoint, feature, page, or script"`
	Class       string `json:"class,omitempty" jsonschema:"only this class (e.g. client_gated, denied_below, higher_only, server_gated, lower_ok, inconsistent, same)"`
	Role        string `json:"role,omitempty" jsonschema:"only items whose states include this role"`
	KeyContains string `json:"key_contains,omitempty" jsonschema:"only items whose key contains this text"`
	Limit       int    `json:"limit,omitempty" jsonschema:"at most this many items (default 100, at most 1000)"`
	Offset      int    `json:"offset,omitempty" jsonschema:"skip this many of the matching items"`
}

type getDiffOut struct {
	Dir       string                    `json:"dir"`
	Host      string                    `json:"host"`
	Roles     []string                  `json:"roles"`
	Generated time.Time                 `json:"generated"`
	Summary   map[string]map[string]int `json:"summary"`
	Warnings  []string                  `json:"warnings,omitempty"`
	Total     int                       `json:"total"`
	Offset    int                       `json:"offset,omitempty"`
	Items     []roles.Item              `json:"items"`
}

func (s *server) getDiff(ctx context.Context, _ *mcp.CallToolRequest, in getDiffIn) (*mcp.CallToolResult, any, error) {
	d, err := s.dir()
	if err != nil {
		return nil, nil, err
	}
	hostDir := filepath.Dir(d.Path)
	b, err := os.ReadFile(filepath.Join(hostDir, "diff.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			host, _ := results.HostRole(d.Path)
			return nil, nil, fmt.Errorf("no diff.json in %s: run `jsharvest diff -target %s` first", hostDir, host)
		}
		return nil, nil, err
	}
	var rep roles.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, nil, err
	}
	limit := clamp(in.Limit, 100, 1000)
	out := getDiffOut{
		Dir:       hostDir,
		Host:      rep.Host,
		Roles:     rep.Roles,
		Generated: rep.Generated,
		Summary:   rep.Summary,
		Warnings:  rep.Warnings,
		Offset:    in.Offset,
		Items:     []roles.Item{},
	}
	for _, it := range rep.Items {
		if in.Layer != "" && it.Layer != in.Layer {
			continue
		}
		if in.Class != "" && it.Class != in.Class {
			continue
		}
		if in.Role != "" {
			if _, ok := it.States[in.Role]; !ok {
				continue
			}
		}
		if in.KeyContains != "" && !strings.Contains(it.Key, in.KeyContains) {
			continue
		}
		out.Total++
		if out.Total <= in.Offset || len(out.Items) >= limit {
			continue
		}
		out.Items = append(out.Items, s.redactDiffItem(it))
	}
	return s.reply(out)
}

func (s *server) redactDiffItem(it roles.Item) roles.Item {
	if s.red == nil || len(it.Evidence) == 0 {
		return it
	}
	evMap := make(map[string]*roles.Evidence, len(it.Evidence))
	for role, ev := range it.Evidence {
		if ev == nil {
			evMap[role] = nil
			continue
		}
		cp := *ev
		cp.FinalURL = s.text(cp.FinalURL)
		cp.Label = s.text(cp.Label)
		cp.Samples = s.redactStrings(cp.Samples)
		cp.Pages = s.redactStrings(cp.Pages)
		evMap[role] = &cp
	}
	it.Evidence = evMap
	return it
}

func (s *server) redactStrings(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = s.text(x)
	}
	return out
}
