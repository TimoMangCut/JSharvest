package jsapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// openAPIYAML and openAPIJSON are the start of an OpenAPI 3.x or Swagger
// 2.0 document: its first key, after comments and a "---"; or within a
// JSON object's first bytes.
var (
	openAPIYAML = regexp.MustCompile(`^(?:\s*(?:#[^\n]*)?\n)*(?:---\s*\n)?(?:openapi|swagger)\s*:\s*["']?[23]\.`)
	openAPIJSON = regexp.MustCompile(`^\s*\{[\s\S]{0,1000}?"(?:openapi|swagger)"\s*:\s*"[23]\.`)
)

// IsOpenAPI reports whether a document is an OpenAPI (or Swagger)
// description: it starts with "openapi: 3…" or "swagger: 2.0" (YAML) or
// is a JSON object with that key among its first, and has paths. A
// script that names the key (swagger-ui's bundle) does not start so.
func IsOpenAPI(b []byte) bool {
	head := b[:min(len(b), 4096)]
	return (openAPIYAML.Match(head) || openAPIJSON.Match(head)) && bytes.Contains(b, []byte("paths"))
}

// MaxSwaggerResources bounds the Springfox resource documents a crawl
// follows from a /swagger-resources index.
const MaxSwaggerResources = 5

// SwaggerResources parses a Springfox /swagger-resources JSON array
// ([{"name":"auth","url":"/v2/api-docs?group=auth","location":"/auth/v2/api-docs"}])
// and returns up to MaxSwaggerResources unique relative document paths,
// preferring "url" and falling back to "location".
func SwaggerResources(body []byte) []string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' || len(trimmed) > 1<<20 {
		return nil
	}
	var items []struct {
		URL      string `json:"url"`
		Location string `json:"location"`
	}
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil
	}
	var out []string
	for _, it := range items {
		raw := strings.TrimSpace(it.URL)
		if raw == "" {
			raw = strings.TrimSpace(it.Location)
		}
		clean := cleanSwaggerResource(raw)
		if clean == "" || slices.Contains(out, clean) {
			continue
		}
		out = append(out, clean)
		if len(out) >= MaxSwaggerResources {
			break
		}
	}
	return out
}

// SwaggerConfigURLs parses a Springdoc / Swagger-UI swagger-config JSON object
// ({"url":"/v3/api-docs","urls":[{"url":"/docs/api-docs.json"}]}) fetched via
// a SwaggerUI configUrl reference.
func SwaggerConfigURLs(body []byte) []string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || len(trimmed) > 1<<20 {
		return nil
	}
	var cfg struct {
		URL  string `json:"url"`
		URLs []struct {
			URL string `json:"url"`
		} `json:"urls"`
	}
	if json.Unmarshal(trimmed, &cfg) != nil {
		return nil
	}
	var out []string
	push := func(raw string) {
		if len(out) >= MaxSwaggerResources {
			return
		}
		clean := cleanSwaggerResource(strings.TrimSpace(raw))
		if clean != "" && !slices.Contains(out, clean) {
			out = append(out, clean)
		}
	}
	push(cfg.URL)
	for _, u := range cfg.URLs {
		push(u.URL)
	}
	return out
}

var (
	swaggerUIInitRe = regexp.MustCompile(`(?i)(?:SwaggerUIBundle|SwaggerUIStandalonePreset|swagger-ui|Redoc\.init|<redoc\b|api-reference)`)
	swaggerUIURLRe  = regexp.MustCompile(`(?i)(?:\b(?:configUrl|spec-url|data-url|url)\s*[:=]\s*["']([^"'<>\s]+)["'])`)
	nonSpecAssetRe  = regexp.MustCompile(`(?i)\.(?:css|m?js|png|jpe?g|svg|ico|woff2?|ttf|html?)$`)
)

// SwaggerUIURLs extracts up to MaxSwaggerResources OpenAPI document or
// swagger-config references from a Swagger UI / Redoc / Scalar HTML wrapper.
func SwaggerUIURLs(htmlBody []byte) []string {
	if len(htmlBody) == 0 || len(htmlBody) > 1<<20 || !swaggerUIInitRe.Match(htmlBody) {
		return nil
	}
	var out []string
	for _, m := range swaggerUIURLRe.FindAllSubmatch(htmlBody, 24) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" || strings.Contains(strings.ToLower(raw), "petstore.swagger.io") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.User != nil {
			continue
		}
		if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
			continue
		}
		if nonSpecAssetRe.MatchString(u.Path) {
			continue
		}
		if !slices.Contains(out, raw) {
			out = append(out, raw)
			if len(out) >= MaxSwaggerResources {
				break
			}
		}
	}
	return out
}

func cleanSwaggerResource(raw string) string {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "://") ||
		strings.ContainsAny(raw, " \t\r\n\\") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return ""
	}
	if slices.Contains(strings.Split(u.Path, "/"), "..") {
		return ""
	}
	clean := u.EscapedPath()
	if clean == "" {
		clean = u.Path
	}
	if u.RawQuery != "" {
		clean += "?" + u.RawQuery
	}
	return clean
}

// ExtractOpenAPI reads an OpenAPI or Swagger document as Extract reads a
// script: each operation an endpoint (its path relative to the servers,
// which are the bases), with its query, header and body parameters.
func ExtractOpenAPI(src []byte) (res Result) {
	res.Version = Version
	res.Endpoints = []Endpoint{}
	var doc map[string]any
	if err := yaml.Unmarshal(src, &doc); err != nil {
		res.Error = "openapi: " + firstLine(err.Error())
		return res
	}
	bases := map[string]bool{}
	for _, s := range list(doc["servers"]) {
		if u, _ := dict(s)["url"].(string); u != "" && !strings.Contains(u, "{") {
			bases[strings.TrimRight(u, "/")] = true
		}
	}
	if host, _ := doc["host"].(string); host != "" {
		bp, _ := doc["basePath"].(string)
		schemes := list(doc["schemes"])
		if len(schemes) == 0 {
			schemes = []any{"https"}
		}
		for _, s := range schemes {
			if s, ok := s.(string); ok {
				bases[strings.TrimRight(s+"://"+host+bp, "/")] = true
			}
		}
	} else if bp, _ := doc["basePath"].(string); bp != "" {
		bases[strings.TrimRight(bp, "/")] = true
	}
	delete(bases, "")
	res.Bases = sortedKeys(bases)

	r := refs{doc: doc}
	schemes := map[string]any{}
	for k, v := range dict(doc["securityDefinitions"]) {
		schemes[k] = v
	}
	for k, v := range dict(dict(doc["components"])["securitySchemes"]) {
		schemes[k] = v
	}
	docSecurity := list(doc["security"])
	paths := dict(doc["paths"])
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		item := r.resolve(paths[p])
		common := list(item["parameters"])
		for _, m := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
			op := dict(item[m])
			if op == nil {
				continue
			}
			ep := Endpoint{Method: strings.ToUpper(m), URL: cleanURL(p), Kind: "openapi", Client: true}
			for _, prm := range append(append([]any{}, common...), list(op["parameters"])...) {
				prm := r.resolve(prm)
				name, _ := prm["name"].(string)
				if in, _ := prm["in"].(string); name != "" && in != "body" && in != "" {
					sch := r.resolve(prm["schema"])
					if sch == nil {
						sch = prm // Swagger 2: the type is on the parameter
					}
					if in == "formData" {
						in = "body"
					}
					req, _ := prm["required"].(bool)
					ps := specOf(name, in, sch, req)
					if in == "path" {
						ps.Position = slotOf(p, name)
					}
					ep.Params = mergeSpecs(ep.Params, []ParamSpec{ps})
				}
				switch prm["in"] {
				case "query":
					ep.Query = append(ep.Query, name)
				case "header":
					ep.Headers = append(ep.Headers, name)
				case "body", "formData":
					if prm["in"] == "formData" {
						ep.Body = append(ep.Body, name)
					} else {
						ep.Body = append(ep.Body, r.fields(r.resolve(prm["schema"]), "", 0)...)
						ep.Params = mergeSpecs(ep.Params, r.specs(r.resolve(prm["schema"]), "", 0))
					}
				}
			}
			if rb := r.resolve(op["requestBody"]); rb != nil {
				for _, media := range dict(rb["content"]) {
					ep.Body = append(ep.Body, r.fields(r.resolve(dict(media)["schema"]), "", 0)...)
					ep.Params = mergeSpecs(ep.Params, r.specs(r.resolve(dict(media)["schema"]), "", 0))
				}
			}
			sec := docSecurity
			if opSec, has := op["security"]; has {
				sec = list(opSec)
			}
			for _, reqItem := range sec {
				rm := dict(reqItem)
				snames := make([]string, 0, len(rm))
				for sn := range rm {
					snames = append(snames, sn)
				}
				sort.Strings(snames)
				for _, sn := range snames {
					sch := r.resolve(schemes[sn])
					if sch == nil {
						continue
					}
					typ, _ := sch["type"].(string)
					switch strings.ToLower(strings.TrimSpace(typ)) {
					case "http":
						rawScheme, _ := sch["scheme"].(string)
						scheme := strings.ToLower(strings.TrimSpace(rawScheme))
						if scheme == "bearer" || scheme == "" {
							ep.Auth = append(ep.Auth, "bearer")
						} else {
							ep.Auth = append(ep.Auth, scheme)
						}
						ep.Headers = append(ep.Headers, "Authorization")
					case "basic":
						ep.Auth = append(ep.Auth, "basic")
						ep.Headers = append(ep.Headers, "Authorization")
					case "oauth2", "openidconnect":
						ep.Auth = append(ep.Auth, "bearer")
						ep.Headers = append(ep.Headers, "Authorization")
					case "apikey":
						kname, _ := sch["name"].(string)
						in, _ := sch["in"].(string)
						if kname != "" {
							ep.Auth = append(ep.Auth, "apiKey:"+kname)
							switch in {
							case "header":
								ep.Headers = append(ep.Headers, kname)
							case "query":
								ep.Query = append(ep.Query, kname)
							}
							if in == "header" || in == "query" || in == "cookie" {
								ep.Params = mergeSpecs(ep.Params, []ParamSpec{{Name: kname, In: in, Type: "string", Required: true}})
							}
						}
					}
				}
			}
			ep.Query, ep.Body, ep.Headers, ep.Auth = uniq(ep.Query), uniq(ep.Body), uniq(ep.Headers), uniq(ep.Auth)
			if id, _ := op["operationId"].(string); id != "" {
				ep.Snippet = m + " " + p + " (" + id + ")"
			} else {
				ep.Snippet = m + " " + p
			}
			res.Endpoints = append(res.Endpoints, ep)
		}
	}
	return res
}

func dict(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

// refs resolves the document's own $refs (#/components/schemas/X).
type refs struct{ doc map[string]any }

func (r refs) resolve(v any) map[string]any {
	m := dict(v)
	for i := 0; i < 8 && m != nil; i++ {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		if !strings.HasPrefix(ref, "#/") {
			return nil // another file's
		}
		var cur any = r.doc
		for _, part := range strings.Split(ref[2:], "/") {
			part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
			cur = dict(cur)[part]
		}
		m = dict(cur)
	}
	return m
}

// fields are a schema's property names, nested ones as a.b (three levels
// at most), through allOf, oneOf and anyOf.
func (r refs) fields(s map[string]any, prefix string, depth int) []string {
	if s == nil || depth > 3 {
		return nil
	}
	var out []string
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		for _, sub := range list(s[k]) {
			out = append(out, r.fields(r.resolve(sub), prefix, depth+1)...)
		}
	}
	for name, p := range dict(s["properties"]) {
		ps := r.resolve(p)
		if sub := r.fields(ps, prefix+name+".", depth+1); len(sub) > 0 && ps["type"] != "array" {
			out = append(out, sub...)
			continue
		}
		out = append(out, prefix+name)
	}
	return out
}

// specOf is a parameter's spec out of its schema: its type (integer is a
// number), its enum, default and example values.
func specOf(name, in string, s map[string]any, required bool) ParamSpec {
	ps := ParamSpec{Name: name, In: in, Required: required}
	switch t, _ := s["type"].(string); t {
	case "integer", "number":
		ps.Type = "number"
	case "string", "boolean", "array", "object":
		ps.Type = t
	}
	var vals []string
	for _, v := range list(s["enum"]) {
		vals = append(vals, scalar(v))
	}
	for _, k := range []string{"default", "example"} {
		if v, ok := s[k]; ok {
			vals = append(vals, scalar(v))
		}
	}
	ps.Values = uniqLimit(slices.DeleteFunc(vals, func(v string) bool { return v == "" }))
	return ps
}

// scalar is a JSON or YAML scalar as text; nothing for a list or a map.
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool, int, int64, float64, uint64:
		return fmt.Sprint(t)
	}
	return ""
}

// slotOf is the place of a path parameter's {name} among the path's.
func slotOf(path, name string) int {
	i := 0
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			if strings.Trim(seg, "{}") == name {
				return i
			}
			i++
		}
	}
	return 0
}

// specs are a schema's properties as body parameters, nested ones as
// a.b, with the schema's required list.
func (r refs) specs(s map[string]any, prefix string, depth int) []ParamSpec {
	if s == nil || depth > 3 {
		return nil
	}
	var out []ParamSpec
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		for _, sub := range list(s[k]) {
			out = append(out, r.specs(r.resolve(sub), prefix, depth+1)...)
		}
	}
	req := map[string]bool{}
	for _, n := range list(s["required"]) {
		if n, ok := n.(string); ok {
			req[n] = true
		}
	}
	for name, p := range dict(s["properties"]) {
		ps := r.resolve(p)
		if sub := r.specs(ps, prefix+name+".", depth+1); len(sub) > 0 && ps["type"] != "array" {
			out = append(out, sub...)
			continue
		}
		out = append(out, specOf(prefix+name, "body", ps, req[name]))
	}
	slices.SortFunc(out, func(a, b ParamSpec) int { return strings.Compare(a.Name, b.Name) })
	return out
}
