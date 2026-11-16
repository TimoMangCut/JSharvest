package export

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/flow"
	"github.com/TimoMangCut/JSharvest/internal/guard"
	"github.com/TimoMangCut/JSharvest/internal/roles"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
)

// openapiFile is the document's name in the export's directory.
const openapiFile = "openapi.json"

// OpenAPI limits: what an example or a schema may grow to.
const (
	maxSchemaDepth  = 6
	maxSchemaProps  = 100
	maxSchemaItems  = 20
	maxExampleBytes = 8 << 10
	maxExamples     = 20
)

// CatalogModel is a model of the code's endpoints alone, for a role that
// has no traffic: its OpenAPI document has only operations of source code.
func CatalogModel(o Options) *Model {
	if o.InScope == nil {
		o.InScope = func(string) bool { return true }
	}
	return &Model{cat: newCatalog(o.Catalog, o.InScope), role: o.Role, redacted: o.Redact != nil, byRef: map[string]*Request{}}
}

// WriteOpenAPI writes the model's OpenAPI document to dir/openapi.json
// (0600; dir 0700 when made), by a temporary file renamed over it.
func (m *Model) WriteOpenAPI(dir string) error {
	b, err := m.OpenAPI()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".openapi-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, openapiFile))
}

// openapiOnly reports a directory holding jsharvest's openapi.json and
// nothing else (export -format openapi), which a later export may replace.
func openapiOnly(dest string) bool {
	es, err := os.ReadDir(dest)
	if err != nil || len(es) != 1 || es[0].Name() != openapiFile {
		return false
	}
	b, err := os.ReadFile(filepath.Join(dest, openapiFile))
	if err != nil {
		return false
	}
	var doc struct {
		X json.RawMessage `json:"x-jsharvest"`
	}
	return json.Unmarshal(b, &doc) == nil && len(doc.X) > 0
}

type obj = map[string]any

var oaMethods = map[string]bool{"GET": true, "PUT": true, "POST": true, "DELETE": true, "OPTIONS": true, "HEAD": true, "PATCH": true, "TRACE": true}

// oaOp is one OpenAPI operation as the evidence gathers it: the requests
// that made it, and the code's endpoints that name it.
type oaOp struct {
	method string
	path   *oaPath
	origin map[string]bool
	reqs   []*Request
	code   []*endpoints.Endpoint
}

type oaPath struct {
	key   string // the template with every {…} as {}
	raw   string // the first template seen, masked as it must be
	names []string
}

type oaBuilder struct {
	m      *Model
	red    *traffic.Redactor
	paths  map[string]*oaPath
	ops    map[string]*oaOp // method + " " + path key
	order  []string
	origin map[string]bool
	hosts  map[string]string // host -> scheme of an origin seen
	// methodless counts the code's endpoints that name no method: nothing
	// says which one the operation is, so none is written.
	methodless int
}

var braceRe = regexp.MustCompile(`\{([^{}]*)\}`)

// OpenAPI is the model as an OpenAPI 3.1 document (JSON, keys sorted: the
// same model gives the same bytes). Operations come from the traffic (the
// representative's params and bodies, the statuses seen) and from the
// code's endpoints that no request matched; nothing else is written.
// Header values are never written; example values only when the export
// is not redacted and the name is not a credential's.
func (m *Model) OpenAPI() ([]byte, error) {
	b := &oaBuilder{m: m, red: traffic.NewRedactor(), paths: map[string]*oaPath{}, ops: map[string]*oaOp{},
		origin: map[string]bool{}, hosts: map[string]string{}}
	b.gather()
	doc := b.document()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// path interns a template: its key, and the names its parameters bring.
func (b *oaBuilder) path(tmpl string) *oaPath {
	if tmpl == "" || tmpl[0] != '/' {
		tmpl = "/" + tmpl
	}
	if b.m.redacted {
		tmpl = roles.MaskTokens(tmpl)
	}
	var names []string
	key := braceRe.ReplaceAllStringFunc(tmpl, func(s string) string {
		names = append(names, paramName(s[1:len(s)-1]))
		return "{}"
	})
	p := b.paths[key]
	if p == nil {
		p = &oaPath{key: key, raw: tmpl, names: make([]string, len(names))}
		b.paths[key] = p
	}
	for i, n := range names {
		if p.names[i] == "" {
			p.names[i] = n
		}
	}
	return p
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// paramName keeps a name the template gave, when it can be one.
func paramName(s string) string {
	if nameRe.MatchString(s) {
		return s
	}
	return ""
}

// final is the path as OpenAPI writes it, its parameters named: the
// template's own names kept, else p1, p2… by position.
func (p *oaPath) final() (string, []string) {
	names := make([]string, len(p.names))
	used := map[string]bool{}
	for i, n := range p.names {
		if n == "" || used[n] {
			n = "p" + strconv.Itoa(i+1)
			for used[n] {
				n += "_"
			}
		}
		used[n], names[i] = true, n
	}
	i := -1
	out := braceRe.ReplaceAllStringFunc(p.key, func(string) string {
		i++
		return "{" + names[i] + "}"
	})
	return out, names
}

func (b *oaBuilder) op(method string, p *oaPath) *oaOp {
	k := method + " " + p.key
	o := b.ops[k]
	if o == nil {
		o = &oaOp{method: method, path: p, origin: map[string]bool{}}
		b.ops[k] = o
		b.order = append(b.order, k)
	}
	return o
}

func (b *oaBuilder) gather() {
	used := map[*endpoints.Endpoint]bool{}
	for _, r := range b.m.Requests {
		if !r.File || !oaMethods[strings.ToUpper(r.Entry.Method)] {
			continue
		}
		u, err := url.Parse(r.Entry.URL)
		if err != nil || u.Host == "" {
			continue
		}
		o := b.op(strings.ToUpper(r.Entry.Method), b.path(r.Template))
		origin := u.Scheme + "://" + u.Host
		o.origin[origin], b.origin[origin] = true, true
		b.hosts[u.Host] = u.Scheme
		o.reqs = append(o.reqs, r)
		if r.EP != nil {
			used[r.EP] = true
			if !containsEP(o.code, r.EP) {
				o.code = append(o.code, r.EP)
			}
		}
	}
	if b.m.cat == nil {
		return
	}
	for i := range b.m.cat.eps {
		ce := &b.m.cat.eps[i]
		if used[&ce.ep] {
			continue
		}
		if ce.ep.Method == "" || !oaMethods[strings.ToUpper(ce.ep.Method)] {
			b.methodless++
			continue
		}
		for _, p := range ce.paths {
			o := b.op(strings.ToUpper(ce.ep.Method), b.path(p))
			if !containsEP(o.code, &ce.ep) {
				o.code = append(o.code, &ce.ep)
			}
			if og := b.codeOrigin(&ce.ep); og != "" {
				o.origin[og], b.origin[og] = true, true
			}
		}
	}
}

func containsEP(l []*endpoints.Endpoint, e *endpoints.Endpoint) bool {
	for _, x := range l {
		if x == e {
			return true
		}
	}
	return false
}

// codeOrigin is the origin a code-only endpoint names: its base's, its
// host (with the scheme of a request to that host when one was seen), or
// "" when the code names none.
func (b *oaBuilder) codeOrigin(e *endpoints.Endpoint) string {
	for _, s := range append([]string{e.Base, e.Origin}, e.Bases...) {
		if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" && (e.Host == "" || strings.EqualFold(hostname(e.Host), u.Hostname())) {
			return u.Scheme + "://" + u.Host
		}
	}
	if e.Host != "" {
		if sch := b.hosts[e.Host]; sch != "" {
			return sch + "://" + e.Host
		}
		return "https://" + e.Host
	}
	return ""
}

func (b *oaBuilder) document() obj {
	origins := sortedSet(b.origin)
	servers := []any{}
	for _, o := range origins {
		servers = append(servers, obj{"url": o})
	}
	title := "jsharvest export"
	if len(origins) > 0 {
		var hs []string
		for _, o := range origins {
			u, _ := url.Parse(o)
			hs = append(hs, u.Host)
		}
		title += " of " + strings.Join(hs, ", ")
	}
	version := "0"
	if len(b.m.Runs) > 0 {
		version = strings.Join(b.m.Runs, "+")
	}
	paths := obj{}
	ids := b.operationIDs()
	for _, k := range b.order {
		o := b.ops[k]
		final, names := o.path.final()
		item, _ := paths[final].(obj)
		if item == nil {
			item = obj{}
			paths[final] = item
		}
		item[strings.ToLower(o.method)] = b.operation(o, final, names, ids[k], len(origins) > 1)
	}
	x := obj{"generator": creator}
	if len(b.m.Runs) > 0 {
		x["runs"] = b.m.Runs
	}
	if b.m.role != "" {
		x["role"] = b.m.role
	}
	if b.methodless > 0 {
		x["code_endpoints_without_method"] = b.methodless
	}
	return obj{
		"openapi":     "3.1.0",
		"info":        obj{"title": title, "version": version},
		"servers":     servers,
		"paths":       paths,
		"x-jsharvest": x,
	}
}

var idClean = regexp.MustCompile(`[^A-Za-z0-9]+`)

// operationIDs gives each operation a stable id: its method and path
// made plain, a number after it when two come to the same.
func (b *oaBuilder) operationIDs() map[string]string {
	keys := append([]string(nil), b.order...)
	sort.Strings(keys)
	ids := map[string]string{}
	used := map[string]bool{}
	for _, k := range keys {
		o := b.ops[k]
		final, _ := o.path.final()
		id := strings.ToLower(o.method) + "_" + strings.Trim(idClean.ReplaceAllString(final, "_"), "_")
		id = strings.TrimSuffix(id, "_")
		base := id
		for n := 2; used[id]; n++ {
			id = base + "_" + strconv.Itoa(n)
		}
		used[id], ids[k] = true, id
	}
	return ids
}

func (b *oaBuilder) operation(o *oaOp, path string, names []string, id string, multiOrigin bool) obj {
	op := obj{"operationId": id}
	summary := o.method + " " + path
	op["summary"] = summary
	x := obj{}
	switch {
	case len(o.reqs) > 0 && len(o.code) > 0:
		x["source"] = "both"
	case len(o.reqs) > 0:
		x["source"] = "traffic"
	default:
		x["source"] = "code"
	}
	if len(o.reqs) > 0 {
		x["requests"] = len(o.reqs)
	}
	if b.m.role != "" && len(o.reqs) > 0 {
		x["roles"] = []string{b.m.role}
	}
	destr := o.method == "DELETE" || guard.Destructive("http://x"+path)
	held := false
	for _, r := range o.reqs {
		destr = destr || r.Destructive
		held = held || r.Held
	}
	if destr {
		x["destructive"] = true
	}
	if held {
		x["held_back"] = true
	}
	op["x-jsharvest"] = x
	if multiOrigin && len(o.origin) > 0 {
		var ss []any
		for _, og := range sortedSet(o.origin) {
			ss = append(ss, obj{"url": og})
		}
		op["servers"] = ss
	}

	// Operations of one endpoint (GraphQL, an RPC's action).
	var gql, other []string
	seenOp := map[string]bool{}
	for _, r := range o.reqs {
		if r.Op == "" || seenOp[r.Op] {
			continue
		}
		seenOp[r.Op] = true
		if n, ok := strings.CutPrefix(r.Op, "op="); ok {
			gql = append(gql, n)
		} else {
			other = append(other, r.Op)
		}
	}
	for _, e := range o.code {
		for _, n := range e.Operations {
			if n != "" && !seenOp[n] {
				seenOp[n] = true
				gql = append(gql, n)
			}
		}
	}
	sort.Strings(gql)
	sort.Strings(other)
	if len(gql) > 0 {
		op["x-graphql-operations"] = gql
	}
	if len(other) > 0 {
		op["x-operations"] = other
	}

	params := b.parameters(o, names)
	if len(params) > 0 {
		op["parameters"] = params
	}
	if rb := b.requestBody(o); rb != nil {
		op["requestBody"] = rb
	}
	op["responses"] = b.responses(o)
	return op
}

type oaParam struct {
	in, name string
	values   map[string]bool
	order    []string
}

// parameters are the path's (required, typed by what the traffic put
// there), then the query and header names of the requests and of the
// code. A header's value is never written.
func (b *oaBuilder) parameters(o *oaOp, names []string) []any {
	var out []any
	// Path.
	ptypes := make([]map[string]bool, len(names))
	for i := range ptypes {
		ptypes[i] = map[string]bool{}
	}
	for _, r := range o.reqs {
		ord := placeholderOrdinals(r.Template)
		for _, p := range r.Params() {
			if p.In != "path" {
				continue
			}
			if k, ok := ord[p.Index]; ok && k < len(ptypes) {
				ptypes[k][p.Value] = true
			}
		}
	}
	for i, n := range names {
		sc := obj{"type": "string"}
		if len(ptypes[i]) > 0 {
			sc = schemaOfType(typeOf(ptypes[i], ParamLine{In: "path", Name: n}))
		}
		out = append(out, obj{"name": n, "in": "path", "required": true, "schema": sc})
	}
	// Query and header.
	agg := map[string]*oaParam{}
	var keys []string
	add := func(in, name, value string, hasValue bool) {
		k := in + "\x00" + name
		a := agg[k]
		if a == nil {
			a = &oaParam{in: in, name: name, values: map[string]bool{}}
			agg[k], keys = a, append(keys, k)
		}
		if hasValue && len(a.values) < 50 && !a.values[value] {
			a.values[value] = true
			a.order = append(a.order, value)
		}
	}
	for _, r := range o.reqs {
		for _, p := range r.Params() {
			switch p.In {
			case "query":
				add("query", p.Name, p.Value, true)
			case "header":
				if strings.EqualFold(p.Name, "cookie") {
					continue
				}
				add("header", strings.ToLower(p.Name), "", false) // the name alone
			}
		}
	}
	for _, e := range o.code {
		for _, n := range e.Query {
			if n != "" {
				add("query", n, "", false)
			}
		}
		for _, n := range e.Headers {
			if n != "" && !flow.PlainHeader(n) && !strings.EqualFold(n, "cookie") {
				add("header", strings.ToLower(n), "", false)
			}
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := agg[k]
		p := obj{"name": a.name, "in": a.in}
		sc := obj{"type": "string"}
		if a.in == "query" && len(a.values) > 0 {
			sc = schemaOfType(typeOf(a.values, ParamLine{In: "query", Name: a.name}))
			if ex, ok := b.exampleValue(a.name, a.order); ok {
				p["example"] = ex
			}
		}
		p["schema"] = sc
		if a.in == "header" && traffic.Sensitive(a.name) {
			p["description"] = "a credential: only its name is exported"
		}
		out = append(out, p)
	}
	return out
}

// placeholderOrdinals maps the segment number (from 1, as Param.Index) of
// each whole-segment placeholder of a template to its place among the
// path's placeholders.
func placeholderOrdinals(tmpl string) map[int]int {
	out := map[int]int{}
	n := 0
	for i, seg := range strings.Split(strings.Trim(tmpl, "/"), "/") {
		c := len(braceRe.FindAllString(seg, -1))
		if c == 1 && braceRe.FindString(seg) == seg {
			out[i+1] = n
		}
		n += c
	}
	return out
}

func schemaOfType(t string) obj {
	switch t {
	case "int":
		return obj{"type": "integer"}
	case "float":
		return obj{"type": "number"}
	case "bool":
		return obj{"type": "boolean"}
	case "uuid":
		return obj{"type": "string", "format": "uuid"}
	case "email":
		return obj{"type": "string", "format": "email"}
	}
	return obj{"type": "string"}
}

// exampleValue is a query value fit to publish: not a credential's name,
// not a token-looking value, masked of emails; none in a redacted export.
func (b *oaBuilder) exampleValue(name string, values []string) (string, bool) {
	if b.m.redacted || traffic.Sensitive(name) {
		return "", false
	}
	for _, v := range values {
		switch valueType(v, ParamLine{In: "query", Name: name}) {
		case "empty", "jwt", "base64", "hex":
			continue
		}
		if len(v) > 120 {
			continue
		}
		return b.mask(v), true
	}
	return "", false
}

var redactedRe = regexp.MustCompile(`REDACTED_[0-9a-f]{8}`)

// mask hides credentials and emails in text that is to be an example. The
// redactor's masks carry a hash under a key made for this call: they are
// made constant, so the document does not change from run to run.
func (b *oaBuilder) mask(s string) string {
	return maskPII(redactedRe.ReplaceAllString(b.red.Text(s), "REDACTED"))
}

type oaBody struct {
	mt     string
	schema obj
	// examples: the first body of the representative, and one for each
	// operation.
	example  any
	hasEx    bool
	examples map[string]any
}

// requestBody has a media type for each content type the requests had,
// its schema the union of their bodies' (JSON), its example masked.
func (b *oaBuilder) requestBody(o *oaOp) obj {
	bodies := map[string]*oaBody{}
	var mts []string
	byMT := map[string][]*Request{}
	for _, r := range o.reqs {
		if r.Entry.Body.Body == "" {
			continue
		}
		mt := mediaType(r)
		if mt == "" {
			continue
		}
		if bodies[mt] == nil {
			bodies[mt] = &oaBody{mt: mt}
			mts = append(mts, mt)
		}
		byMT[mt] = append(byMT[mt], r)
	}
	content := obj{}
	for _, mt := range mts {
		ob := bodies[mt]
		reqs := byMT[mt]
		switch {
		case strings.Contains(mt, "json"):
			b.jsonBody(ob, reqs)
		case mt == "application/x-www-form-urlencoded":
			ob.schema = formSchema(reqs, "form")
		case strings.HasPrefix(mt, "multipart/"):
			ob.schema = formSchema(reqs, "multipart")
		default:
			ob.schema = obj{}
		}
		if ob.schema == nil {
			ob.schema = obj{}
		}
		mto := obj{"schema": ob.schema}
		if ob.hasEx && len(ob.examples) == 0 {
			mto["example"] = ob.example
		}
		if len(ob.examples) > 0 {
			ex := obj{}
			for k, v := range ob.examples {
				ex[k] = obj{"value": v}
			}
			mto["examples"] = ex
		}
		content[mt] = mto
	}
	desc := ""
	if len(content) == 0 {
		// The code names fields; the traffic had no body.
		var fields []string
		types := map[string]string{}
		for _, e := range o.code {
			for _, n := range e.Body {
				if n != "" {
					fields = append(fields, n)
				}
			}
			for _, ps := range e.Params {
				if ps.In == "body" && ps.Name != "" {
					types[ps.Name] = ps.Type
				}
			}
		}
		if len(fields) == 0 {
			return nil
		}
		sort.Strings(fields)
		props := obj{}
		for _, n := range fields {
			switch types[n] {
			case "string", "number", "boolean", "array", "object":
				props[n] = obj{"type": types[n]}
			default:
				props[n] = obj{}
			}
		}
		content["application/json"] = obj{"schema": obj{"type": "object", "properties": props}}
		desc = "field names taken from the code; the content type was not observed"
	}
	rb := obj{"content": content}
	if desc != "" {
		rb["description"] = desc
	}
	return rb
}

// mediaType is a request's content type without its parameters; a JSON
// body without one is application/json.
func mediaType(r *Request) string {
	ct := ""
	for k, v := range r.Entry.Headers {
		if strings.EqualFold(k, "content-type") {
			ct = v
		}
	}
	if ct == "" {
		s := strings.TrimSpace(r.Entry.Body.Body)
		if !r.Entry.Body.BodyBase64 && (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Valid([]byte(s)) {
			return "application/json"
		}
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	}
	return mt
}

func (b *oaBuilder) jsonBody(ob *oaBody, reqs []*Request) {
	for _, r := range reqs {
		if r.Entry.Body.BodyBase64 || r.Entry.BodyTruncated {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(r.Entry.Body.Body))
		dec.UseNumber()
		var v any
		if dec.Decode(&v) != nil {
			continue
		}
		ob.schema = mergeSchema(ob.schema, inferSchema(v, 0))
	}
	if b.m.redacted {
		return
	}
	// Examples: the best request of each operation (one example when the
	// endpoint has none).
	groups := map[string][]*Request{}
	var names []string
	for _, r := range reqs {
		if groups[r.Op] == nil {
			names = append(names, r.Op)
		}
		groups[r.Op] = append(groups[r.Op], r)
	}
	sort.Strings(names)
	for _, op := range names {
		best := Best(groups[op])
		if best == nil || best.Entry.Body.BodyBase64 || best.Entry.BodyTruncated {
			continue
		}
		text := b.mask(best.Entry.Body.Body)
		if len(text) > maxExampleBytes {
			continue
		}
		var v any
		if json.Unmarshal([]byte(text), &v) != nil {
			continue
		}
		if op == "" {
			if !ob.hasEx {
				ob.example, ob.hasEx = v, true
			}
			continue
		}
		if len(ob.examples) >= maxExamples {
			continue
		}
		if ob.examples == nil {
			ob.examples = map[string]any{}
		}
		name := strings.TrimPrefix(op, "op=")
		ob.examples[name] = v
	}
	if len(ob.examples) > 0 && ob.hasEx {
		// A body with no operation among those that have: an example of
		// its own.
		ob.examples["(no operation)"], ob.hasEx = ob.example, false
	}
}

// formSchema is an object with the names the requests' form had.
func formSchema(reqs []*Request, in string) obj {
	vals := map[string]map[string]bool{}
	var names []string
	for _, r := range reqs {
		for _, p := range r.Params() {
			if p.In != in {
				continue
			}
			if vals[p.Name] == nil {
				vals[p.Name] = map[string]bool{}
				names = append(names, p.Name)
			}
			if len(vals[p.Name]) < 50 {
				vals[p.Name][p.Value] = true
			}
		}
	}
	if len(names) == 0 {
		return obj{"type": "object"}
	}
	props := obj{}
	for _, n := range names {
		if in == "multipart" {
			props[n] = obj{"type": "string"}
			continue
		}
		props[n] = schemaOfType(typeOf(vals[n], ParamLine{In: "form", Name: n}))
	}
	return obj{"type": "object", "properties": props}
}

// inferSchema is the JSON Schema of a sample: the kinds of its leaves.
func inferSchema(v any, depth int) obj {
	if depth > maxSchemaDepth {
		return obj{}
	}
	switch x := v.(type) {
	case string:
		return obj{"type": "string"}
	case bool:
		return obj{"type": "boolean"}
	case nil:
		return obj{"type": "null"}
	case json.Number:
		if strings.ContainsAny(x.String(), ".eE") {
			return obj{"type": "number"}
		}
		return obj{"type": "integer"}
	case float64:
		return obj{"type": "number"}
	case map[string]any:
		s := obj{"type": "object"}
		if len(x) == 0 {
			return s
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > maxSchemaProps {
			keys = keys[:maxSchemaProps]
		}
		props := obj{}
		for _, k := range keys {
			props[k] = inferSchema(x[k], depth+1)
		}
		s["properties"] = props
		return s
	case []any:
		s := obj{"type": "array"}
		var items obj
		for i, e := range x {
			if i >= maxSchemaItems {
				break
			}
			items = mergeSchema(items, inferSchema(e, depth+1))
		}
		if items != nil {
			s["items"] = items
		}
		return s
	}
	return obj{}
}

func typeList(s obj) []string {
	switch t := s["type"].(type) {
	case string:
		return []string{t}
	case []string:
		return t
	}
	return nil
}

// mergeSchema is a schema both a and b satisfy: the union of the types,
// of the properties, of the items. A schema of no type says anything, so
// it absorbs.
func mergeSchema(a, b obj) obj {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	ta, tb := typeList(a), typeList(b)
	if len(ta) == 0 || len(tb) == 0 {
		return obj{}
	}
	set := map[string]bool{}
	for _, t := range append(append([]string{}, ta...), tb...) {
		set[t] = true
	}
	if set["number"] {
		delete(set, "integer")
	}
	types := sortedSet(set)
	out := obj{}
	if len(types) == 1 {
		out["type"] = types[0]
	} else {
		out["type"] = types
	}
	pa, _ := a["properties"].(obj)
	pb, _ := b["properties"].(obj)
	if pa != nil || pb != nil {
		props := obj{}
		for k, v := range pa {
			props[k] = v
		}
		for k, v := range pb {
			if old, ok := props[k]; ok {
				props[k] = mergeSchema(old.(obj), v.(obj))
			} else {
				props[k] = v
			}
		}
		out["properties"] = props
	}
	ia, _ := a["items"].(obj)
	ib, _ := b["items"].(obj)
	if ia != nil || ib != nil {
		out["items"] = mergeSchema(ia, ib)
	}
	if f, ok := a["format"]; ok && f == b["format"] && len(types) == 1 {
		out["format"] = f
	}
	return out
}

// responses are the statuses the requests got (a status of a request the
// guard held is the guard's, not the server's). Where none was seen, the
// code's operation or an unanswered request has the default.
func (b *oaBuilder) responses(o *oaOp) obj {
	type seen struct{ ct map[string]bool }
	byStatus := map[int64]*seen{}
	for _, r := range o.reqs {
		resp := r.Entry.Response
		if resp == nil || r.Held || resp.Status < 100 || resp.Status > 599 {
			continue
		}
		s := byStatus[resp.Status]
		if s == nil {
			s = &seen{ct: map[string]bool{}}
			byStatus[resp.Status] = s
		}
		for k, v := range resp.Headers {
			if strings.EqualFold(k, "content-type") {
				if mt, _, err := mime.ParseMediaType(v); err == nil {
					s.ct[mt] = true
				}
			}
		}
	}
	out := obj{}
	for st, s := range byStatus {
		d := http.StatusText(int(st))
		if d == "" {
			d = "status " + strconv.Itoa(int(st))
		}
		r := obj{"description": d + " (observed)"}
		if len(s.ct) > 0 {
			c := obj{}
			for mt := range s.ct {
				c[mt] = obj{}
			}
			r["content"] = c
		}
		out[strconv.Itoa(int(st))] = r
	}
	if len(out) == 0 {
		if len(o.reqs) > 0 {
			out["default"] = obj{"description": "no response observed"}
		} else {
			out["default"] = obj{"description": "not observed: found in the code only"}
		}
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
