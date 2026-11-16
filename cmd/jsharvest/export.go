package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/export"
	"github.com/TimoMangCut/JSharvest/internal/results"
	"github.com/TimoMangCut/JSharvest/internal/scope"
	"github.com/TimoMangCut/JSharvest/internal/traffic"
	"github.com/TimoMangCut/JSharvest/internal/verify"
)

// runExport writes a role's traffic for fuzzers (see
// docs/gd4-export-design.md). It reads the output and sends nothing.
func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	out := fs.String("o", env("JSHARVEST_OUTPUT", "output"), "output root (env JSHARVEST_OUTPUT)")
	target := fs.String("target", "", "the target's host, as its output directory is named")
	role := fs.String("role", "anon", "role")
	run := fs.String("run", "", "the run to export: a run id, or all; default: the latest run with flows")
	dest := fs.String("dest", "", "where to write; default <output>/<host>/<role>/export (replaced, if jsharvest wrote it)")
	scopeMode := fs.String("scope", "", "rdn or fqdn: which hosts are the target's; default: the run's -scope")
	thirdParty := fs.Bool("third-party", false, "export requests to hosts out of scope too (analytics, CDNs: not yours to fuzz)")
	redact := fs.Bool("redact", false, "hide credentials and leave response bodies out, for sharing: the files then do not replay")
	drafts := fs.Bool("drafts", false, "also write <dest>/drafts/: a raw request of each endpoint of the catalog, sample values in (no traffic needed)")
	includeDocs := fs.Bool("include-docs", false, "with -drafts, the lines only a document names too (by default only once verify found them alive)")
	includeStrings := fs.Bool("include-strings", false, "with -drafts, write bare method-less path strings too (confidence string)")
	includeSourceOnly := fs.Bool("include-source-only", false, "with -drafts, write tree-shaken sourcemap-only endpoints too")
	format := fs.String("format", "files", "files (default: raw requests, HARs, params), openapi (openapi.json alone: an OpenAPI 3.1 document of the traffic and the code's endpoints), or all")
	fs.Parse(args)
	if *format != "files" && *format != "openapi" && *format != "all" {
		return fmt.Errorf("export: bad -format %q (files, openapi or all)", *format)
	}
	if *target == "" {
		return errors.New("export: -target is required")
	}
	if !roleRe.MatchString(*role) {
		return fmt.Errorf("export: bad -role %q", *role)
	}
	dir := filepath.Join(*out, targetDir(*target), *role)
	haveLog := true
	if _, err := os.Stat(filepath.Join(dir, "requests.jsonl")); err != nil {
		if !*drafts && *format == "files" {
			return fmt.Errorf("export: no request log in %s (record with crawl or watch, -record api; -drafts writes the catalog's drafts alone)", dir)
		}
		haveLog = false
	}
	mode := *scopeMode
	if mode == "" {
		mode = results.ScopeMode(dir)
	}
	in, err := scope.New(hostOnly(*target), mode)
	if err != nil {
		return err
	}
	var cat []endpoints.Endpoint
	if haveLog {
		if cat, err = endpoints.Catalog(dir, in, false); err != nil {
			return err
		}
	}
	o := export.Options{Dir: dir, Dest: *dest, Run: *run, InScope: in, ThirdParty: *thirdParty, Catalog: cat, Role: *role}
	if *redact {
		o.Redact = traffic.NewRedactor()
	}
	if *thirdParty {
		fmt.Fprintln(os.Stderr, "warning: -third-party exports hosts out of the target's scope: do not fuzz them without their owners' leave")
	}
	where := o.Dest
	if where == "" {
		where = filepath.Join(dir, "export")
	}
	if *format == "openapi" {
		return writeOpenAPI(o, where, dir, haveLog, in)
	}
	writeDrafts := func() (bool, error) {
		if !*drafts {
			return false, nil
		}
		inputs, err := verify.Load(dir, "", false)
		if err != nil {
			return false, err
		}
		inputs.InScope = in
		ds := verify.Drafts(inputs)
		if len(ds) == 0 {
			return false, nil
		}
		if o.Redact != nil {
			ds = verify.RedactDrafts(ds, o.Redact)
		}
		if err := os.MkdirAll(where, 0o700); err != nil {
			return false, err
		}
		idx, err := verify.WriteDraftsFull(filepath.Join(where, "drafts"), verify.WithUserAgent(ds, pickUA(nil, dir, filepath.Join(filepath.Dir(dir), "*"))), *includeDocs, *includeStrings, *includeSourceOnly, verify.AliveKeys(filepath.Join(dir, "verify")))
		if err != nil {
			return false, err
		}
		var tiers []string
		for _, k := range []string{verify.Ready, verify.Parameterized, verify.Incomplete} {
			tiers = append(tiers, fmt.Sprintf("%s %d", k, idx.Tiers[k]))
		}
		fmt.Fprintf(os.Stderr, "drafts: %d of %d endpoints written (%s); unverified unless verify says so\n", idx.Files, len(ds), strings.Join(tiers, ", "))
		return true, nil
	}
	exportStaticFallback := func(fromLog bool) error {
		if *format == "all" {
			if fromLog {
				fmt.Fprintf(os.Stderr, "note: 0 live API flows captured in %s; writing static catalog artifacts\n", dir)
			}
			oaErr := writeOpenAPI(o, where, dir, false, in)
			if oaErr != nil && !errors.Is(oaErr, export.ErrNoFlows) {
				return oaErr
			}
			wroteOA := oaErr == nil
			wroteDrafts := false
			var draftErr error
			if *drafts {
				wroteDrafts, draftErr = writeDrafts()
				if draftErr != nil && !errors.Is(draftErr, os.ErrNotExist) {
					return draftErr
				}
				if wroteDrafts {
					fmt.Fprintln(os.Stderr, "wrote", filepath.Join(where, "drafts"))
				}
			}
			if !wroteOA && !wroteDrafts {
				if draftErr != nil {
					return draftErr
				}
				if oaErr != nil {
					return oaErr
				}
				return fmt.Errorf("%w in %s", export.ErrNoFlows, dir)
			}
			return nil
		}
		// format == "files" with -drafts
		wroteDrafts, err := writeDrafts()
		if err != nil {
			return err
		}
		if !wroteDrafts {
			return fmt.Errorf("%w in %s", export.ErrNoFlows, dir)
		}
		if fromLog {
			fmt.Fprintln(os.Stderr, "note: no run with flows: the drafts alone; wrote", filepath.Join(where, "drafts"))
		} else {
			fmt.Fprintln(os.Stderr, "wrote", filepath.Join(where, "drafts"))
		}
		return nil
	}
	if !haveLog {
		return exportStaticFallback(false)
	}
	m, err := export.Export(o)
	if errors.Is(err, export.ErrNoFlows) {
		if *format == "all" || *drafts {
			return exportStaticFallback(true)
		}
		return err
	}
	if err != nil {
		return err
	}
	if _, err := writeDrafts(); err != nil {
		return err
	}
	if *format == "all" {
		if err := writeOpenAPI(o, where, dir, haveLog, in); err != nil {
			return err
		}
	}
	var counts []string
	for k, v := range m.Counts {
		counts = append(counts, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(counts)
	fmt.Fprintf(os.Stderr, "export of run %s: %s\n", strings.Join(m.Runs, ", "), strings.Join(counts, ", "))
	for _, w := range m.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if len(m.Incomplete) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d raw file(s) have an incomplete body (manifest.json incomplete)\n", len(m.Incomplete))
	}
	if !m.Redacted {
		fmt.Fprintln(os.Stderr, "note: the export holds real cookies and tokens (files 0600); -redact for a copy to share")
	}
	fmt.Fprintln(os.Stderr, "wrote", where)
	return nil
}

// writeOpenAPI writes where/openapi.json: the model of the role's traffic
// when it has flows, else the code's endpoints alone.
func writeOpenAPI(o export.Options, where, dir string, haveLog bool, in func(string) bool) error {
	var m *export.Model
	if haveLog {
		var err error
		m, err = export.Load(o)
		if err != nil && !errors.Is(err, export.ErrNoFlows) {
			return err
		}
		if err != nil {
			m = nil
		}
	}
	if m == nil {
		if len(o.Catalog) == 0 {
			cat, err := endpoints.Catalog(dir, in, false)
			if err != nil {
				return err
			}
			o.Catalog = cat
		}
		if len(o.Catalog) == 0 {
			o.Catalog = readCatalogFile(dir)
		}
		m = export.CatalogModel(o)
		b, err := m.OpenAPI()
		if err != nil {
			return err
		}
		var doc struct {
			Paths map[string]json.RawMessage `json:"paths"`
		}
		if json.Unmarshal(b, &doc) != nil || len(doc.Paths) == 0 {
			return fmt.Errorf("%w in %s", export.ErrNoFlows, dir)
		}
		fmt.Fprintln(os.Stderr, "note: no run with flows: the OpenAPI document has the code's endpoints alone")
	}
	if err := m.WriteOpenAPI(where); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "wrote", filepath.Join(where, "openapi.json"))
	return nil
}

func readCatalogFile(dir string) []endpoints.Endpoint {
	f, err := os.Open(filepath.Join(dir, endpoints.File))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []endpoints.Endpoint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ep endpoints.Endpoint
		if json.Unmarshal(sc.Bytes(), &ep) == nil {
			out = append(out, ep)
		}
	}
	return out
}
