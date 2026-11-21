package endpoints

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TimoMangCut/JSharvest/internal/marker"
	"github.com/TimoMangCut/JSharvest/internal/netsafe"
)

// MaxCloudTargets caps how many cloud storage URLs a verify run probes.
const MaxCloudTargets = 10

const (
	cloudProbeTimeout = 10 * time.Second
	cloudMaxReadBytes = 8192
)

// Cloud ACL probe statuses.
const (
	CloudPublicListable = "public_listable"
	CloudPublicObject   = "public_object"
	CloudBucketPrivate  = "bucket_exists_private"
	CloudObjectNotFound = "object_not_found"
	CloudBucketMissing  = "bucket_missing"
)

// ErrCloudProbeStopped signals that an external request gate (such as
// replay.Sender's -max budget or stop condition) halted further cloud probes.
var ErrCloudProbeStopped = errors.New("cloud probe stopped")

// CloudProbeOptions configure active safe ACL probing of cloud storage URLs.
type CloudProbeOptions struct {
	Proxy        *url.URL
	HostRules    netsafe.Rules
	AllowPrivate bool
	Insecure     bool
	Resolver     netsafe.Resolver
	Timeout      time.Duration
	MaxTargets   int
	UserAgent    string
	// Do optionally wraps client.Do(req) so callers (such as verify) can
	// enforce rate limits, request budgets, and sent.jsonl logging.
	Do func(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error)
}

// CloudCheck records the outcome of probing one cloud storage entry.
type CloudCheck struct {
	URL           string `json:"url"`
	Provider      string `json:"provider,omitempty"`
	Bucket        string `json:"bucket,omitempty"`
	Region        string `json:"region,omitempty"`
	ObjectKey     string `json:"object_key,omitempty"`
	BucketRootURL string `json:"bucket_root_url,omitempty"`
	Status        string `json:"status"`
	RootStatus    int    `json:"root_status,omitempty"`
	ObjectStatus  int    `json:"object_status,omitempty"`
	Error         string `json:"error,omitempty"`
}

func newIntelURL(raw string) *IntelURL {
	iu := &IntelURL{URL: raw}
	enrichCloudURL(iu)
	return iu
}

func enrichCloudURL(iu *IntelURL) {
	if p, b, r, k, root, ok := ParseCloudURL(iu.URL); ok {
		iu.Provider = p
		iu.Bucket = b
		iu.Region = r
		iu.ObjectKey = k
		iu.BucketRootURL = root
	}
}

// ParseCloudURL parses a cloud storage URL into its provider, bucket/container,
// region, object key, and canonical bucket root URL. Protocol-relative URLs
// ("//...") are normalized to "https://...".
func ParseCloudURL(raw string) (provider, bucket, region, objectKey, rootURL string, ok bool) {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "//") {
		s = "https:" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", "", "", "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
	if host == "" || strings.ContainsAny(host, "{}") {
		return "", "", "", "", "", false
	}
	hostPort := canonAuthHost(scheme, u.Host)

	switch {
	case strings.HasSuffix(host, ".amazonaws.com.cn"):
		return parseS3Style(scheme, host, hostPort, u.Path, ".amazonaws.com.cn", "aws_s3")
	case strings.HasSuffix(host, ".amazonaws.com"):
		return parseS3Style(scheme, host, hostPort, u.Path, ".amazonaws.com", "aws_s3")
	case strings.HasSuffix(host, ".wasabisys.com"):
		return parseS3Style(scheme, host, hostPort, u.Path, ".wasabisys.com", "wasabi")
	case strings.HasSuffix(host, ".backblazeb2.com"):
		if p, b, r, k, root, ok := parseS3Style(scheme, host, hostPort, u.Path, ".backblazeb2.com", "backblaze_b2"); ok {
			return p, b, r, k, root, true
		}
		if strings.HasPrefix(u.Path, "/file/") {
			b, rest := splitFirstSegment(strings.TrimPrefix(u.Path, "/file"))
			if b != "" && !strings.ContainsAny(b, "{}") {
				return "backblaze_b2", b, "", rest, scheme + "://" + hostPort + "/file/" + b, true
			}
		}
		return "", "", "", "", "", false

	case host == "firebasestorage.googleapis.com":
		ep := strings.TrimPrefix(u.EscapedPath(), "/")
		if !strings.HasPrefix(ep, "v0/b/") {
			return "", "", "", "", "", false
		}
		rem := strings.TrimPrefix(ep, "v0/b/")
		bEnc, rest, _ := strings.Cut(rem, "/")
		b, err := url.PathUnescape(bEnc)
		if err != nil || b == "" || strings.ContainsAny(b, "{}") {
			return "", "", "", "", "", false
		}
		var key string
		if strings.HasPrefix(rest, "o/") {
			rawKey := strings.TrimPrefix(rest, "o/")
			if dec, err := url.PathUnescape(rawKey); err == nil {
				key = dec
			} else {
				key = rawKey
			}
		}
		return "firebase", b, "", key, scheme + "://" + hostPort + "/v0/b/" + b + "/o", true

	case host == "storage.googleapis.com" || host == "storage.cloud.google.com":
		b, rest := splitFirstSegment(u.Path)
		if b == "" || strings.ContainsAny(b, "{}") {
			return "", "", "", "", "", false
		}
		return "gcs", b, "", rest, scheme + "://" + hostPort + "/" + b, true

	case strings.HasSuffix(host, ".storage.googleapis.com"):
		b := strings.TrimSuffix(host, ".storage.googleapis.com")
		if b == "" {
			return "", "", "", "", "", false
		}
		return "gcs", b, "", strings.TrimPrefix(u.Path, "/"), scheme + "://" + hostPort, true

	case strings.HasSuffix(host, ".blob.core.windows.net"):
		acct := strings.TrimSuffix(host, ".blob.core.windows.net")
		if acct == "" {
			return "", "", "", "", "", false
		}
		c, rest := splitFirstSegment(u.Path)
		if c == "" || strings.ContainsAny(c, "{}") {
			return "", "", "", "", "", false
		}
		return "azure_blob", c, "", rest, scheme + "://" + hostPort + "/" + c, true

	case strings.HasSuffix(host, ".digitaloceanspaces.com"):
		sub := strings.TrimSuffix(host, ".cdn.digitaloceanspaces.com")
		if sub == host {
			sub = strings.TrimSuffix(host, ".digitaloceanspaces.com")
		}
		if sub == "" {
			return "", "", "", "", "", false
		}
		if dot := strings.LastIndex(sub, "."); dot > 0 {
			return "digitalocean_spaces", sub[:dot], sub[dot+1:], strings.TrimPrefix(u.Path, "/"), scheme + "://" + hostPort, true
		}
		b, rest := splitFirstSegment(u.Path)
		if b == "" || strings.ContainsAny(b, "{}") {
			return "", "", "", "", "", false
		}
		return "digitalocean_spaces", b, sub, rest, scheme + "://" + hostPort + "/" + b, true

	case strings.HasSuffix(host, ".r2.dev"):
		b := strings.TrimSuffix(host, ".r2.dev")
		if b == "" {
			return "", "", "", "", "", false
		}
		return "cloudflare_r2", b, "", strings.TrimPrefix(u.Path, "/"), scheme + "://" + hostPort, true

	case strings.HasSuffix(host, ".r2.cloudflarestorage.com"):
		sub := strings.TrimSuffix(host, ".r2.cloudflarestorage.com")
		if sub == "" {
			return "", "", "", "", "", false
		}
		parts := strings.Split(sub, ".")
		if len(parts) == 1 || (len(parts) == 2 && (parts[1] == "eu" || parts[1] == "fedramp")) {
			b, rest := splitFirstSegment(u.Path)
			if b == "" || strings.ContainsAny(b, "{}") {
				return "", "", "", "", "", false
			}
			return "cloudflare_r2", b, "", rest, scheme + "://" + hostPort + "/" + b, true
		}
		b := strings.Join(parts[:len(parts)-1], ".")
		return "cloudflare_r2", b, "", strings.TrimPrefix(u.Path, "/"), scheme + "://" + hostPort, true

	case strings.HasSuffix(host, ".aliyuncs.com"):
		sub := strings.TrimSuffix(host, ".aliyuncs.com")
		if idx := strings.LastIndex(sub, ".oss-"); idx > 0 {
			return "alibaba_oss", sub[:idx], sub[idx+5:], strings.TrimPrefix(u.Path, "/"), scheme + "://" + hostPort, true
		}
		if strings.HasSuffix(sub, ".oss") {
			b := strings.TrimSuffix(sub, ".oss")
			if b != "" {
				return "alibaba_oss", b, "", strings.TrimPrefix(u.Path, "/"), scheme + "://" + hostPort, true
			}
		}
		if strings.HasPrefix(sub, "oss-") {
			b, rest := splitFirstSegment(u.Path)
			if b != "" && !strings.ContainsAny(b, "{}") {
				return "alibaba_oss", b, strings.TrimPrefix(sub, "oss-"), rest, scheme + "://" + hostPort + "/" + b, true
			}
		}
	}
	return "", "", "", "", "", false
}

func parseS3Style(scheme, host, hostPort, rawPath, suffix, providerName string) (provider, bucket, region, objectKey, rootURL string, ok bool) {
	sub := strings.TrimSuffix(host, suffix)
	if sub == "" {
		return "", "", "", "", "", false
	}
	// Path-style: s3.<region>, s3-<region>, s3.dualstack.<region>, s3
	if sub == "s3" || strings.HasPrefix(sub, "s3.") || strings.HasPrefix(sub, "s3-") {
		b, rest := splitFirstSegment(rawPath)
		if b == "" || strings.ContainsAny(b, "{}") {
			return "", "", "", "", "", false
		}
		return providerName, b, extractS3Region(sub), rest, scheme + "://" + hostPort + "/" + b, true
	}
	// Virtual-hosted-style: <bucket>.s3, <bucket>.s3.<region>, <bucket>.s3-<region>
	if strings.HasSuffix(sub, ".s3") {
		b := strings.TrimSuffix(sub, ".s3")
		if b == "" {
			return "", "", "", "", "", false
		}
		return providerName, b, "", strings.TrimPrefix(rawPath, "/"), scheme + "://" + hostPort, true
	}
	idx := max(strings.LastIndex(sub, ".s3."), strings.LastIndex(sub, ".s3-"))
	if idx <= 0 {
		return "", "", "", "", "", false
	}
	b := sub[:idx]
	tail := sub[idx+1:]
	return providerName, b, extractS3Region(tail), strings.TrimPrefix(rawPath, "/"), scheme + "://" + hostPort, true
}

func extractS3Region(s3Part string) string {
	switch {
	case s3Part == "s3" || s3Part == "s3-accelerate" || s3Part == "s3-accelerate.dualstack":
		return ""
	case strings.HasPrefix(s3Part, "s3.dualstack."):
		return strings.TrimPrefix(s3Part, "s3.dualstack.")
	case strings.HasPrefix(s3Part, "s3-website-"):
		return strings.TrimPrefix(s3Part, "s3-website-")
	case strings.HasPrefix(s3Part, "s3-website."):
		return strings.TrimPrefix(s3Part, "s3-website.")
	case strings.HasPrefix(s3Part, "s3."):
		return strings.TrimPrefix(s3Part, "s3.")
	case strings.HasPrefix(s3Part, "s3-"):
		return strings.TrimPrefix(s3Part, "s3-")
	default:
		return ""
	}
}

func splitFirstSegment(p string) (first, rest string) {
	trimmed := strings.TrimPrefix(p, "/")
	if trimmed == "" {
		return "", ""
	}
	seg, rem, ok := strings.Cut(trimmed, "/")
	if !ok {
		return seg, ""
	}
	return seg, strings.TrimPrefix(rem, "/")
}

type rootProbeAns struct {
	status int
	body   string
	err    error
}

// ProbeCloud safely checks up to MaxCloudTargets cloud storage URLs using
// netsafe.Dialer + netsafe.Guard + opts.Proxy, sending zero cookies or
// application credentials.
func ProbeCloud(ctx context.Context, cloud []IntelURL, opts CloudProbeOptions) ([]IntelURL, []CloudCheck) {
	out := slices.Clone(cloud)
	for i := range out {
		if out[i].BucketRootURL == "" {
			enrichCloudURL(&out[i])
		}
	}
	if len(out) == 0 {
		return out, nil
	}
	limit := opts.MaxTargets
	if limit <= 0 {
		limit = MaxCloudTargets
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = cloudProbeTimeout
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = marker.FallbackUA
	}

	dialer := &netsafe.Dialer{
		Resolver:     opts.Resolver,
		HostRules:    opts.HostRules,
		AllowPrivate: opts.AllowPrivate,
		Proxy:        opts.Proxy,
		Timeout:      timeout,
	}
	tr := &http.Transport{
		Proxy:              netsafe.ProxyFunc(opts.Proxy, opts.HostRules),
		DialContext:        dialer.DialContext,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: opts.Insecure},
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	if opts.Proxy == nil {
		tr.Proxy = nil
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: netsafe.Guard{
			Next:         tr,
			AllowPrivate: opts.AllowPrivate,
			Rules:        opts.HostRules,
		},
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return http.ErrUseLastResponse
			}
			if _, _, _, _, _, ok := ParseCloudURL(req.URL.String()); !ok {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	rootCache := map[string]rootProbeAns{}
	var checks []CloudCheck
	probed := 0

	for i := range out {
		if ctx.Err() != nil || probed >= limit {
			break
		}
		u := &out[i]
		if u.BucketRootURL == "" {
			continue
		}
		probed++

		rootReqURL := u.BucketRootURL
		if u.Provider == "azure_blob" && !strings.Contains(rootReqURL, "?") {
			rootReqURL += "?restype=container&comp=list"
		}
		ra, cached := rootCache[rootReqURL]
		if !cached {
			ra = doCloudRootGET(ctx, client, opts.Do, rootReqURL, ua)
			if errors.Is(ra.err, ErrCloudProbeStopped) {
				break
			}
			rootCache[rootReqURL] = ra
		}

		objStatus := 0
		var objErr error
		stoppedAfterRoot := false
		if u.ObjectKey != "" && !strings.ContainsAny(u.URL, "{}") {
			sampleURL := strings.TrimSpace(u.URL)
			if strings.HasPrefix(sampleURL, "//") {
				sampleURL = "https:" + sampleURL
			}
			objStatus, objErr = doCloudObjectHEAD(ctx, client, opts.Do, sampleURL, ua)
			if errors.Is(objErr, ErrCloudProbeStopped) {
				objErr = nil
				stoppedAfterRoot = true
			}
		}

		status := classifyCloudACL(u.Provider, ra, objStatus)
		u.Status = status

		chk := CloudCheck{
			URL:           u.URL,
			Provider:      u.Provider,
			Bucket:        u.Bucket,
			Region:        u.Region,
			ObjectKey:     u.ObjectKey,
			BucketRootURL: u.BucketRootURL,
			Status:        status,
			RootStatus:    ra.status,
			ObjectStatus:  objStatus,
		}
		if status == "" {
			if ra.err != nil {
				chk.Error = ra.err.Error()
			} else if objErr != nil {
				chk.Error = objErr.Error()
			}
		}
		checks = append(checks, chk)
		if stoppedAfterRoot {
			break
		}
	}
	return out, checks
}

func doCloudReq(ctx context.Context, client *http.Client, doFn func(context.Context, *http.Client, *http.Request) (*http.Response, error), req *http.Request) (*http.Response, error) {
	if doFn != nil {
		return doFn(ctx, client, req)
	}
	return client.Do(req)
}

func doCloudRootGET(ctx context.Context, client *http.Client, doFn func(context.Context, *http.Client, *http.Request) (*http.Response, error), target, ua string) rootProbeAns {
	reqCtx, cancel := context.WithTimeout(ctx, cloudProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return rootProbeAns{err: err}
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", ua)
	resp, err := doCloudReq(reqCtx, client, doFn, req)
	if err != nil {
		return rootProbeAns{err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, cloudMaxReadBytes))
	return rootProbeAns{status: resp.StatusCode, body: string(b)}
}

func doCloudObjectHEAD(ctx context.Context, client *http.Client, doFn func(context.Context, *http.Client, *http.Request) (*http.Response, error), target, ua string) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, cloudProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", ua)
	resp, err := doCloudReq(reqCtx, client, doFn, req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func classifyCloudACL(provider string, root rootProbeAns, objStatus int) string {
	lb := strings.ToLower(root.body)
	if root.status == http.StatusOK && isCloudListBody(provider, root.body, lb) {
		return CloudPublicListable
	}
	if root.status == http.StatusNotFound && isBucketMissingBody(lb) {
		return CloudBucketMissing
	}
	if objStatus == http.StatusOK {
		return CloudPublicObject
	}
	if objStatus == http.StatusNotFound && root.err == nil && root.status > 0 {
		return CloudObjectNotFound
	}
	if root.status == http.StatusForbidden || root.status == http.StatusUnauthorized ||
		objStatus == http.StatusForbidden || objStatus == http.StatusUnauthorized ||
		strings.Contains(lb, "accessdenied") || strings.Contains(lb, "publicaccessnotpermitted") || strings.Contains(lb, "authenticationfailed") {
		return CloudBucketPrivate
	}
	return ""
}

func isCloudListBody(provider, raw, lower string) bool {
	if strings.Contains(raw, "<ListBucketResult") || strings.Contains(lower, "<listbucketresult") ||
		strings.Contains(raw, "<EnumerationResults") || strings.Contains(lower, "<enumerationresults") ||
		strings.Contains(lower, `"storage#objects"`) {
		return true
	}
	if provider == "firebase" && (strings.Contains(lower, `"items"`) || strings.Contains(lower, `"prefixes"`)) {
		return true
	}
	return false
}

func isBucketMissingBody(lower string) bool {
	return strings.Contains(lower, "nosuchbucket") ||
		strings.Contains(lower, "the specified bucket does not exist") ||
		strings.Contains(lower, "the specified container does not exist") ||
		strings.Contains(lower, "containernotfound")
}

// UpdateIntelCloud updates an existing intel.json in roleDir with probed cloud
// statuses and high-signal security notes, if the file exists and is writable.
func UpdateIntelCloud(roleDir string, probed []IntelURL) error {
	path := filepath.Join(roleDir, IntelFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var in Intel
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	byURL := make(map[string]IntelURL, len(probed))
	for _, u := range probed {
		byURL[u.URL] = u
	}
	for i := range in.Cloud {
		if p, ok := byURL[in.Cloud[i].URL]; ok {
			srcs := in.Cloud[i].Sources
			in.Cloud[i] = p
			if len(srcs) > 0 {
				in.Cloud[i].Sources = srcs
			}
		}
	}

	addCloudNote := func(kind, rootURL string) {
		orig := originOf(rootURL)
		if orig == "" {
			orig = rootURL
		}
		for i := range in.SecurityNotes {
			if in.SecurityNotes[i].Kind == kind {
				if !slices.Contains(in.SecurityNotes[i].Origins, orig) {
					in.SecurityNotes[i].Origins = append(in.SecurityNotes[i].Origins, orig)
					slices.Sort(in.SecurityNotes[i].Origins)
					in.SecurityNotes[i].Count++
				}
				return
			}
		}
		in.SecurityNotes = append(in.SecurityNotes, SecurityNote{
			Kind:    kind,
			Origins: []string{orig},
			Example: rootURL,
			Count:   1,
		})
	}
	for _, u := range in.Cloud {
		switch u.Status {
		case CloudPublicListable:
			addCloudNote("cloud_public_listable", u.BucketRootURL)
		case CloudBucketMissing:
			addCloudNote("cloud_bucket_missing", u.BucketRootURL)
		}
	}
	slices.SortFunc(in.SecurityNotes, func(a, b SecurityNote) int { return strings.Compare(a.Kind, b.Kind) })

	out, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
