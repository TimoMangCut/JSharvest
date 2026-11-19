package endpoints

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// memCache holds extracted jsapi.Result structs and script bodies in memory
// across two independent bounded pools (65% AST Result pool, 35% Script Body pool)
// so crawl and archive pipelines avoid re-reading thousands of files from disk
// without raw bodies ever starving AST cache entries.
type memCache struct {
	budgetBytes   int64
	resUsedBytes  atomic.Int64
	bodyUsedBytes atomic.Int64

	resShards  [16]resShard
	bodyShards [16]bodyShard
}

type resShard struct {
	mu sync.RWMutex
	m  map[string]cachedRes
}

type cachedRes struct {
	res  jsapi.Result
	cost int64
}

type bodyShard struct {
	mu sync.RWMutex
	m  map[string][]byte
}

var globalMem memCache

func init() {
	if s := strings.TrimSpace(os.Getenv("JSHARVEST_MEM_CACHE_MB")); s != "" {
		if mb, err := strconv.Atoi(s); err == nil && mb > 0 {
			SetMemCacheMB(mb)
		}
	}
}

// SetMemCacheMB sets the maximum RAM budget (in MiB) for caching static
// extraction results and script bodies in memory (0 disables in-memory caching).
func SetMemCacheMB(mb int) {
	if mb <= 0 {
		atomic.StoreInt64(&globalMem.budgetBytes, 0)
		ClearMemCache()
		return
	}
	atomic.StoreInt64(&globalMem.budgetBytes, int64(mb)<<20)
}

// ClearResultMemCache releases all cached jsapi.Result entries while keeping
// cached script bodies intact for deferred builder/export linking.
func ClearResultMemCache() {
	for i := range globalMem.resShards {
		s := &globalMem.resShards[i]
		s.mu.Lock()
		s.m = nil
		s.mu.Unlock()
	}
	globalMem.resUsedBytes.Store(0)
}

// ClearMemCache releases all in-memory cached AST results and script bodies.
func ClearMemCache() {
	ClearResultMemCache()
	for i := range globalMem.bodyShards {
		s := &globalMem.bodyShards[i]
		s.mu.Lock()
		s.m = nil
		s.mu.Unlock()
	}
	globalMem.bodyUsedBytes.Store(0)
}

func shardIdx(sha string) int {
	if len(sha) == 0 {
		return 0
	}
	c := sha[len(sha)-1]
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return int(c) & 15
	}
}

func sumStringsBytes(ss []string) int64 {
	var n int64
	for _, s := range ss {
		n += 16 + int64(len(s))
	}
	return n
}

func estimateResultBytes(r jsapi.Result) int64 {
	n := int64(256 + len(r.Error) + len(r.ParseError))
	for _, e := range r.Endpoints {
		n += 160 + int64(len(e.Method)+len(e.URL)+len(e.Base)+len(e.Kind)+len(e.Snippet))
		n += sumStringsBytes(e.Query) + sumStringsBytes(e.Body) + sumStringsBytes(e.Headers) + sumStringsBytes(e.Operations)
	}
	n += sumStringsBytes(r.Bases) + sumStringsBytes(r.Routes) + sumStringsBytes(r.Paths) +
		sumStringsBytes(r.Operations) + sumStringsBytes(r.Cloud) + sumStringsBytes(r.DocProd)
	for _, h := range r.PropBases {
		n += 48 + int64(len(h.Name)+len(h.Value))
	}
	for _, h := range r.Settings {
		n += 48 + int64(len(h.Name)+len(h.Value))
	}
	for _, h := range r.ClientHeaders {
		n += 48 + int64(len(h.Name)+len(h.Value))
	}
	for _, h := range r.Keys {
		n += 48 + int64(len(h.Name)+len(h.Value))
	}
	for _, h := range r.DocVars {
		n += 48 + int64(len(h.Name)+len(h.Value))
	}
	for _, h := range r.DocDev {
		n += 48 + int64(len(h.Name)+len(h.Value))
	}
	n += int64(len(r.Exports)+len(r.Imports)+len(r.Builders)+len(r.Deferred)) * 128
	for _, g := range r.GraphQLDocs {
		n += 96 + int64(len(g.Name)+len(g.Kind)+len(g.Query))
	}
	for _, re := range r.RouteEntries {
		n += 96 + int64(len(re.Path)+len(re.Redirect)) + sumStringsBytes(re.Roles) + sumStringsBytes(re.Permissions)
	}
	n += int64(len(r.UnresolvedRoutePerms)+len(r.UnresolvedAuthzRules)) * 128
	for _, ce := range r.ConstExports {
		n += 128 + int64(len(ce.Module)+len(ce.Export)+len(ce.Scalar))
		for k, v := range ce.Values {
			n += 48 + int64(len(k)+len(v))
		}
	}
	return n
}

func memGetResult(sha string) (jsapi.Result, bool) {
	if atomic.LoadInt64(&globalMem.budgetBytes) <= 0 {
		return jsapi.Result{}, false
	}
	s := &globalMem.resShards[shardIdx(sha)]
	s.mu.RLock()
	cr, ok := s.m[sha]
	s.mu.RUnlock()
	if !ok || cr.res.Version != jsapi.Version {
		return jsapi.Result{}, false
	}
	return cr.res, true
}

func evictHalfResShardLocked(s *resShard) int64 {
	if len(s.m) == 0 {
		return 0
	}
	var freed int64
	count := 0
	target := max(1, len(s.m)/2)
	for k, v := range s.m {
		delete(s.m, k)
		freed += v.cost
		count++
		if count >= target {
			break
		}
	}
	return freed
}

func memPutResult(sha string, res jsapi.Result) {
	budget := atomic.LoadInt64(&globalMem.budgetBytes)
	if budget <= 0 || res.Version != jsapi.Version {
		return
	}
	resBudget := (budget * 65) / 100
	if resBudget <= 0 {
		resBudget = budget
	}
	cost := estimateResultBytes(res)
	if cost > resBudget {
		return
	}
	idx := shardIdx(sha)
	s := &globalMem.resShards[idx]
	s.mu.Lock()
	if s.m == nil {
		s.m = map[string]cachedRes{}
	}
	if old, ok := s.m[sha]; ok {
		s.m[sha] = cachedRes{res: res, cost: cost}
		s.mu.Unlock()
		globalMem.resUsedBytes.Add(cost - old.cost)
		return
	}
	if globalMem.resUsedBytes.Load()+cost > resBudget {
		if freed := evictHalfResShardLocked(s); freed > 0 {
			globalMem.resUsedBytes.Add(-freed)
		}
	}
	if globalMem.resUsedBytes.Load()+cost <= resBudget {
		s.m[sha] = cachedRes{res: res, cost: cost}
		globalMem.resUsedBytes.Add(cost)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Fallback ring eviction across sibling shards (locking one shard at a time).
	for step := 1; step < 16 && globalMem.resUsedBytes.Load()+cost > resBudget; step++ {
		other := &globalMem.resShards[(idx+step)&15]
		other.mu.Lock()
		freed := evictHalfResShardLocked(other)
		other.mu.Unlock()
		if freed > 0 {
			globalMem.resUsedBytes.Add(-freed)
		}
	}

	s.mu.Lock()
	if s.m == nil {
		s.m = map[string]cachedRes{}
	}
	if old, ok := s.m[sha]; ok {
		s.m[sha] = cachedRes{res: res, cost: cost}
		globalMem.resUsedBytes.Add(cost - old.cost)
	} else if globalMem.resUsedBytes.Load()+cost <= resBudget {
		s.m[sha] = cachedRes{res: res, cost: cost}
		globalMem.resUsedBytes.Add(cost)
	}
	s.mu.Unlock()
}

func memGetBody(sha string) ([]byte, bool) {
	if atomic.LoadInt64(&globalMem.budgetBytes) <= 0 {
		return nil, false
	}
	s := &globalMem.bodyShards[shardIdx(sha)]
	s.mu.RLock()
	b, ok := s.m[sha]
	s.mu.RUnlock()
	return b, ok
}

func evictHalfBodyShardLocked(s *bodyShard) int64 {
	if len(s.m) == 0 {
		return 0
	}
	var freed int64
	count := 0
	target := max(1, len(s.m)/2)
	for k, v := range s.m {
		delete(s.m, k)
		freed += int64(len(v))
		count++
		if count >= target {
			break
		}
	}
	return freed
}

// CacheScriptBody stores a script body in the bounded 35% body pool (with per-shard
// and cross-shard ring eviction so raw bodies never starve AST Result caching).
func CacheScriptBody(sha string, body []byte) {
	budget := atomic.LoadInt64(&globalMem.budgetBytes)
	if budget <= 0 || len(body) == 0 || int64(len(body)) > 2<<20 {
		return
	}
	resBudget := (budget * 65) / 100
	bodyBudget := budget - resBudget
	cost := int64(len(body))
	if bodyBudget <= 0 || cost > bodyBudget {
		return
	}
	idx := shardIdx(sha)
	s := &globalMem.bodyShards[idx]
	s.mu.Lock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	if _, exists := s.m[sha]; exists {
		s.mu.Unlock()
		return
	}
	if globalMem.bodyUsedBytes.Load()+cost > bodyBudget {
		if freed := evictHalfBodyShardLocked(s); freed > 0 {
			globalMem.bodyUsedBytes.Add(-freed)
		}
	}
	if globalMem.bodyUsedBytes.Load()+cost <= bodyBudget {
		cp := make([]byte, len(body))
		copy(cp, body)
		s.m[sha] = cp
		globalMem.bodyUsedBytes.Add(cost)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	for step := 1; step < 16 && globalMem.bodyUsedBytes.Load()+cost > bodyBudget; step++ {
		other := &globalMem.bodyShards[(idx+step)&15]
		other.mu.Lock()
		freed := evictHalfBodyShardLocked(other)
		other.mu.Unlock()
		if freed > 0 {
			globalMem.bodyUsedBytes.Add(-freed)
		}
	}

	s.mu.Lock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	if _, exists := s.m[sha]; !exists && globalMem.bodyUsedBytes.Load()+cost <= bodyBudget {
		cp := make([]byte, len(body))
		copy(cp, body)
		s.m[sha] = cp
		globalMem.bodyUsedBytes.Add(cost)
	}
	s.mu.Unlock()
}

// LoadOrExtractSig returns the SemanticAPISig of an already-stored script
// identified by its SHA-256 hex digest in dir (checking MemCache, then
// <dir>/static/<sha256>.json, then <dir>/js/<sha256>.js) without network I/O.
func LoadOrExtractSig(dir, sha256Hex, hint string) ([32]byte, bool) {
	if sha256Hex == "" {
		return [32]byte{}, false
	}
	if res, ok := memGetResult(sha256Hex); ok {
		sig, _ := SemanticAPISig(res)
		return sig, true
	}
	if dir == "" {
		return [32]byte{}, false
	}
	cache := filepath.Join(dir, CacheDir, sha256Hex+".json")
	var res jsapi.Result
	if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &res) == nil && res.Version == jsapi.Version {
		memPutResult(sha256Hex, res)
		sig, _ := SemanticAPISig(res)
		return sig, true
	}
	src, ok := memGetBody(sha256Hex)
	if !ok {
		var err error
		src, err = os.ReadFile(filepath.Join(dir, "js", sha256Hex+".js"))
		if err != nil || len(src) == 0 {
			return [32]byte{}, false
		}
	}
	res = ExtractCached(dir, src, hint)
	if strings.HasPrefix(res.Error, "not analysed:") {
		return [32]byte{}, false
	}
	sig, _ := SemanticAPISig(res)
	return sig, true
}

// SemanticAPISig returns a deterministic 32-byte semantic signature of all
// API-relevant artifacts extracted from a script (endpoints, bases, headers,
// settings/keys, GraphQL operations/docs, exports, route guards, and authz).
// Pure UI/CSS/i18n/minifier rebuilds produce the exact same signature, whereas
// adding, removing, or modifying even a single API endpoint or RBAC rule changes it.
func SemanticAPISig(r jsapi.Result) (sig [32]byte, empty bool) {
	var parts []string
	for _, e := range r.Endpoints {
		if e.Collector {
			continue
		}
		crefTag := ""
		if e.ConstRef != nil {
			crefTag = "|" + e.ConstRef.Module + ":" + e.ConstRef.Export + ":" + e.ConstRef.Key + ":" + e.ConstSuffix
		}
		parts = append(parts, "ep:"+e.Method+"|"+e.Kind+"|"+e.Base+"|"+e.URL+"|"+strings.Join(e.Query, ",")+"|"+strings.Join(e.Body, ",")+"|"+strings.Join(e.Headers, ",")+"|"+strings.Join(e.Operations, ",")+crefTag)
	}
	for _, b := range r.Bases {
		parts = append(parts, "b:"+b)
	}
	for _, b := range r.PropBases {
		parts = append(parts, "pb:"+b.Name+"="+b.Value)
	}
	for _, h := range r.ClientHeaders {
		parts = append(parts, "ch:"+strings.ToLower(h.Name)+"="+h.Value)
	}
	for _, k := range r.Keys {
		parts = append(parts, "k:"+k.Name+"="+k.Value)
	}
	for _, s := range r.Settings {
		parts = append(parts, "s:"+s.Name+"="+s.Value)
	}
	for _, c := range r.Cloud {
		parts = append(parts, "cl:"+c)
	}
	for _, op := range r.Operations {
		parts = append(parts, "op:"+op)
	}
	for _, gd := range r.GraphQLDocs {
		parts = append(parts, "gqldoc:"+gd.Kind+"|"+gd.Name)
	}
	for _, re := range r.RouteEntries {
		auth := ""
		if re.AuthRequired != nil {
			if *re.AuthRequired {
				auth = "1"
			} else {
				auth = "0"
			}
		}
		parts = append(parts, "rt:"+re.Path+"|"+re.Redirect+"|"+auth+"|"+strings.Join(re.Roles, ",")+"|"+strings.Join(re.Permissions, ","))
	}
	if len(r.Exports) > 0 {
		if b, err := json.Marshal(r.Exports); err == nil {
			parts = append(parts, "ex:"+string(b))
		}
	}
	if len(r.Imports) > 0 {
		if b, err := json.Marshal(r.Imports); err == nil {
			parts = append(parts, "im:"+string(b))
		}
	}
	if len(r.Builders) > 0 {
		if b, err := json.Marshal(r.Builders); err == nil {
			parts = append(parts, "bd:"+string(b))
		}
	}
	if len(r.Deferred) > 0 {
		if b, err := json.Marshal(r.Deferred); err == nil {
			parts = append(parts, "df:"+string(b))
		}
	}
	if r.ClientAuthz != nil {
		if b, err := json.Marshal(r.ClientAuthz); err == nil {
			parts = append(parts, "az:"+string(b))
		}
	}
	if len(r.ConstExports) > 0 {
		if b, err := json.Marshal(r.ConstExports); err == nil {
			parts = append(parts, "ce:"+string(b))
		}
	}
	if len(r.UnresolvedRoutePerms) > 0 {
		if b, err := json.Marshal(r.UnresolvedRoutePerms); err == nil {
			parts = append(parts, "urp:"+string(b))
		}
	}
	if len(r.UnresolvedAuthzRules) > 0 {
		if b, err := json.Marshal(r.UnresolvedAuthzRules); err == nil {
			parts = append(parts, "uar:"+string(b))
		}
	}
	if len(parts) == 0 {
		return sha256.Sum256(nil), true
	}
	sort.Strings(parts)
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	copy(sig[:], h.Sum(nil))
	return sig, false
}
