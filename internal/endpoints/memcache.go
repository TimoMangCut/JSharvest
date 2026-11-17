package endpoints

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/TimoMangCut/JSharvest/internal/jsapi"
)

// memCache holds extracted jsapi.Result structs and script bodies in memory
// up to a configurable byte budget so crawl and archive pipelines avoid
// re-reading and re-unmarshaling thousands of small files from disk.
type memCache struct {
	budgetBytes int64
	usedBytes   atomic.Int64

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

// ClearMemCache releases all in-memory cached AST results and script bodies.
func ClearMemCache() {
	for i := range globalMem.resShards {
		s := &globalMem.resShards[i]
		s.mu.Lock()
		s.m = nil
		s.mu.Unlock()
	}
	for i := range globalMem.bodyShards {
		s := &globalMem.bodyShards[i]
		s.mu.Lock()
		s.m = nil
		s.mu.Unlock()
	}
	globalMem.usedBytes.Store(0)
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

func estimateResultBytes(r jsapi.Result) int64 {
	n := int64(256)
	n += int64(len(r.Endpoints)) * 192
	n += int64(len(r.Bases)+len(r.Routes)+len(r.Paths)+len(r.Operations)+len(r.Cloud)) * 64
	n += int64(len(r.PropBases)+len(r.Settings)+len(r.ClientHeaders)+len(r.Keys)+len(r.Exports)+len(r.Imports)+len(r.Builders)+len(r.Deferred)) * 96
	n += int64(len(r.GraphQLDocs)+len(r.RouteEntries)) * 192
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

func memPutResult(sha string, res jsapi.Result) {
	budget := atomic.LoadInt64(&globalMem.budgetBytes)
	if budget <= 0 || res.Version != jsapi.Version {
		return
	}
	cost := estimateResultBytes(res)
	s := &globalMem.resShards[shardIdx(sha)]
	s.mu.Lock()
	if s.m == nil {
		s.m = map[string]cachedRes{}
	}
	if old, ok := s.m[sha]; ok {
		s.m[sha] = cachedRes{res: res, cost: cost}
		s.mu.Unlock()
		globalMem.usedBytes.Add(cost - old.cost)
		return
	}
	// Reserve up to 75% of budget for Result structs, 25% for raw bodies;
	// if full, evict half the shard to keep insertion O(1) amortized.
	if globalMem.usedBytes.Load()+cost > budget {
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
		if freed > 0 {
			globalMem.usedBytes.Add(-freed)
		}
	}
	if globalMem.usedBytes.Load()+cost <= budget {
		s.m[sha] = cachedRes{res: res, cost: cost}
		globalMem.usedBytes.Add(cost)
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

// CacheScriptBody stores a script body in the bounded RAM cache (if enabled and
// only when the script exports/imports symbols needed for deferred linking or is modest in size).
func CacheScriptBody(sha string, body []byte) {
	budget := atomic.LoadInt64(&globalMem.budgetBytes)
	if budget <= 0 || len(body) == 0 || int64(len(body)) > 2<<20 {
		return
	}
	// Cap raw bodies at 40% of total budget so Result structs always fit.
	bodyCap := (budget * 2) / 5
	if globalMem.usedBytes.Load()+int64(len(body)) > budget || int64(len(body)) > bodyCap {
		return
	}
	s := &globalMem.bodyShards[shardIdx(sha)]
	s.mu.Lock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	if _, exists := s.m[sha]; !exists {
		cp := make([]byte, len(body))
		copy(cp, body)
		s.m[sha] = cp
		globalMem.usedBytes.Add(int64(len(cp)))
	}
	s.mu.Unlock()
}

// SemanticAPISig returns a deterministic 32-byte semantic signature of all
// API-relevant artifacts extracted from a script (endpoints, bases, headers,
// settings/keys, GraphQL operations/docs, WebSocket URLs, exports, and authz).
// Pure UI/CSS/i18n/minifier rebuilds produce the exact same signature, whereas
// adding, removing, or modifying even a single API endpoint changes it.
func SemanticAPISig(r jsapi.Result) (sig [32]byte, empty bool) {
	var parts []string
	for _, e := range r.Endpoints {
		if e.Collector {
			continue
		}
		parts = append(parts, "ep:"+e.Method+"|"+e.Kind+"|"+e.Base+"|"+e.URL+"|"+strings.Join(e.Query, ",")+"|"+strings.Join(e.Body, ",")+"|"+strings.Join(e.Headers, ",")+"|"+strings.Join(e.Operations, ","))
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
