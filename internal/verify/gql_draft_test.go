package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/TimoMangCut/JSharvest/internal/endpoints"
	"github.com/TimoMangCut/JSharvest/internal/jsapi"
	"github.com/TimoMangCut/JSharvest/internal/replay"
)

func TestGraphQLStaticDocDraftsAndVerifyReadSafety(t *testing.T) {
	var mu sync.Mutex
	var seenOps []string
	var seenMethods []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		var req struct {
			OperationName string         `json:"operationName"`
			Query         string         `json:"query"`
			Variables     map[string]any `json:"variables"`
		}
		_ = json.Unmarshal(b, &req)
		mu.Lock()
		seenMethods = append(seenMethods, r.Method)
		if req.OperationName != "" {
			seenOps = append(seenOps, req.OperationName)
		}
		mu.Unlock()
		if r.Method != "POST" || req.OperationName == "" || !strings.Contains(req.Query, req.OperationName) {
			w.WriteHeader(400)
			w.Write([]byte(`{"errors":[{"message":"invalid graphql request"}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ok": true, "op": req.OperationName}})
	}))
	defer srv.Close()

	// Chunk 1: GraphQL client transport pointing to srv.URL + "/graphql".
	chunkClient := []byte(`
		export function sendGQL(body) {
			return fetch("` + srv.URL + `/graphql", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
		}
	`)
	// Chunk 2: Separate code-split chunk holding gql tagged templates (2 queries + 1 mutation + fragment).
	chunkDocs := []byte(`
		const ProfileFields = gql` + "`fragment ProfileFields on User { id displayName }`" + `;
		export const GET_PROFILE = gql` + "`" + `
			query GetProfile($id: ID!) {
				user(id: $id) { ...ProfileFields }
			}
			${ProfileFields}
		` + "`" + `;
		export const GET_FEED = gql` + "`" + `
			query GetFeed($limit: Int) {
				feed(limit: $limit) { id }
			}
		` + "`" + `;
		export const UPDATE_BIO = gql` + "`" + `
			mutation UpdateBio($bio: String!) {
				updateBio(bio: $bio) { id }
			}
		` + "`" + `;
	`)

	s1 := endpoints.Script{Result: jsapi.Extract(chunkClient), SHA256: "1111", URLs: []string{srv.URL + "/assets/client.js"}}
	s2 := endpoints.Script{Result: jsapi.Extract(chunkDocs), SHA256: "2222", URLs: []string{srv.URL + "/assets/docs.js"}}
	inScope := func(string) bool { return true }
	cat := endpoints.Build([]endpoints.Script{s1, s2}, nil, inScope)
	intel := endpoints.BuildIntel([]endpoints.Script{s1, s2}, inScope)

	ds := Drafts(Inputs{Catalog: cat, Intel: intel, InScope: inScope})
	byOp := map[string]Draft{}
	for _, d := range ds {
		byOp[d.Operation] = d
	}
	for _, wantOp := range []string{"op=GetProfile", "op=GetFeed", "op=UpdateBio"} {
		d, ok := byOp[wantOp]
		if !ok {
			t.Fatalf("missing draft for %s in %+v", wantOp, ds)
		}
		if len(d.Body) == 0 {
			t.Fatalf("draft %s has empty Body", wantOp)
		}
	}
	if !strings.Contains(string(byOp["op=GetProfile"].Body), "fragment ProfileFields on User") {
		t.Fatalf("GetProfile draft body missing fragment: %s", string(byOp["op=GetProfile"].Body))
	}

	// Run verify without -allow-write: BOTH queries must be probed via POST, while UpdateBio mutation MUST be skipped!
	snd, err := replay.NewSender(replay.SenderOptions{AllowPrivate: true, Max: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer snd.Close()

	rep, err := Run(context.Background(), Options{
		Target:  srv.URL,
		Role:    "anon",
		Drafts:  ds,
		Sender:  snd,
		InScope: inScope,
	})
	if err != nil {
		t.Fatal(err)
	}

	verdictByOp := map[string]string{}
	for _, r := range rep.Results {
		verdictByOp[r.Operation] = r.Verdict
	}
	if verdictByOp["op=GetProfile"] != Alive || verdictByOp["op=GetFeed"] != Alive {
		t.Fatalf("query verdicts = %v, want Alive for GetProfile and GetFeed (results=%+v)", verdictByOp, rep.Results)
	}
	if verdictByOp["op=UpdateBio"] != Skipped {
		t.Fatalf("mutation UpdateBio verdict = %q, want %q", verdictByOp["op=UpdateBio"], Skipped)
	}

	mu.Lock()
	defer mu.Unlock()
	if slices.Contains(seenOps, "UpdateBio") {
		t.Fatalf("server received mutation UpdateBio without -allow-write: %v", seenOps)
	}
	if !slices.Contains(seenOps, "GetProfile") || !slices.Contains(seenOps, "GetFeed") {
		t.Fatalf("server seenOps = %v, want both GetProfile and GetFeed", seenOps)
	}
}
