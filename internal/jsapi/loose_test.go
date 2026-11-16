package jsapi

import (
	"fmt"
	"slices"
	"testing"
)

func TestExtractLoose(t *testing.T) {
	src := []byte(`import { http } from '../lib/http';
import logo from '/assets/logo.png';
export interface User { id: number; name: string }
export const getUser = (id: number): Promise<User> => http.get<User>(` + "`/api/v1/users/${id}`" + `);
export const del = (id: string) => axios.delete('/api/v1/users/' + id);
export async function save(u: User) {
  return fetch('/api/v1/users?notify=1', { method: 'POST', body: JSON.stringify(u) });
}
const routes = [{ path: '/admin/reports/:reportId', component: Reports }];
const raw = "/internal/debug/flags";
const Comp = () => <div className="x">{fetch("/api/jsx")}</div>;
`)
	if r := Extract(src); r.Error == "" {
		t.Fatalf("the parser took TypeScript: %+v", r)
	}
	r := ExtractLoose(src)
	var got []string
	for _, e := range r.Endpoints {
		got = append(got, fmt.Sprintf("%s %s %s", e.Method, e.URL, e.Kind))
	}
	for _, want := range []string{
		"GET /api/v1/users/{} client",
		"DELETE /api/v1/users/ client",
		"POST /api/v1/users fetch",
		" /admin/reports/{} string",
		" /internal/debug/flags string",
		"GET /api/jsx fetch",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	for _, e := range r.Endpoints {
		if e.URL == "/assets/logo.png" || e.URL == "/lib/http" {
			t.Errorf("an asset or module path: %+v", e)
		}
		if e.Line == 0 {
			t.Errorf("no line: %+v", e)
		}
	}
}
