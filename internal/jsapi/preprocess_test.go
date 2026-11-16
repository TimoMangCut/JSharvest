package jsapi

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestExtractSourceTypeScriptConstructs(t *testing.T) {
	src := []byte(`import axios, { type AxiosInstance } from 'axios';

declare global {
  interface Window {
    __APP_CFG__?: { apiBase: string };
  }
}

type MultiLineUnion =
  | 'draft'
  | 'published'
  | 'archived'

export enum ApiRoutes {
  Users = '/api/v1/users',
  Roles = '/api/v1/roles',
}

export namespace LegacyApi {
  export const Audit = '/api/v1/audit';
  export namespace Admin {
    export const Flags = '/api/v1/admin/flags';
  }
}

function Injectable(): ClassDecorator {
  return (target) => target;
}
function Inject(_token: string): ParameterDecorator {
  return () => {};
}

abstract class BaseService {
  [key: string]: unknown;
  abstract prefix(): string;
}

@Injectable()
export class UserService extends BaseService {
  constructor(@Inject('HTTP') private readonly http: AxiosInstance) {
    super();
  }

  prefix(): string {
    return '/api/v1';
  }

  loadAll(this: UserService, state: MultiLineUnion) {
    const raw = <Record<string, unknown>>{ state };
    const id = state === 'draft'
      ? <T>(x: T): T => x
      : <T>(x: T): T => x;
    const getTyped = <T>(path: string): Promise<T> => this.http.get<T>(path, { params: raw });
    void id(raw);
    void getTyped(ApiRoutes.Users);
    void this.http.post(ApiRoutes['Roles'], { role: 'viewer' });
    void this.http.put('/api/v1/users/profile', { bio: 'ok' });
    void axios.delete(LegacyApi.Audit);
    return axios.patch(LegacyApi.Admin.Flags, { enabled: true });
  }
}
`)
	if r := Extract(src); r.Error == "" {
		t.Fatalf("plain Extract unexpectedly accepted TypeScript: %+v", r)
	}
	r := ExtractSource(src, "https://app.example/assets/chunk.js#src/services/user.service.ts")
	if r.Error != "" {
		t.Fatalf("ExtractSource error: %s", r.Error)
	}
	var got []string
	for _, ep := range r.Endpoints {
		got = append(got, fmt.Sprintf("%s %s %s", ep.Method, ep.URL, ep.Kind))
	}
	for _, want := range []string{
		"GET /api/v1/users wrapper",
		"POST /api/v1/roles client",
		"PUT /api/v1/users/profile client",
		"DELETE /api/v1/audit client",
		"PATCH /api/v1/admin/flags client",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	// Verify source-map VLQ mapping maps generated JS lines back to original .ts lines
	// despite stripped declare global / MultiLineUnion / expanded enum & namespace IIFEs.
	wantEnumLine := lineContaining(src, "Roles = '/api/v1/roles'")
	wantInlineLine := lineContaining(src, "this.http.put('/api/v1/users/profile'")
	var gotEnumLine, gotInlineLine int
	for _, ep := range r.Endpoints {
		if ep.Method == "POST" && ep.URL == "/api/v1/roles" {
			gotEnumLine = ep.Line
		}
		if ep.Method == "PUT" && ep.URL == "/api/v1/users/profile" {
			gotInlineLine = ep.Line
		}
	}
	if gotEnumLine != wantEnumLine {
		t.Fatalf("POST /api/v1/roles line = %d, want %d", gotEnumLine, wantEnumLine)
	}
	if gotInlineLine != wantInlineLine {
		t.Fatalf("PUT /api/v1/users/profile line = %d, want %d", gotInlineLine, wantInlineLine)
	}
}

func TestExtractSourceAccessorAndTC39Decorators(t *testing.T) {
	src := []byte(`class TokenStore {
  accessor endpoint: string = '/api/v2/sessions';
  refresh() {
    return fetch('/api/v2/sessions/refresh', { method: 'POST' });
  }
}
new TokenStore().refresh();
`)
	r := ExtractSource(src, "src/store/token.ts")
	if r.Error != "" {
		t.Fatalf("ExtractSource accessor error: %s", r.Error)
	}
	var got []string
	for _, ep := range r.Endpoints {
		got = append(got, ep.Method+" "+ep.URL)
	}
	if !slices.Contains(got, "POST /api/v2/sessions/refresh") {
		t.Fatalf("got %v", got)
	}
}

func TestExtractSourceVueSFCLinePreservation(t *testing.T) {
	src := []byte(`<template>
  <div class="panel">
    <template v-if="ready">
      <a href="/not-an-api/view">Open</a>
    </template>
  </div>
</template>

<script lang="ts">
export interface PanelItem {
  id: string;
  title: string;
}
export const loadSummary = () => fetch('/api/v1/panel/summary');
</script>

<script setup lang="ts" generic="T extends Record<string, unknown>">
import axios from 'axios';

interface FilterSpec {
  search?: string;
  limit?: number;
}

async function saveFilter(spec: FilterSpec): Promise<void> {
  await axios.put('/api/v1/panel/filter', { search: spec.search, limit: spec.limit });
}
void saveFilter({ search: 'all' });
</script>

<style scoped>
.panel { background: url('/assets/bg.svg'); }
</style>
`)
	r := ExtractSource(src, "https://app.example/assets/index.js#../../src/components/Panel.vue")
	if r.Error != "" {
		t.Fatalf("ExtractSource Vue SFC error: %s", r.Error)
	}
	wantSummaryLine := lineContaining(src, "fetch('/api/v1/panel/summary')")
	wantFilterLine := lineContaining(src, "axios.put('/api/v1/panel/filter'")
	byURL := map[string]Endpoint{}
	for _, ep := range r.Endpoints {
		byURL[ep.Method+" "+ep.URL] = ep
	}
	sumEP, ok := byURL["GET /api/v1/panel/summary"]
	if !ok {
		t.Fatalf("missing summary endpoint in %+v", r.Endpoints)
	}
	if sumEP.Line != wantSummaryLine {
		t.Errorf("summary line = %d, want %d", sumEP.Line, wantSummaryLine)
	}
	fltEP, ok := byURL["PUT /api/v1/panel/filter"]
	if !ok {
		t.Fatalf("missing filter endpoint in %+v", r.Endpoints)
	}
	if fltEP.Line != wantFilterLine {
		t.Errorf("filter line = %d, want %d", fltEP.Line, wantFilterLine)
	}
	if !slices.Contains(fltEP.Body, "search") || !slices.Contains(fltEP.Body, "limit") {
		t.Errorf("filter body = %v, want [limit search]", fltEP.Body)
	}
	for _, ep := range r.Endpoints {
		if strings.Contains(ep.URL, "not-an-api") || strings.Contains(ep.URL, "bg.svg") {
			t.Errorf("leaked non-script template/style URL: %+v", ep)
		}
	}
}

func TestExtractSourceDTSAndHTMLRejection(t *testing.T) {
	dts := []byte(`export declare interface UsersClient {
  list(params?: { page?: number }): Promise<Array<{ id: string }>>;
  remove(id: string): Promise<void>;
}
export declare const API_PREFIX = "/api/v1";
`)
	r := ExtractSource(dts, "types/users.d.ts")
	if r.Error != "" || len(r.Endpoints) != 0 {
		t.Fatalf("expected clean empty result on .d.ts, got err=%q eps=%+v", r.Error, r.Endpoints)
	}

	htmlDoc := []byte(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Error</title></head>
<body><pre>Cannot GET /api/v1/secret</pre></body>
</html>`)
	rh := ExtractSource(htmlDoc, "https://app.example/bad.js")
	if rh.Error == "" {
		t.Fatalf("expected HTML document to fail JS/TS parse, got %+v", rh)
	}
}

func lineContaining(src []byte, needle string) int {
	i := bytes.Index(src, []byte(needle))
	if i < 0 {
		return -1
	}
	return 1 + bytes.Count(src[:i], []byte("\n"))
}
