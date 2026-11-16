package jsapi

import (
	"reflect"
	"testing"
)

// plan-28 2.2: a .vue SFC whose <script> and <script setup> import the same
// name is extracted block by block (extractSFCSpans); what each block finds
// must all reach the result, ReExports, Builders and Deferred included.
func TestSFCSpansKeepEveryField(t *testing.T) {
	src := []byte(`<template><div/></template>
<script lang="ts">
import { ep } from "./shared.js";
export * from "./extra";
export function forName(e: string) { return ` + "`/records/${e}`" + ` }
const shared = 1;
</script>
<script setup lang="ts">
import { ep } from "./shared.js";
const load = (id: string) => fetch(` + "`/v2${ep(id)}`" + `, { method: "DELETE" });
void load("x");
const shared = 2;
</script>
`)
	r := ExtractSource(src, "https://app.example/assets/index.js#../../src/views/Two.vue")
	if r.Error != "" {
		t.Fatalf("error: %s", r.Error)
	}
	if len(r.ReExports) != 1 || r.ReExports[0].Module != "./extra" || !r.ReExports[0].All {
		t.Errorf("re-exports %+v, want export * from ./extra", r.ReExports)
	}
	if len(r.Builders) != 1 || r.Builders[0].Name != "forName" {
		t.Errorf("builders %+v, want forName", r.Builders)
	}
	if len(r.Deferred) != 1 || r.Deferred[0].Name != "ep" {
		t.Errorf("deferred %+v, want the DELETE through ep", r.Deferred)
	}
}

// Every slice field of Result goes through the merge: a field added later
// and forgotten there fails here.
func TestMergeSpanCoversEverySlice(t *testing.T) {
	var r Result
	v := reflect.ValueOf(&r).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Slice {
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		}
	}
	var out Result
	out.mergeSpan(r)
	o := reflect.ValueOf(out)
	for i := 0; i < o.NumField(); i++ {
		if f := o.Field(i); f.Kind() == reflect.Slice && f.Len() != 1 {
			t.Errorf("Result.%s not merged", o.Type().Field(i).Name)
		}
	}
}
