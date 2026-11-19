/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package mistralmoderation

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const pathDoc = `{
  "model": "m",
  "messages": [
    {"role": "system", "content": "be nice"},
    {"role": "user", "content": "first"},
    {"role": "assistant", "content": null, "tool_calls": [{"id": "1"}]},
    {"role": "user", "content": [
        {"type": "text", "text": "part one"},
        {"type": "image_url", "image_url": {"url": "http://x/y.png"}},
        {"type": "text", "text": "part two"}]},
    {"role": "user", "content": "last", "score": 7}
  ],
  "a": {"b": {"c": 1}, "list": [10, 20, 30, 40, 50]},
  "weird key": "wk",
  "quote'd": "qd",
  "choices": [{"message": {"content": "reply"}, "delta": {"content": "tok"}}]
}`

func evalPath(t *testing.T, path string) []interface{} {
	t.Helper()
	jp, err := compileJSONPath(path)
	if err != nil {
		t.Fatalf("compile %q: %v", path, err)
	}
	nodes, err := selectNodes([]byte(pathDoc), jp)
	if err != nil {
		t.Fatalf("evaluate %q: %v", path, err)
	}
	return nodes
}

func TestJSONPathSelectors(t *testing.T) {
	cases := []struct {
		path string
		want []interface{}
	}{
		{"$.model", []interface{}{"m"}},
		{"$['model']", []interface{}{"m"}},
		{`$["model"]`, []interface{}{"m"}},
		{"$['weird key']", []interface{}{"wk"}},
		{`$['quote\'d']`, []interface{}{"qd"}},
		{"$.messages[0].content", []interface{}{"be nice"}},
		{"$.messages[-1].content", []interface{}{"last"}},
		{"$.messages[ 1 ].content", []interface{}{"first"}},
		{"$.a.b.c", []interface{}{1.0}},
		{"$.a.list[1:3]", []interface{}{20.0, 30.0}},
		{"$.a.list[:2]", []interface{}{10.0, 20.0}},
		{"$.a.list[3:]", []interface{}{40.0, 50.0}},
		{"$.a.list[-2:]", []interface{}{40.0, 50.0}},
		{"$.a.list[::2]", []interface{}{10.0, 30.0, 50.0}},
		{"$.a.list[::-1]", []interface{}{50.0, 40.0, 30.0, 20.0, 10.0}},
		{"$.a.list[3:1:-1]", []interface{}{40.0, 30.0}},
		{"$.a.list[10:20]", nil},
		{"$.a.list[0,2,-1]", []interface{}{10.0, 30.0, 50.0}},
		{"$.a['b','list'].c", []interface{}{1.0}},
		{"$.a.b.*", []interface{}{1.0}},
		{"$.a.list[*]", []interface{}{10.0, 20.0, 30.0, 40.0, 50.0}},
		{"$.messages[*].role", []interface{}{"system", "user", "assistant", "user", "user"}},
		{"$..role", []interface{}{"system", "user", "assistant", "user", "user"}},
		{"$..c", []interface{}{1.0}},
		{"$.messages[?(@.role=='system')].content", []interface{}{"be nice"}},
		{`$.messages[?(@.role=="user")].score`, []interface{}{7.0}},
		{"$.messages[?(@.role == 'user' && @.score > 5)].content", []interface{}{"last"}},
		{"$.messages[?(@.score >= 7 || @.role == 'system')].role", []interface{}{"system", "user"}},
		{"$.messages[?(@.score)].role", []interface{}{"user"}},
		{"$.messages[?(!@.score && @.role=='system')].role", []interface{}{"system"}},
		{"$.messages[?(@.role != 'user' && @.role != 'system')].role", []interface{}{"assistant"}},
		{"$.messages[?(@.content == null)].role", []interface{}{"assistant"}},
		{"$.messages[?(@.tool_calls[0].id == '1')].role", []interface{}{"assistant"}},
		{"$.messages[?@.role=='system'].role", []interface{}{"system"}},
		{"$.messages[?((@.role=='system' || @.role=='assistant') && @.content != null)].role", []interface{}{"system"}},
		{"$.choices[0].message.content", []interface{}{"reply"}},
		{"$.choices[0].delta.content", []interface{}{"tok"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := evalPath(t, tc.path)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v\nwant %#v", got, tc.want)
			}
		})
	}
}

func TestJSONPathMissSelectsNothing(t *testing.T) {
	for _, path := range []string{"$.nope", "$.messages[99].content", "$.model.deeper", "$.a.list[0].x", "$.messages[?(@.role=='nobody')].content", "$.nope[*]", "$..nothing", "$.a.list[50:60]", "$.messages[*].nokey"} {
		jp, _ := compileJSONPath(path)
		nodes, err := selectNodes([]byte(pathDoc), jp)
		if err != nil || len(nodes) != 0 {
			t.Errorf("%s: nodes=%v err=%v", path, nodes, err)
		}
	}
}

func TestJSONPathInvalidDocument(t *testing.T) {
	jp, _ := compileJSONPath("$.a")
	if _, err := selectNodes([]byte("not json"), jp); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("err = %v", err)
	}
}

func TestJSONPathCompileErrors(t *testing.T) {
	bad := []string{
		"", "messages", ".a", "$a", "$.", "$..", "$.a.", "$[", "$[]", "$['a'", "$[abc]", "$['a' 'b']",
		"$.a[1,", "$.a[?]", "$.a[?(@.x ==)]", "$.a[?(@.x == 'y']", "$.a[?(@.x == 'y')", "$.a[?('y')]",
		"$.a[?($.x == 1)]", "$.a[?(@.* == 1)]", "$.a[?(@..x == 1)]", "$.a[?(@.x ~ 1)]", "$.a[?(@.x == 1) , 2]",
		"$.a[0:1:2:3]", `$['a\q']`, "$['unterminated", "$.a[?(@.x == tru)]", "$.a[?(@.x == 1 &&)]",
	}
	for _, path := range bad {
		if _, err := compileJSONPath(path); err == nil {
			t.Errorf("compile %q should have failed", path)
		}
	}
}

func TestJSONPathSliceStepZeroSelectsNothing(t *testing.T) {
	if got := evalPath(t, "$.a.list[::0]"); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestJSONPathNodeLimit(t *testing.T) {
	// A wide document is fine; the budget only stops pathological ones.
	items := make([]string, 0, maxPathNodes)
	for i := 0; i < maxPathNodes/2; i++ {
		items = append(items, "1")
	}
	doc := "[" + strings.Join(items, ",") + "]"
	jp, _ := compileJSONPath("$..*")
	if _, err := selectNodes([]byte(doc), jp); err != nil {
		t.Errorf("document under the limit failed: %v", err)
	}
	items = append(items, items...)
	items = append(items, items[:10]...)
	doc = "[" + strings.Join(items, ",") + "]"
	if _, err := selectNodes([]byte(doc), jp); err == nil || !strings.Contains(err.Error(), "node limit") {
		t.Errorf("expected node limit error, got %v", err)
	}
}

func TestJSONPathDeepNestingDoesNotOverflow(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 5000) + `"x"` + strings.Repeat(`}`, 5000)
	jp, _ := compileJSONPath("$..a")
	if _, err := selectNodes([]byte(deep), jp); err != nil && !strings.Contains(err.Error(), "node limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ─── Text collection ────────────────────────────────────────────────────────

func texts(t *testing.T, path string) []string {
	t.Helper()
	jp, err := compileJSONPath(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := extractTexts([]byte(pathDoc), jp, path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

func TestExtractTexts(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"$.messages[-1].content", []string{"last"}},
		{"$.messages[*].content", []string{"be nice", "first", "part one", "part two", "last"}}, // null content and the image part contribute nothing
		{"$.messages[3].content", []string{"part one", "part two"}},
		{"$.messages[3].content[0].text", []string{"part one"}},
		{"$.messages[3]", []string{"part one", "part two"}}, // a whole message: its content is read
		{"$.messages[?(@.role=='user')]", []string{"first", "part one", "part two", "last"}},
		{"$.messages", []string{"be nice", "first", "part one", "part two", "last"}},
		{"$..text", []string{"part one", "part two"}},
		{"$.a.b.c", nil},               // a number is not text
		{"$.messages[2].content", nil}, // null: nothing to check, not an error
		{"$.model", []string{"m"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := texts(t, tc.path)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestExtractTextsEmptyPathMeansWholePayload(t *testing.T) {
	out, err := extractTexts([]byte("plain text body"), nil, "")
	if err != nil || len(out) != 1 || out[0] != "plain text body" {
		t.Errorf("out=%q err=%v", out, err)
	}
}

func TestCollectTextDepthLimit(t *testing.T) {
	var node interface{} = "deep"
	for i := 0; i < maxCollectDepth+5; i++ {
		node = []interface{}{node}
	}
	var out []string
	collectText(node, &out, 0)
	if len(out) != 0 {
		t.Errorf("text below the depth limit was collected: %q", out)
	}
	b, _ := json.Marshal(node)
	jp, _ := compileJSONPath("$")
	if got, err := extractTexts(b, jp, "$"); err != nil || len(got) != 0 {
		t.Errorf("got %q err=%v", got, err)
	}
}

// ─── SSE helpers ────────────────────────────────────────────────────────────

func TestLooksLikeSSE(t *testing.T) {
	yes := []string{"data: {}\n\n", ": keep-alive\n\n", "event: x\ndata: 1\n\n", "\n\ndata: {}\n\n", "id: 3\n", "retry: 10\n", "data:{\"a\":1}\n\n"}
	no := []string{`{"a":1}`, "[1,2]", "plain text", "", "  \n ", "datum: x"}
	for _, s := range yes {
		if !looksLikeSSE(s) {
			t.Errorf("%q should look like SSE", s)
		}
	}
	for _, s := range no {
		if looksLikeSSE(s) {
			t.Errorf("%q should not look like SSE", s)
		}
	}
}

func TestSSEFrameTexts(t *testing.T) {
	jp, _ := compileJSONPath("$.choices[0].delta.content")
	stream := ": keep-alive\n\n" +
		"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" + // role delta: no text
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n" +
		"event: message\r\ndata:{\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\r\n\r\n" + // no space after "data:", CRLF
		"data: not json\n\n" +
		"data: {\"usage\":{\"total_tokens\":3}}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\" wörld\"}}]}\n\n" +
		"data: [DONE]\n\n"
	got := strings.Join(sseFrameTexts(stream, jp), "")
	if got != "Hello wörld" {
		t.Errorf("got %q", got)
	}
}

func TestSSEBoundaryAndPartialHelpers(t *testing.T) {
	if !endsAtSSEEventBoundary([]byte("data: 1\n\n")) || !endsAtSSEEventBoundary([]byte("data: 1\r\n\r\n")) ||
		endsAtSSEEventBoundary([]byte("data: 1\n")) || endsAtSSEEventBoundary([]byte("data: 1")) {
		t.Error("endsAtSSEEventBoundary wrong")
	}
	if c, p := splitTrailingPartialLine("a\nb\nc"); c != "a\nb\n" || p != "c" {
		t.Errorf("got %q %q", c, p)
	}
	if c, p := splitTrailingPartialLine("a\n"); c != "a\n" || p != "" {
		t.Errorf("got %q %q", c, p)
	}
	if c, p := splitTrailingPartialLine("abc"); c != "" || p != "abc" {
		t.Errorf("got %q %q", c, p)
	}
	if !looksLikeJSONDocument([]byte("  \n{")) || !looksLikeJSONDocument([]byte("[1")) || looksLikeJSONDocument([]byte("data:")) || looksLikeJSONDocument(nil) {
		t.Error("looksLikeJSONDocument wrong")
	}
}
