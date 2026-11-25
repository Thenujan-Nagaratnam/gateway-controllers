package piimaskingregex

import (
	"context"
	"encoding/json"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"regexp"
	"strings"
	"testing"
	"time"
)

func newPolicy(t *testing.T, params map[string]interface{}) *PIIMaskingRegexPolicy {
	t.Helper()
	pol, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	return pol.(*PIIMaskingRegexPolicy)
}

func rootParams(extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"jsonPath": "$"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// maskBody runs the request phase and returns the upstream body (the input when unchanged)
// and the request metadata.
func maskBody(t *testing.T, p *PIIMaskingRegexPolicy, body string) (string, map[string]interface{}) {
	t.Helper()
	ctx := piiRequestContext(body)
	act := p.OnRequestBody(context.Background(), ctx, nil)
	mods, ok := act.(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestModifications, got %T", act)
	}
	if mods.Body == nil {
		return body, ctx.Metadata
	}
	return string(mods.Body), ctx.Metadata
}

var phRe = regexp.MustCompile(`\[[A-Z_]+_[0-9a-f]{8}\]`)

func TestScanner_SpansDecodeAndMapBack(t *testing.T) {
	src := []byte(`{"a":"x\né😀bob@example.org","n":-1.50e+2,"b":[true,null]}`)
	root, err := parseJSON(src)
	if err != nil {
		t.Fatal(err)
	}
	s := root.get("a")
	d, ok := decodeJSONString(src[s.start:s.end])
	if !ok || d.text != "x\né\U0001F600bob@example.org" {
		t.Fatalf("decode = %q ok=%v", d.text, ok)
	}
	i := strings.Index(d.text, "bob@")
	rs, re := d.rawSpan(i, len(d.text))
	if got := string(src[s.start+rs : s.start+re]); got != "bob@example.org" {
		t.Fatalf("raw span = %q", got)
	}
	// A match that begins right after a multi-byte escape must not cut the escape.
	j := strings.Index(d.text, "\U0001F600") + len("\U0001F600")
	rs, _ = d.rawSpan(j, len(d.text))
	if got := string(src[s.start+rs : s.start+rs+3]); got != "bob" {
		t.Fatalf("span after surrogate pair starts at %q", got)
	}
}

func TestScanner_RejectsInvalid(t *testing.T) {
	for _, bad := range []string{``, `{`, `{"a":}`, `[1,]`, `{"a":"\x"}`, "{\"a\":\"\n\"}", `01`, `1.`, `{"a":1} x`, `"\ud83d`} {
		if _, err := parseJSON([]byte(bad)); err == nil && bad != `"\ud83d` {
			t.Errorf("accepted %q", bad)
		}
	}
	deep := strings.Repeat("[", maxJSONDepth+5) + strings.Repeat("]", maxJSONDepth+5)
	if _, err := parseJSON([]byte(deep)); err == nil {
		t.Error("accepted over-deep input")
	}
}

func TestRequest_EscapeBeforeEmailKeepsJSONValid(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	for _, esc := range []string{`\n`, `\t`, `\r`, `\b`, `\f`, `<`, `é`, `\\`, `\"`} {
		body := fmt.Sprintf(`{"messages":[{"role":"user","content":"a%sbob@example.org"}]}`, esc)
		out, _ := maskBody(t, p, body)
		if !json.Valid([]byte(out)) {
			t.Fatalf("escape %s: invalid JSON %s", esc, out)
		}
		if strings.Contains(out, "bob@example.org") {
			t.Fatalf("escape %s: email leaked: %s", esc, out)
		}
		if !strings.Contains(out, `"a`+esc+`[EMAIL_`) {
			t.Fatalf("escape %s not preserved verbatim: %s", esc, out)
		}
	}
}

func TestRequest_OnlyThePIIBytesChange(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	body := "{ \"z\" : 1, \"a\": [1, 2.50, 3e0],\n \"messages\": [ {\"role\":\"user\", \"content\":\"mail bob@example.org \\u003c ok\"} ] }"
	out, _ := maskBody(t, p, body)
	ph := phRe.FindString(out)
	if ph == "" {
		t.Fatalf("no placeholder in %s", out)
	}
	if got := strings.Replace(out, ph, "bob@example.org", 1); got != body {
		t.Fatalf("not identical outside the PII:\n got %s\nwant %s", got, body)
	}
}

func TestRequest_NoPIIIsByteIdentical(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	body := `{ "model":"m","max_tokens":9007199254740993,"x":1.0,"messages":[{"role":"user","content":"hi<"}]}`
	ctx := piiRequestContext(body)
	mods := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	if mods.Body != nil {
		t.Fatalf("body was rewritten: %s", mods.Body)
	}
	if _, set := ctx.Metadata[MetadataKeyPIIEntities]; set {
		t.Fatal("metadata set without a match")
	}
}

func TestRequest_WholePayloadIsMasked(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	body := `{"model":"claude","max_tokens":4155550199,"system":"ops@corp.example.org",` +
		`"tools":[{"name":"t","description":"mail ops@corp.example.org or 415-555-0199","input_schema":{"maximum":9007199254740991}}],` +
		`"metadata":{"user_id":"bob@example.org"},` +
		`"messages":[{"role":"user","content":[` +
		`{"type":"text","text":"mail bob@example.org"},` +
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA4155550199BBBB"}},` +
		`{"type":"thinking","thinking":"ask bob@example.org","signature":"sig4155550199abc"}]},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_4155550199","name":"x","input":{"q":"bob@example.org","n":5}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_4155550199","content":"found 415-555-0199"}]}]}`
	out, _ := maskBody(t, p, body)
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON: %s", out)
	}
	// Everything a person could read is masked: the system prompt, the tool
	// definitions, the metadata and every message.
	for _, gone := range []string{"ops@corp.example.org", "bob@example.org", "415-555-0199"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s was not masked:\n%s", gone, out)
		}
	}
	// Structure, numbers and signed or binary data are not.
	for _, keep := range []string{`"max_tokens":4155550199`, `"maximum":9007199254740991`, `"n":5`,
		`"data":"AAAA4155550199BBBB"`, `"signature":"sig4155550199abc"`,
		`"id":"toolu_4155550199"`, `"tool_use_id":"toolu_4155550199"`, `"model":"claude"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %s\n%s", keep, out)
		}
	}
}

func TestRequest_OpenAIShapeIsMasked(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	body := `{"model":"m","messages":[{"role":"system","content":"to ops@corp.example.org"},{"role":"user","content":"bob@example.org"},` +
		`{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"to\":\"bob@example.org\"}"}}]}]}`
	out, _ := maskBody(t, p, body)
	if strings.Contains(out, "@example") || strings.Contains(out, "@corp") {
		t.Errorf("not masked: %s", out)
	}
	if !json.Valid([]byte(out)) || !strings.Contains(out, `"id":"c1"`) {
		t.Fatalf("broken output: %s", out)
	}
}

func TestRequest_TypedNumbersKeepTheirType(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true, "email": true}))
	body := `{"max_tokens":4155550199,"tools":[{"a":9007199254740993,"b":1.0,"c":2147483647,"d":1e2,"e":4155550199}],` +
		`"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{"n":4155550199,"who":"bob@example.org","ok":true}}]}]}`
	out, _ := maskBody(t, p, body)
	for _, keep := range []string{`"max_tokens":4155550199`, `"a":9007199254740993,"b":1.0,"c":2147483647,"d":1e2,"e":4155550199`, `"n":4155550199`, `"ok":true`} {
		if !strings.Contains(out, keep) {
			t.Fatalf("a typed number was rewritten, lost %s: %s", keep, out)
		}
	}
	if strings.Contains(out, "bob@example.org") || !json.Valid([]byte(out)) {
		t.Fatalf("string not masked or invalid: %s", out)
	}
}

func TestRequest_NumericPIIIsMaskedAsAValidString(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true}))
	out, _ := maskBody(t, p, `{"customer":{"phone":5552345678,"id":9007199254740991,"score":1.5},"list":[5552345678]}`)
	if !json.Valid([]byte(out)) || strings.Contains(out, "5552345678") {
		t.Fatalf("numeric phone not masked into a valid string: %s", out)
	}
	if !strings.Contains(out, `"id":9007199254740991`) || !strings.Contains(out, `"score":1.5`) {
		t.Fatalf("other numbers rewritten: %s", out)
	}
}

func TestDetectors_PhoneNeverCutsALongerNumber(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true}))
	for _, s := range []string{"started 1795104230191 ok", "id 9007199254740991", "uuid 550e8400-e29b-41d4-a716-446655440000", "pi 3.14159265358"} {
		out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"`+s+`"}]}`)
		if strings.Contains(out, "[PHONE_") {
			t.Errorf("%q was cut: %s", s, out)
		}
	}
	for _, s := range []string{"(415) 555-0199", "415-555-0199", "+1 415 555 0199", "build id 2147483647"} {
		out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"`+s+`"}]}`)
		if !strings.Contains(out, "[PHONE_") {
			t.Errorf("%q not masked: %s", s, out)
		}
	}
}

func TestDetectors_OverlapPrefersTheEarlierLongerMatch(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"4155550199@example.org and 415-555-0199"}]}`)
	if strings.Contains(out, "4155550199") || strings.Contains(out, "example.org") || len(phRe.FindAllString(out, -1)) != 2 {
		t.Fatalf("unexpected masking: %s", out)
	}
	if strings.Contains(out, "][") {
		t.Fatalf("nested placeholder: %s", out)
	}
}

func TestPlaceholders_StableAcrossRequestsAndOrder(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true, "ssn": true}))
	first, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"a bob@example.org b 415-555-0199 c 123-45-6789"}]}`)
	for i := 0; i < 200; i++ {
		got, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"a bob@example.org b 415-555-0199 c 123-45-6789"}]}`)
		if got != first {
			t.Fatalf("request %d differs:\n%s\n%s", i, got, first)
		}
	}
	// Same values, different order and an extra value: each keeps its placeholder.
	other, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"zz alice@example.com 123-45-6789 415-555-0199 bob@example.org"}]}`)
	for _, ph := range phRe.FindAllString(first, -1) {
		if !strings.Contains(other, ph) {
			t.Errorf("placeholder %s changed between requests", ph)
		}
	}
}

func TestPlaceholders_NoCollisionsAndNoDigitsLeak(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	var parts []string
	for i := 0; i < 1500; i++ {
		parts = append(parts, fmt.Sprintf("user%d@example.org", i))
	}
	out, md := maskBody(t, p, `{"messages":[{"role":"user","content":"`+strings.Join(parts, " ")+`"}]}`)
	seen := map[string]bool{}
	for _, ph := range phRe.FindAllString(out, -1) {
		if seen[ph] {
			t.Fatalf("placeholder %s reused for two values", ph)
		}
		seen[ph] = true
	}
	if len(seen) != 1500 || len(md[MetadataKeyPIIEntities].(map[string]string)) != 1500 {
		t.Fatalf("got %d placeholders", len(seen))
	}
}

func TestRequest_RedactModeAndFallbacks(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "redactPII": true}))
	out, md := maskBody(t, p, `{"system":"a@b.co","messages":[{"role":"user","content":"x\nbob@example.org"}]}`)
	if !strings.Contains(out, `"x\n*****"`) || strings.Contains(out, "a@b.co") || len(md) != 0 {
		t.Fatalf("redact result %s md=%v", out, md)
	}
	// Not JSON: masked as text, never forwarded raw.
	out, _ = maskBody(t, newPolicy(t, rootParams(map[string]interface{}{"email": true})), "mail bob@example.org {")
	if strings.Contains(out, "bob@example.org") {
		t.Fatalf("non-JSON body not masked: %s", out)
	}
}

func TestRequest_SpecificPathChangesOnlyThatValue(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true})
	body := "{ \"model\":\"m\", \"n\":9007199254740993, \"messages\":[{\"role\":\"user\",\"content\":\"old a@b.co\"},{\"role\":\"user\",\"content\":\"  \\\"q\\\" bob@example.org  \"}] }"
	out, _ := maskBody(t, p, body)
	ph := phRe.FindString(out)
	if strings.Replace(out, ph, "bob@example.org", 1) != body {
		t.Fatalf("more than the value changed:\n%s", out)
	}
}

// ─── response side ───────────────────────────────────────────────────────────

func TestRequest_SpecificPathMasksInsideArraysAndObjects(t *testing.T) {
	body := `{"system":"ops@corp.example.org","messages":[{"role":"user","content":[` +
		`{"type":"text","text":"a bob@example.org"},` +
		`{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"b amy@example.org"}]},` +
		`{"type":"image","source":{"type":"base64","data":"AAAA"}}]}]}`
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[0].content"})
	out, _ := maskBody(t, p, body)
	if strings.Contains(out, "bob@example.org") || strings.Contains(out, "amy@example.org") {
		t.Fatalf("strings inside the selected array were forwarded: %s", out)
	}
	if !strings.Contains(out, "ops@corp.example.org") || !strings.Contains(out, `"tool_use_id":"t1"`) || !strings.Contains(out, `"data":"AAAA"`) {
		t.Fatalf("outside the path, or opaque, changed: %s", out)
	}
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[0]"})
	out, _ = maskBody(t, p, body)
	if strings.Contains(out, "bob@example.org") || !json.Valid([]byte(out)) {
		t.Fatalf("object at path not masked: %s", out)
	}
}

func TestRequest_SpecificPathNumberAndMissing(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"phone": true, "jsonPath": "$.p"})
	out, _ := maskBody(t, p, `{"p":5552345678,"q":5552345678}`)
	if strings.Contains(out, `"p":5552345678`) || !strings.Contains(out, `"q":5552345678`) || !json.Valid([]byte(out)) {
		t.Fatalf("named number handling wrong: %s", out)
	}
	// A path that matches nothing is refused, as it always was, instead of
	// forwarding a body that was meant to be masked.
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.nothing.here"})
	act := p.OnRequestBody(context.Background(), piiRequestContext(`{"a":"bob@example.org"}`), nil)
	if _, ok := act.(policy.UpstreamRequestModifications); ok {
		t.Fatalf("a path that matches nothing must not forward the body, got %T", act)
	}
}

func TestMetadata_InstancesAddToEachOther(t *testing.T) {
	email := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	phone := newPolicy(t, rootParams(map[string]interface{}{"phone": true}))
	ctx := piiRequestContext(`{"messages":[{"role":"user","content":"bob@example.org 415-555-0199"}]}`)
	m1 := email.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	ctx.Body.Content = m1.Body
	m2 := phone.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	got := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if got["bob@example.org"] == "" || got["415-555-0199"] == "" {
		t.Fatalf("an instance overwrote the other: %v", got)
	}
	if strings.Contains(string(m2.Body), "@example") || strings.Contains(string(m2.Body), "555-0199") {
		t.Fatalf("not fully masked: %s", m2.Body)
	}
}

func TestRequest_KeysAndOpaqueDataAreNeverMasked(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	body := `{"bob@example.org":"v","messages":[{"role":"user","content":[` +
		`{"type":"redacted_thinking","data":"AAAA4155550199bob@example.org"},` +
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA4155550199BBBB"}},` +
		`{"type":"input_audio","input_audio":{"data":"4155550199","format":"wav"}},` +
		`{"type":"text","text":"mail bob@example.org"}]},` +
		`{"role":"assistant","tool_calls":[{"id":"call_4155550199","type":"function","function":{"name":"f","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"call_4155550199","content":"found 415-555-0199"}]}`
	out, _ := maskBody(t, p, body)
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON: %s", out)
	}
	for _, keep := range []string{`"bob@example.org":"v"`, `"data":"AAAA4155550199bob@example.org"`,
		`"url":"data:image/png;base64,AAAA4155550199BBBB"`, `"id":"call_4155550199"`, `"tool_call_id":"call_4155550199"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %s\n%s", keep, out)
		}
	}
	if strings.Contains(out, "mail bob@example.org") || strings.Contains(out, "found 415-555-0199") {
		t.Errorf("text not masked: %s", out)
	}
}

func TestRequest_ThinkingRoundTripMasksToTheSameText(t *testing.T) {
	// The client resends the thinking block with the values restored. Masking it
	// again must give exactly the text the upstream signed the first time.
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	first, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"hi bob@example.org"}]}`)
	again, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"hi bob@example.org"},{"role":"assistant","content":[{"type":"thinking","thinking":"look up bob@example.org","signature":"SIG"}]}]}`)
	ph := phRe.FindString(first)
	if ph == "" || !strings.Contains(again, `"thinking":"look up `+ph+`"`) || !strings.Contains(again, `"signature":"SIG"`) {
		t.Fatalf("thinking text did not mask to the same placeholder:\n%s\n%s", first, again)
	}
}

// ─── regressions found in review ─────────────────────────────────────────────

func TestRequest_BOMNDJSONAndDeepNestingStayValid(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	out, _ := maskBody(t, p, "\ufeff"+`{"a":"x\nbob@example.org"}`)
	if !json.Valid([]byte(strings.TrimPrefix(out, "\ufeff"))) || strings.Contains(out, "bob@example.org") {
		t.Fatalf("BOM body: %s", out)
	}
	// Two documents, one per line: each is masked as JSON, none is spliced as text.
	out, _ = maskBody(t, p, `{"a":"x\nbob@example.org"}`+"\n"+`{"b":"y\tamy@example.org"}`)
	for _, line := range strings.Split(out, "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("a line is not valid JSON: %q in %s", line, out)
		}
	}
	if strings.Contains(out, "@example.org") {
		t.Fatalf("not masked: %s", out)
	}
	// Deeper than the old 512 limit, as deep as encoding/json goes.
	deep := strings.Repeat(`{"a":`, 3000) + `"x\nbob@example.org"` + strings.Repeat(`}`, 3000)
	out, _ = maskBody(t, p, deep)
	if !json.Valid([]byte(out)) || strings.Contains(out, "bob@example.org") {
		t.Fatalf("deep body: %.80s", out)
	}
}

func TestRequest_PlainTextThatStartsLikeJSONIsMaskedAsText(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	for _, body := range []string{`[INFO] contact bob@example.org`, `{x} call 415-555-0199`, `"quoted" then bob@example.org`, `[1,2,3] bob@example.org`, `{"truncated":"bob@example.org`} {
		act := p.OnRequestBody(context.Background(), piiRequestContext(body), nil)
		mods, ok := act.(policy.UpstreamRequestModifications)
		if !ok || strings.Contains(string(mods.Body), "bob@example.org") || strings.Contains(string(mods.Body), "415-555-0199") || mods.Body == nil {
			t.Errorf("plain text %q not masked as text: %T %s", body, act, mods.Body)
		}
	}
}

func TestDetectors_CustomMatchRunningIntoAPlaceholderStillMasksTheRest(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "ALL", "piiRegex": `pw=\S+`}}}))
	out, _ := maskBody(t, p, `{"a":"pw=hunter2[ALL_00000000]"}`)
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret forwarded because a placeholder-like tail followed it: %s", out)
	}
}

func TestPlaceholders_OneValueOneEntityInARequest(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true, "customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "AAA", "piiRegex": `^\d{10}`}}}))
	for i := 0; i < 40; i++ {
		out, md := maskBody(t, p, `{"messages":[{"role":"user","content":["5552345678","a 5552345678"]}]}`)
		if strings.Contains(out, "5552345678") {
			t.Fatalf("not masked: %s", out)
		}
		ph := md[MetadataKeyPIIEntities].(map[string]string)["5552345678"]
		for _, found := range phRe.FindAllString(out, -1) {
			if found != ph {
				t.Fatalf("one value got two placeholders (%s and %s), so one is never restored: %s", ph, found, out)
			}
		}
	}
}

func TestPlaceholders_DoNotDependOnOtherValues(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	solo, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"u240@example.org"}]}`)
	var all []string
	for i := 0; i < 300; i++ {
		all = append(all, fmt.Sprintf("u%d@example.org", i))
	}
	many, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"`+strings.Join(all, " ")+`"}]}`)
	if !strings.Contains(many, phRe.FindString(solo)) {
		t.Fatalf("a value's placeholder changed when 299 other values were present")
	}
}

func TestSSE_DataWithoutSpaceIsRestored(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	got := p.restoreSSEChunk("data:{\"delta\":{\"text\":\"hi [EMAIL_1a2b3c4d]\"}}\n\n", map[string]string{"[EMAIL_1a2b3c4d]": "bob@example.org"})
	if !strings.Contains(string(got.Body), "hi bob@example.org") || !strings.HasPrefix(string(got.Body), "data:{") {
		t.Fatalf("got %q", got.Body)
	}
}

func TestSSE_ResponsesAPIEventKindsDoNotShareAChannel(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	in := "data: {\"type\":\"response.reasoning_summary_text.delta\",\"item_id\":\"r1\",\"delta\":\"thinking \"}\n\n" +
		"data: {\"type\":\"response.output_text.delta\",\"item_id\":\"m1\",\"delta\":\"[EMAIL_1a2b3c4d]\"}\n\n"
	got := string(p.restoreSSEChunk(in, map[string]string{"[EMAIL_1a2b3c4d]": "bob@example.org"}).Body)
	if strings.Contains(got, "thinking bob@example.org") || !strings.Contains(got, `"delta":"thinking "`) || !strings.Contains(got, `"delta":"bob@example.org"`) {
		t.Fatalf("text moved between event kinds: %s", got)
	}
}

func TestRestore_IsOneDeterministicPass(t *testing.T) {
	m := map[string]string{"[A_00000001]": "[B_00000002]", "[B_00000002]": "bob@example.org"}
	for i := 0; i < 50; i++ {
		if got := restore("x [A_00000001] y", m); got != "x [B_00000002] y" {
			t.Fatalf("restore expanded an original that looks like a placeholder: %q", got)
		}
	}
	if got := restoreJSONBytes("a [A_00000001] <b>", map[string]string{"[A_00000001]": `q"&`}); got != `a q\"& <b>` {
		t.Fatalf("got %q", got)
	}
}

func TestScope_ExemptionsAreNotBlanket(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	out, _ := maskBody(t, p, `{"signature":"Regards, bob@example.org","data":"data: amy@example.org","parameters":{"phone":5552345678},"n":5552345678}`)
	for _, gone := range []string{"bob@example.org", "amy@example.org", "5552345678"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s was exempted by key name: %s", gone, out)
		}
	}
	out, _ = maskBody(t, p, `{"signature":"EuYBCkQYAiJA4155550199abc==","messages":[{"role":"user","content":[{"type":"image","source":{"format":"png","data":"AAAA4155550199BBBBCCCC"}}]}]}`)
	if !strings.Contains(out, `"signature":"EuYBCkQYAiJA4155550199abc=="`) || !strings.Contains(out, `"data":"AAAA4155550199BBBBCCCC"`) {
		t.Errorf("opaque token was masked: %s", out)
	}
}

func TestRequest_RepeatedKeyIsMaskedInEveryCopy(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[0].content"})
	out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"a bob@example.org"}],"messages":[{"role":"user","content":"b amy@example.org"}]}`)
	if strings.Contains(out, "bob@example.org") || strings.Contains(out, "amy@example.org") {
		t.Fatalf("a repeated key left one copy unmasked: %s", out)
	}
}

func TestScope_TextDocumentSourceIsMaskedBase64IsNot(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":[`+
		`{"type":"document","source":{"type":"text","media_type":"text/plain","data":"contact bob@example.org"}},`+
		`{"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBERi0bob@example.org"}}]}]}`)
	if strings.Contains(out, "contact bob@example.org") || !strings.Contains(out, `"data":"JVBERi0bob@example.org"`) {
		t.Fatalf("document sources handled wrongly: %s", out)
	}
}

// Item 8 without an SDK change: jsonPath "$.messages" masks the conversation (user
// text, assistant history, tool calls and results, thinking text) and leaves the
// application's own system prompt and tool definitions as they were.
func TestRequest_MessagesPathMasksTheConversationNotTheApplication(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "phone": true, "jsonPath": "$.messages"})
	body := `{"model":"claude","max_tokens":4155550199,"system":"Escalate to ops@corp.example.org",` +
		`"tools":[{"name":"lookup","description":"Mail ops@corp.example.org or call 415-555-0199","input_schema":{"type":"object","maximum":2147483647}}],` +
		`"messages":[{"role":"user","content":"mail bob@example.org"},` +
		`{"role":"assistant","content":[{"type":"thinking","thinking":"ask bob@example.org","signature":"EuYBCkQYAiJA4155550199abc=="},` +
		`{"type":"tool_use","id":"toolu_4155550199","name":"lookup","input":{"q":"bob@example.org","n":4155550199}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_4155550199","content":[{"type":"text","text":"found 415-555-0199"}]},` +
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA4155550199BBBBCCCC"}}]}]}`
	out, md := maskBody(t, p, body)
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON: %s", out)
	}
	for _, keep := range []string{`"system":"Escalate to ops@corp.example.org"`, `Mail ops@corp.example.org or call 415-555-0199`,
		`"max_tokens":4155550199`, `"maximum":2147483647`, `"signature":"EuYBCkQYAiJA4155550199abc=="`,
		`"id":"toolu_4155550199"`, `"tool_use_id":"toolu_4155550199"`, `"n":4155550199`, `"data":"AAAA4155550199BBBBCCCC"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("outside the conversation or opaque, but changed: lost %s\n%s", keep, out)
		}
	}
	var msgs struct {
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(out), &msgs); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"bob@example.org", "415-555-0199"} {
		if strings.Contains(string(msgs.Messages), gone) {
			t.Errorf("%s reached the upstream inside messages: %s", gone, msgs.Messages)
		}
	}
	if m, _ := md[MetadataKeyPIIEntities].(map[string]string); m["bob@example.org"] == "" || m["415-555-0199"] == "" {
		t.Errorf("mapping for the response is incomplete: %v", m)
	}
}

// ─── regressions found against the original policy ──────────────────────────

func TestScope_PIIUnderOpaqueKeyNamesIsStillMasked(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	for _, body := range []string{
		`{"format":"csv","data":"bob@example.org,415-555-0199"}`, `{"mime_type":"text/csv","data":"bob@example.org"}`,
		`{"signature":"bob@example.org"}`, `{"bytes":"bob@example.org"}`, `{"file_data":"415-555-0199"}`,
		`{"encrypted_content":"bob@example.org"}`, `{"tool_call_id":"bob@example.org"}`, `{"tool_use_id":"415-555-0199"}`,
		`{"type":"function","id":"bob@example.org"}`, `{"type":"tool_use","name":"f","id":"415-555-0199"}`,
	} {
		out, _ := maskBody(t, p, body)
		if strings.Contains(out, "bob@example.org") || strings.Contains(out, "415-555-0199") || !json.Valid([]byte(out)) {
			t.Errorf("contact data kept because of its key name: %s -> %s", body, out)
		}
	}
	// Real tokens under the same keys still pass through byte for byte.
	for _, keep := range []string{`"id":"call_4155550199"`, `"tool_call_id":"toolu_01A4155550199xyz"`, `"signature":"EuYBCkQYAiJA4155550199abcdef"`} {
		body := `{"type":"function",` + keep + `}`
		if out, _ := maskBody(t, p, body); out != body {
			t.Errorf("token changed: %s -> %s", body, out)
		}
	}
}

func TestDetectors_PhoneWrittenAsAFloatIsMasked(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true}))
	out, _ := maskBody(t, p, `{"p":4155550199.0,"q":4155550199.50,"r":"4155550199.0","s":"415-555-0199.5","t":"3.14159265358","u":1795104230191.0}`)
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON: %s", out)
	}
	for _, gone := range []string{`4155550199.0,`, `"4155550199.0"`, `415-555-0199`} {
		if strings.Contains(out, gone) {
			t.Errorf("%s was not masked: %s", gone, out)
		}
	}
	for _, keep := range []string{`"q":4155550199.50`, `"t":"3.14159265358"`, `"u":1795104230191.0`} {
		if !strings.Contains(out, keep) {
			t.Errorf("a decimal or longer number was cut, lost %s: %s", keep, out)
		}
	}
}

func TestScope_OnlyRealToolCallsKeepTheirInputTypes(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true}))
	out, _ := maskBody(t, p, `{"name":"Bob","input":{"phone":4155550199}}`)
	if strings.Contains(out, "4155550199") || !json.Valid([]byte(out)) {
		t.Fatalf("a record with a name and an input field is not a tool call: %s", out)
	}
	for _, body := range []string{
		`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01A4155550199xyz","name":"f","input":{"n":4155550199}}]}]}`,
		`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"tu_1abcdef","name":"f","input":{"n":4155550199}}}]}]}`,
	} {
		if out, _ := maskBody(t, p, body); out != body {
			t.Errorf("tool call arguments changed type: %s", out)
		}
	}
}

func TestExportedConstantsOfTheOriginalSurviveTheRewrite(t *testing.T) {
	if TextCleanRegex != "^\"|\"$" || DefaultJSONPath != "$.messages[-1].content" || MetadataKeyPIIEntities != "piimaskingregex:pii_entities" {
		t.Fatal("an exported constant changed")
	}
}

// The integration feature pins these exact placeholders; a change to the hashing
// scheme has to change the feature with it.
func TestPlaceholders_ExactValuesPinnedByTheFeatureFile(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true, "phone": true}))
	out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":"bob@example.org 415-555-0199"}]}`)
	for _, want := range []string{"[EMAIL_9b71a8a4]", "[PHONE_0ccd993b]"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in %s", want, out)
		}
	}
}

// ─── RFC 9535 paths (through the SDK query) ─────────────────────────────────

const rfcChat = `{"model":"claude","system":"Escalate to ops@corp.example.org",` +
	`"tools":[{"name":"lookup","description":"Mail ops@corp.example.org"}],` +
	`"messages":[{"role":"user","content":"mail bob@example.org"},` +
	`{"role":"assistant","content":[{"type":"text","text":"sent to amy@example.org"}]},` +
	`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01A4155550199xyz","content":"found cat@example.org"}]},` +
	`{"role":"tool","content":"dan@example.org"}]}`

func TestRequest_WildcardPathMasksEveryMessageContent(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[*].content"})
	out, _ := maskBody(t, p, rfcChat)
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid JSON: %s", out)
	}
	for _, gone := range []string{"bob@example.org", "amy@example.org", "cat@example.org", "dan@example.org"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s not masked: %s", gone, out)
		}
	}
	// Outside the selection and opaque ids: untouched.
	for _, keep := range []string{"Escalate to ops@corp.example.org", "Mail ops@corp.example.org", `"tool_use_id":"toolu_01A4155550199xyz"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %s: %s", keep, out)
		}
	}
}

func TestRequest_FilterPathSelectsByRole(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[?@.role=='user'].content"})
	out, _ := maskBody(t, p, rfcChat)
	for _, gone := range []string{"bob@example.org", "cat@example.org"} {
		if strings.Contains(out, gone) {
			t.Errorf("user content %s not masked: %s", gone, out)
		}
	}
	for _, keep := range []string{"amy@example.org", "dan@example.org", "ops@corp.example.org"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%s is not user content and must stay: %s", keep, out)
		}
	}
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[?@.role!='assistant'].content"})
	out, _ = maskBody(t, p, rfcChat)
	if strings.Contains(out, "dan@example.org") || strings.Contains(out, "bob@example.org") || !strings.Contains(out, "amy@example.org") {
		t.Errorf("everything but assistant: %s", out)
	}
}

func TestRequest_SlicePathAndDescendantPath(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[-2:].content"})
	out, _ := maskBody(t, p, rfcChat)
	if strings.Contains(out, "cat@example.org") || strings.Contains(out, "dan@example.org") || !strings.Contains(out, "bob@example.org") {
		t.Errorf("last two messages only: %s", out)
	}
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$..text"})
	out, _ = maskBody(t, p, rfcChat)
	if strings.Contains(out, "amy@example.org") || !strings.Contains(out, "bob@example.org") {
		t.Errorf("descendant text only: %s", out)
	}
}

func TestRequest_QueryPathEdgeCases(t *testing.T) {
	// A query that selects nothing masks nothing and is not an error.
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.messages[?@.role=='nobody'].content"})
	if out, _ := maskBody(t, p, rfcChat); out != rfcChat {
		t.Errorf("no match must leave the body alone: %s", out)
	}
	// Keys that need escaping in a normalized path are found again on the document.
	tricky := `{"a]b":{"it's":"x bob@example.org"},"q\"":["amy@example.org"],"é\n":"cat@example.org","keep":"dan@example.org"}`
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$[\"a]b\",\"q\\\"\",\"é\\n\"]"})
	out, _ := maskBody(t, p, tricky)
	for _, gone := range []string{"bob@example.org", "amy@example.org", "cat@example.org"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s not masked: %s", gone, out)
		}
	}
	if !strings.Contains(out, "dan@example.org") || !json.Valid([]byte(out)) {
		t.Errorf("outside the selection changed or invalid: %s", out)
	}
	// A repeated key under a query is refused: parsers disagree about which copy
	// counts, so the body could be read one way by the query and another upstream.
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.m[*].c"})
	act := p.OnRequestBody(context.Background(), piiRequestContext(`{"m":[{"c":"a@b.co"}],"m":[{"c":"x@y.co"}]}`), nil)
	if _, ok := act.(policy.UpstreamRequestModifications); ok {
		t.Errorf("a repeated key under a query must be refused, got %T", act)
	}
	// A path that is neither RFC 9535 nor in the older syntax is refused, not skipped.
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.a b"})
	act = p.OnRequestBody(context.Background(), piiRequestContext(`{"a":"bob@example.org"}`), nil)
	if _, ok := act.(policy.UpstreamRequestModifications); ok {
		t.Errorf("an unusable path must not forward the body: %T", act)
	}
}

// ─── structured values under jsonPath (TypeSafe / Jev shapes, gateway-controllers#320) ──

func TestStructured_ObjectValueHasEveryNestedStringMasked(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})
	out, md := maskBody(t, p, `{"model":"jev-latest","state":{"ticket":"reach me at a.user@example.com","notes":{"cc":"b.user@example.com"},"list":["c.user@example.com",3]}}`)
	for _, gone := range []string{"a.user@example.com", "b.user@example.com", "c.user@example.com"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s not masked: %s", gone, out)
		}
	}
	if got := len(phRe.FindAllString(out, -1)); got != 3 || !json.Valid([]byte(out)) {
		t.Errorf("want 3 placeholders and valid JSON, got %d: %s", got, out)
	}
	if !strings.Contains(out, `"model":"jev-latest"`) || !strings.Contains(out, `,3]`) {
		t.Errorf("outside the path or non-PII values changed: %s", out)
	}
	if m, _ := md[MetadataKeyPIIEntities].(map[string]string); len(m) != 3 {
		t.Errorf("one mapping entry per distinct value: %v", md)
	}
}

func TestStructured_StateMayBeAStringAnObjectOrAnArray(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})
	for _, body := range []string{
		`{"state":"mail a.user@example.com"}`, `{"state":["a.user@example.com",{"x":"a.user@example.com"}]}`,
		`{"state":{"a":{"b":{"c":"a.user@example.com"}}}}`,
	} {
		out, _ := maskBody(t, p, body)
		if strings.Contains(out, "a.user@example.com") || !json.Valid([]byte(out)) {
			t.Errorf("%s -> %s", body, out)
		}
	}
}

func TestStructured_WildcardMatchesShareOnePlaceholderMap(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.questions.*.instructions"})
	out, md := maskBody(t, p, `{"questions":{"a":{"type":"noul","instructions":"Is a.user@example.com urgent?"},"b":{"type":"noul","instructions":"Is b.user@example.com urgent?"},"c":{"type":"noul","instructions":"Again a.user@example.com"}}}`)
	if strings.Contains(out, "@example.com") || !json.Valid([]byte(out)) {
		t.Fatalf("not masked: %s", out)
	}
	m, _ := md[MetadataKeyPIIEntities].(map[string]string)
	if len(m) != 2 || m["a.user@example.com"] == m["b.user@example.com"] {
		t.Fatalf("one entry per distinct email and distinct placeholders: %v", m)
	}
	if strings.Count(out, m["a.user@example.com"]) != 2 {
		t.Errorf("a repeated value must get the same placeholder every time: %s", out)
	}
	if !strings.Contains(out, `"type":"noul"`) {
		t.Errorf("a sibling field changed: %s", out)
	}
	// The whole map of questions, selected with a bare wildcard.
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.questions.*"})
	out, _ = maskBody(t, p, `{"questions":{"a":{"instructions":"a.user@example.com"},"b":{"instructions":"b.user@example.com"}},"keep":"c.user@example.com"}`)
	if strings.Contains(out, "a.user@example.com") || strings.Contains(out, "b.user@example.com") || !strings.Contains(out, "c.user@example.com") {
		t.Errorf("wildcard over a map: %s", out)
	}
}

func TestStructured_MultimodalContentPartsAreMaskedImageURLsAreNot(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true})
	out, _ := maskBody(t, p, `{"messages":[{"role":"user","content":[{"type":"text","text":"mail a.user@example.com"},{"type":"image_url","image_url":{"url":"https://example.com/cat.png"}}]}]}`)
	if strings.Contains(out, "a.user@example.com") || !phRe.MatchString(out) || !strings.Contains(out, "https://example.com/cat.png") {
		t.Errorf("default path over a block array: %s", out)
	}
}

func TestStructured_NumericLeafIsMaskedOtherNumbersStayNumbers(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"ssn": true, "jsonPath": "$.state"})
	out, _ := maskBody(t, p, `{"state":{"applicant":{"ssn":123456789,"age":42}}}`)
	if strings.Contains(out, "123456789") || !strings.Contains(out, `"age":42`) || !json.Valid([]byte(out)) {
		t.Errorf("numeric SSN: %s", out)
	}
}

func TestStructured_RedactKeepsTheShapeAndStoresNoMapping(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "redactPII": true, "jsonPath": "$.state"})
	out, md := maskBody(t, p, `{"state":{"ticket":"reach me at a.user@example.com","status":"open"}}`)
	if strings.Contains(out, "a.user@example.com") || !strings.Contains(out, "*****") || !strings.Contains(out, `"status":"open"`) {
		t.Errorf("redact: %s", out)
	}
	if _, set := md[MetadataKeyPIIEntities]; set {
		t.Error("redact mode must not store a restore mapping")
	}
}

func TestStructured_ObjectWithoutPIIIsLeftAlone(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})
	body := `{"state":{"ticket":"no pii here","count":3}}`
	ctx := piiRequestContext(body)
	mods := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	if mods.Body != nil {
		t.Errorf("expected no modification, got %s", mods.Body)
	}
}

func TestStructured_MaskedValuesAreRestoredInTheResponse(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.state"})
	reqCtx := piiRequestContext(`{"state":{"ticket":"reach me at a.user@example.com"}}`)
	p.OnRequestBody(context.Background(), reqCtx, nil)
	ph := reqCtx.Metadata[MetadataKeyPIIEntities].(map[string]string)["a.user@example.com"]
	respCtx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{RequestID: "r", Metadata: reqCtx.Metadata},
		ResponseBody:  &policy.Body{Content: []byte(`{"answers":{"note":"contact ` + ph + `"}}`), Present: true},
	}
	mods, ok := p.OnResponseBody(context.Background(), respCtx, nil).(policy.DownstreamResponseModifications)
	if !ok || !strings.Contains(string(mods.Body), `"note":"contact a.user@example.com"`) {
		t.Errorf("not restored: %s", mods.Body)
	}
}

func TestStructured_AFailedWriteBackNeverForwardsTheOriginal(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true})
	out, ok := p.updatePayloadWithMaskedContent([]byte(`not json a.user@example.com`), "a.user@example.com", "[EMAIL_00000000]", "$.messages[-1].content")
	if ok || out != nil {
		t.Errorf("a payload that cannot be rewritten must be an error, not the original: ok=%v %s", ok, out)
	}
}

// ─── regressions found in review of the query path ──────────────────────────

func TestQueryPath_SweptUpScalarsKeepTheirProtections(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"phone": true, "email": true, "jsonPath": "$..*"})
	body := `{"max_tokens":5552345678,"seed":5552345678,"tool_use_id":"call_5552345678","tools":[{"max":5552345678}],` +
		`"messages":[{"role":"user","content":"call 415-555-0199 or bob@example.org"}]}`
	out, _ := maskBody(t, p, body)
	for _, keep := range []string{`"max_tokens":5552345678`, `"seed":5552345678`, `"tool_use_id":"call_5552345678"`, `"max":5552345678`} {
		if !strings.Contains(out, keep) {
			t.Errorf("a typed number or an id was rewritten, lost %s: %s", keep, out)
		}
	}
	if strings.Contains(out, "415-555-0199") || strings.Contains(out, "bob@example.org") || !json.Valid([]byte(out)) {
		t.Errorf("message text not masked: %s", out)
	}
	// A scalar the path names exactly is masked as asked.
	p = newPolicy(t, map[string]interface{}{"phone": true, "jsonPath": "$.seed"})
	if out, _ := maskBody(t, p, `{"seed":5552345678}`); strings.Contains(out, "5552345678") {
		t.Errorf("an explicitly named number must be masked: %s", out)
	}
	// An object selected by name keeps its typed numbers too.
	p = newPolicy(t, map[string]interface{}{"phone": true, "email": true, "jsonPath": "$.tools"})
	out, _ = maskBody(t, p, `{"tools":[{"max":5552345678,"description":"mail bob@example.org"}]}`)
	if !strings.Contains(out, `"max":5552345678`) || strings.Contains(out, "bob@example.org") {
		t.Errorf("$.tools: %s", out)
	}
}

func TestQueryPath_RepeatedKeyInABodyIsRefusedNotLeaked(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.m[?@.r=='user'].c"})
	body := `{"m":[{"r":"user","c":"x@y.co","r":"sys"}]}`
	act := p.OnRequestBody(context.Background(), piiRequestContext(body), nil)
	if mods, ok := act.(policy.UpstreamRequestModifications); ok {
		t.Fatalf("a filter over a repeated key must not forward the body: %s", mods.Body)
	}
	// A simple path covers every copy of a repeated key, as before.
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.m[0].c"})
	if out, _ := maskBody(t, p, `{"m":[{"c":"a@b.co","c":"x@y.co"}]}`); strings.Contains(out, "a@b.co") || strings.Contains(out, "x@y.co") {
		t.Errorf("repeated key under a simple path: %s", out)
	}
}

func TestQueryPath_DeepAndWideBodiesAreCheap(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$..*"})
	deep := strings.Repeat("[", 5000) + `"bob@example.org"` + strings.Repeat("]", 5000)
	start := time.Now()
	act := p.OnRequestBody(context.Background(), piiRequestContext(deep), nil)
	if _, ok := act.(policy.UpstreamRequestModifications); ok {
		t.Error("a body nested this deep must be refused for a descendant query")
	}
	var wide strings.Builder
	wide.WriteString(`{`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			wide.WriteString(",")
		}
		fmt.Fprintf(&wide, `"k%d":"u%d@example.org"`, i, i)
	}
	wide.WriteString(`}`)
	p = newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$.*"})
	out, _ := maskBody(t, p, wide.String())
	if strings.Contains(out, "@example.org") || !json.Valid([]byte(out)) {
		t.Error("wide object not masked")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("deep and wide bodies took %v", d)
	}
}

// ─── regressions found in the final review ──────────────────────────────────

func TestQueryPath_DescendantQueryDoesNotRepeatWorkPerAncestor(t *testing.T) {
	big := strings.Repeat("x", 250_000) + " bob@example.org"
	body := strings.Repeat("[", 100) + `"` + big + `"` + strings.Repeat("]", 100)
	timeIt := func(params map[string]interface{}) (time.Duration, string, map[string]interface{}) {
		p := newPolicy(t, params)
		start := time.Now()
		out, md := maskBody(t, p, body)
		return time.Since(start), out, md
	}
	whole, wOut, _ := timeIt(rootParams(map[string]interface{}{"email": true}))
	query, qOut, md := timeIt(map[string]interface{}{"email": true, "jsonPath": "$..*"})
	if strings.Contains(qOut, "bob@example.org") || qOut != wOut {
		t.Fatalf("the query result must equal the whole-payload result")
	}
	// Scanning the string once per ancestor would make this about 100 times slower.
	if query > 15*whole+300*time.Millisecond {
		t.Errorf("$..* took %v against %v for $: the string is scanned once per ancestor", query, whole)
	}
	if m, _ := md[MetadataKeyPIIEntities].(map[string]string); len(m) != 1 {
		t.Errorf("one value, one mapping: %v", m)
	}
}

func TestQueryPath_LargeDeepBodiesAreRefusedBeforeTheyCostMemory(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "$..*"})
	// ~1 MB of numbers at depth 100: the paths of its 500,000 matches would take gigabytes.
	flat := "[" + strings.Repeat("1,", 500000) + "1]"
	body := strings.Repeat("[", 100) + flat + strings.Repeat("]", 100)
	act := p.OnRequestBody(context.Background(), piiRequestContext(body), nil)
	if _, ok := act.(policy.UpstreamRequestModifications); ok {
		t.Fatal("a body this large and this deep must be refused for a descendant query")
	}
	// The same body is fine for the whole-payload mode.
	whole := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	if _, ok := whole.OnRequestBody(context.Background(), piiRequestContext(body), nil).(policy.UpstreamRequestModifications); !ok {
		t.Fatal("$ must still handle it")
	}
}

func TestLegacyPath_TrailingDataIsRefusedNotDropped(t *testing.T) {
	p := newPolicy(t, map[string]interface{}{"email": true, "jsonPath": "a"})
	for _, body := range []string{`{"a":"bob@example.org"}` + "\n" + `{"b":"cat@example.org"}`, `{"a":"bob@example.org"} trailing`} {
		act := p.OnRequestBody(context.Background(), piiRequestContext(body), nil)
		if mods, ok := act.(policy.UpstreamRequestModifications); ok {
			t.Errorf("trailing data must not be silently dropped: %s -> %s", body, mods.Body)
		}
	}
}

func TestScanner_GetIsFastOnObjectsWithManyRepeatedKeys(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"type":"x"`)
	for i := 0; i < 40000; i++ {
		sb.WriteString(`,"data":"hello"`)
	}
	sb.WriteString(`}`)
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	start := time.Now()
	maskBody(t, p, sb.String())
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("40,000 repeated keys took %v: key lookups are not using the index", d)
	}
}

func TestQueryPath_ArrayValuedDataFollowsItsSiblingsLikeTheWholePayloadMode(t *testing.T) {
	body := `{"format":"wav","data":["AAAAAAAAAAAAAAAA4155550199"]}`
	whole := newPolicy(t, rootParams(map[string]interface{}{"phone": true}))
	query := newPolicy(t, map[string]interface{}{"phone": true, "jsonPath": "$..*"})
	a, _ := maskBody(t, whole, body)
	b, _ := maskBody(t, query, body)
	if a != b {
		t.Errorf("$ and $..* disagree:\n$     %s\n$..*  %s", a, b)
	}
}
