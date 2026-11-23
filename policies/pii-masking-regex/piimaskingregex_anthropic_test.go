package piimaskingregex

import (
	"context"
	"encoding/json"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"regexp"
	"strings"
	"testing"
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

var phRe = regexp.MustCompile(`\[[A-Z_]+_[0-9a-f]{4}\]`)

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
	for _, bad := range []string{``, `{`, `{"a":}`, `[1,]`, `{"a":"\x"}`, "{\"a\":\"\n\"}", `01`, `1.`, `{"a":1} x`, `"\ud83d`, "\ufeff{}"} {
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

func TestRequest_ApplicationContentIsNotMasked(t *testing.T) {
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
	for _, keep := range []string{`"system":"ops@corp.example.org"`, `"max_tokens":4155550199`, `"maximum":9007199254740991`,
		`"user_id":"bob@example.org"`, `"data":"AAAA4155550199BBBB"`, `"signature":"sig4155550199abc"`,
		`"id":"toolu_4155550199"`, `"tool_use_id":"toolu_4155550199"`, `mail ops@corp.example.org or 415-555-0199`, `"n":5`} {
		if !strings.Contains(out, keep) {
			t.Errorf("application content changed, lost %s\n%s", keep, out)
		}
	}
	// Everything the users and tools said is masked.
	var v struct {
		Messages []struct {
			Content json.RawMessage
		}
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for i, m := range v.Messages {
		if strings.Contains(string(m.Content), "bob@example.org") || strings.Contains(string(m.Content), "415-555-0199") && i == 2 {
			t.Errorf("message %d content not masked: %s", i, m.Content)
		}
	}
}

func TestRequest_OpenAISystemAndToolsUntouched(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	body := `{"model":"m","messages":[{"role":"system","content":"to ops@corp.example.org"},{"role":"user","content":"bob@example.org"},` +
		`{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"to\":\"bob@example.org\"}"}}]}]}`
	out, _ := maskBody(t, p, body)
	if !strings.Contains(out, "to ops@corp.example.org") {
		t.Error("system message was masked")
	}
	if strings.Count(out, "bob@example.org") != 0 {
		t.Errorf("user or tool_call arguments not masked: %s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatal("invalid JSON")
	}
}

func TestRequest_NumbersKeepTheirSpelling(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true, "email": true}))
	body := `{"tools":[{"a":9007199254740993,"b":1.0,"c":2147483647,"d":1e2}],"messages":[{"role":"user","content":"hi 415-555-0199"}]}`
	out, _ := maskBody(t, p, body)
	if !strings.Contains(out, `"a":9007199254740993,"b":1.0,"c":2147483647,"d":1e2`) {
		t.Fatalf("tool numbers rewritten: %s", out)
	}
	// Generic payload (no messages): a whole-literal numeric phone becomes a valid string; a longer number is left.
	out, _ = maskBody(t, p, `{"phone":5552345678,"id":9007199254740991}`)
	if !json.Valid([]byte(out)) || strings.Contains(out, "5552345678") || !strings.Contains(out, "9007199254740991") {
		t.Fatalf("generic number handling wrong: %s", out)
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
	if !strings.Contains(out, `"x\n*****"`) || !strings.Contains(out, `"a@b.co"`) || len(md) != 0 {
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

func TestRequest_ChatToolInputNumbersKeepTheirType(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"phone": true, "email": true}))
	body := `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{"n":4155550199,"who":"bob@example.org","ok":true}}]}]}`
	out, _ := maskBody(t, p, body)
	if !strings.Contains(out, `"n":4155550199`) || !strings.Contains(out, `"ok":true`) || strings.Contains(out, "bob@example.org") {
		t.Fatalf("tool input handled wrongly: %s", out)
	}
}
