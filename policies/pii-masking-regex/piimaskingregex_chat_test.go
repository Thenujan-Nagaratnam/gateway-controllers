package piimaskingregex

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func chatPolicy(t *testing.T, extra map[string]interface{}) *PIIMaskingRegexPolicy {
	t.Helper()
	params := map[string]interface{}{"jsonPath": "$"}
	for k, v := range extra {
		params[k] = v
	}
	pol, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatal(err)
	}
	return pol.(*PIIMaskingRegexPolicy)
}

func maskChat(t *testing.T, p *PIIMaskingRegexPolicy, body string) (string, map[string]interface{}) {
	t.Helper()
	ctx := piiRequestContext(body)
	mods, ok := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	if !ok {
		t.Fatal("expected UpstreamRequestModifications")
	}
	if mods.Body == nil {
		return body, ctx.Metadata
	}
	return string(mods.Body), ctx.Metadata
}

func contentOf(t *testing.T, body string, msg int) string {
	t.Helper()
	var d struct{ Messages []struct{ Content string } }
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, body)
	}
	return d.Messages[msg].Content
}

var chatPH = regexp.MustCompile(`\[[A-Z_]+_[0-9a-f]{4}\]`)

func TestChat_EscapeBeforeEmailKeepsJSONValid(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"email": true})
	for _, esc := range []string{`\n`, `\t`, `\r`, `<`, `é`, `\\`, `\"`} {
		out, _ := maskChat(t, p, fmt.Sprintf(`{"messages":[{"role":"user","content":"a%sbob@example.org"}]}`, esc))
		got := contentOf(t, out, 0)
		if strings.Contains(got, "bob@example.org") || !chatPH.MatchString(got) {
			t.Fatalf("escape %s: not masked: %q", esc, got)
		}
		var want string
		_ = json.Unmarshal([]byte(`"a`+esc+`"`), &want)
		if !strings.HasPrefix(got, want) {
			t.Fatalf("escape %s: prefix %q lost, got %q", esc, want, got)
		}
	}
}

func TestChat_ApplicationContentIsNotMasked(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"email": true, "phone": true})
	body := `{"system":"ops@corp.example.org","max_tokens":4155550199,` +
		`"tools":[{"name":"t","description":"mail ops@corp.example.org","input_schema":{"maximum":9007199254740991}}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"mail bob@example.org"},` +
		`{"type":"image","source":{"type":"base64","data":"AAAA4155550199BBBB"}},` +
		`{"type":"thinking","thinking":"ask bob@example.org","signature":"sig4155550199abc"}]},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_4155550199","name":"x","input":{"q":"bob@example.org","n":5}}]}]}`
	out, _ := maskChat(t, p, body)
	for _, keep := range []string{`"ops@corp.example.org"`, `"max_tokens":4155550199`, `"maximum":9007199254740991`, `"data":"AAAA4155550199BBBB"`,
		`"signature":"sig4155550199abc"`, `"id":"toolu_4155550199"`, `"n":5`, `mail ops@corp.example.org`} {
		if !strings.Contains(out, keep) {
			t.Errorf("changed: lost %s\n%s", keep, out)
		}
	}
	if strings.Contains(out, "bob@example.org") {
		t.Errorf("user content not masked: %s", out)
	}
}

func TestChat_NothingToMaskIsForwardedUntouched(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"email": true})
	body := `{ "z":1, "a":[1, 2.50, 3e0], "messages":[{"role":"user","content":"hi <"}] }`
	ctx := piiRequestContext(body)
	if mods := p.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications); mods.Body != nil {
		t.Fatalf("rewritten: %s", mods.Body)
	}
}

func TestChat_NumberLiteralsKeepTheirSpelling(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"email": true})
	out, _ := maskChat(t, p, `{"x":9007199254740993,"y":1.0,"messages":[{"role":"user","content":"bob@example.org"}]}`)
	if !strings.Contains(out, `"x":9007199254740993`) || !strings.Contains(out, `"y":1.0`) {
		t.Fatalf("number spelling changed: %s", out)
	}
}

func TestChat_PlaceholdersAreStable(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"email": true, "phone": true, "ssn": true})
	body := `{"messages":[{"role":"user","content":"a bob@example.org b 415-555-0199 c 123-45-6789"}]}`
	first, _ := maskChat(t, p, body)
	for i := 0; i < 100; i++ {
		if got, _ := maskChat(t, p, body); got != first {
			t.Fatalf("request %d differs", i)
		}
	}
	other, _ := maskChat(t, p, `{"messages":[{"role":"user","content":"zz alice@example.com 123-45-6789 415-555-0199 bob@example.org"}]}`)
	for _, ph := range chatPH.FindAllString(first, -1) {
		if !strings.Contains(other, ph) {
			t.Errorf("%s changed", ph)
		}
	}
}

func TestChat_PhoneNeverCutsALongerNumber(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"phone": true})
	for _, s := range []string{"started 1795104230191", "id 9007199254740991", "pi 3.14159265358"} {
		out, _ := maskChat(t, p, `{"messages":[{"role":"user","content":"`+s+`"}]}`)
		if strings.Contains(out, "[PHONE_") {
			t.Errorf("%q was cut: %s", s, out)
		}
	}
}

func TestChat_InstancesShareTheirMappings(t *testing.T) {
	email := chatPolicy(t, map[string]interface{}{"email": true})
	phone := chatPolicy(t, map[string]interface{}{"phone": true})
	ctx := piiRequestContext(`{"messages":[{"role":"user","content":"bob@example.org 415-555-0199"}]}`)
	m1 := email.OnRequestBody(context.Background(), ctx, nil).(policy.UpstreamRequestModifications)
	ctx.Body.Content = m1.Body
	phone.OnRequestBody(context.Background(), ctx, nil)
	got := ctx.Metadata[MetadataKeyPIIEntities].(map[string]string)
	if got["bob@example.org"] == "" || got["415-555-0199"] == "" {
		t.Fatalf("an instance overwrote the other: %v", got)
	}
}

func sseAnth(events ...string) string {
	var sb strings.Builder
	for _, e := range events {
		var m struct{ Type string }
		_ = json.Unmarshal([]byte(e), &m)
		sb.WriteString("event: " + m.Type + "\ndata: " + e + "\n\n")
	}
	return sb.String()
}

func anthDelta(idx int, kind, field, val string) string {
	v, _ := json.Marshal(val)
	return fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"%s","%s":%s}}`, idx, kind, field, v)
}

func TestChatStream_ToolArgumentsThinkingAndBlocksRestoreSeparately(t *testing.T) {
	p := chatPolicy(t, map[string]interface{}{"email": true})
	mapping := map[string]string{"bob@example.org": "[EMAIL_ab12]"}
	pieces := func(s string, n int) []string {
		var o []string
		for len(s) > n {
			o, s = append(o, s[:n]), s[n:]
		}
		return append(o, s)
	}
	for _, n := range []int{1, 3, 100} {
		var evs []string
		for _, s := range pieces("look [EMAIL_ab12] up", n) {
			evs = append(evs, anthDelta(0, "thinking_delta", "thinking", s))
		}
		for _, s := range pieces("A:[EMAIL_ab12]", n) {
			evs = append(evs, anthDelta(1, "text_delta", "text", s))
		}
		for _, s := range pieces("B:[EMAIL_ab12]", n) {
			evs = append(evs, anthDelta(2, "text_delta", "text", s))
		}
		for _, s := range pieces(`{"e":"[EMAIL_ab12]"}`, n) {
			evs = append(evs, anthDelta(3, "input_json_delta", "partial_json", s))
		}
		stream := sseAnth(evs...)
		for _, cut := range []int{len(stream), 9} {
			out := driveResponseStream(t, p, streamingRespCtx("text/event-stream", mapping), splitEvery(stream, cut))
			got := map[string]string{}
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var ev struct {
					Index int
					Delta map[string]interface{}
				}
				_ = json.Unmarshal([]byte(line[6:]), &ev)
				for _, f := range []string{"text", "thinking", "partial_json"} {
					if s, ok := ev.Delta[f].(string); ok {
						got[fmt.Sprintf("%d:%s", ev.Index, f)] += s
					}
				}
			}
			if got["0:thinking"] != "look bob@example.org up" || got["1:text"] != "A:bob@example.org" ||
				got["2:text"] != "B:bob@example.org" || got["3:partial_json"] != `{"e":"bob@example.org"}` {
				t.Fatalf("n=%d cut=%d: %v", n, cut, got)
			}
		}
	}
}
