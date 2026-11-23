package piimaskingregex

import (
	"context"
	"encoding/json"
	"fmt"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"strings"
	"testing"
)

func anthropicSSE(events ...string) string {
	var sb strings.Builder
	for _, e := range events {
		var m struct{ Type string }
		_ = json.Unmarshal([]byte(e), &m)
		sb.WriteString("event: " + m.Type + "\ndata: " + e + "\n\n")
	}
	return sb.String()
}

func delta(idx int, kind, field, val string) string {
	v, _ := json.Marshal(val)
	return fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"%s","%s":%s}}`, idx, kind, field, v)
}

func collect(t *testing.T, out string) map[string]string {
	t.Helper()
	res := map[string]string{}
	for _, blk := range strings.Split(out, "\n\n") {
		for _, line := range strings.Split(blk, "\n") {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var ev struct {
				Index int
				Delta map[string]interface{}
			}
			if json.Unmarshal([]byte(line[6:]), &ev) != nil || ev.Delta == nil {
				continue
			}
			for _, f := range []string{"text", "thinking", "partial_json"} {
				if s, ok := ev.Delta[f].(string); ok {
					res[fmt.Sprintf("%d:%s", ev.Index, f)] += s
				}
			}
		}
	}
	return res
}

func TestStream_ToolArgumentsThinkingAndBlocksRestoreSeparately(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	mapping := map[string]string{"bob@example.org": "[EMAIL_ab12]", `a"b\c@x.org`: "[EMAIL_cd34]"}
	pieces := func(s string, n int) []string {
		var o []string
		for len(s) > n {
			o, s = append(o, s[:n]), s[n:]
		}
		return append(o, s)
	}
	for _, n := range []int{1, 2, 3, 5, 100} {
		var evs []string
		evs = append(evs, `{"type":"message_start","message":{"id":"m"}}`)
		evs = append(evs, `{"type":"content_block_start","index":0,"content_block":{"type":"thinking"}}`)
		for _, s := range pieces("look up [EMAIL_ab12] now", n) {
			evs = append(evs, delta(0, "thinking_delta", "thinking", s))
		}
		evs = append(evs, delta(0, "signature_delta", "signature", "sig4155550199"), `{"type":"content_block_stop","index":0}`)
		evs = append(evs, `{"type":"content_block_start","index":1,"content_block":{"type":"text"}}`)
		for _, s := range pieces("A:[EMAIL_ab12]", n) {
			evs = append(evs, delta(1, "text_delta", "text", s))
		}
		evs = append(evs, `{"type":"content_block_stop","index":1}`, `{"type":"content_block_start","index":2,"content_block":{"type":"text"}}`)
		for _, s := range pieces("B:[EMAIL_ab12]", n) {
			evs = append(evs, delta(2, "text_delta", "text", s))
		}
		evs = append(evs, `{"type":"content_block_stop","index":2}`, `{"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_1","name":"f","input":{}}}`,
			delta(3, "input_json_delta", "partial_json", ""))
		for _, s := range pieces(`{"e":"[EMAIL_ab12]","f":"[EMAIL_cd34]"}`, n) {
			evs = append(evs, delta(3, "input_json_delta", "partial_json", s))
		}
		evs = append(evs, `{"type":"content_block_stop","index":3}`, `{"type":"message_stop"}`)
		stream := anthropicSSE(evs...)
		for _, cut := range []int{len(stream), 7, 41} {
			out := driveResponseStream(t, p, streamingRespCtx("text/event-stream", mapping), splitEvery(stream, cut))
			got := collect(t, out)
			if got["0:thinking"] != "look up bob@example.org now" || got["1:text"] != "A:bob@example.org" || got["2:text"] != "B:bob@example.org" {
				t.Fatalf("n=%d cut=%d wrong text/thinking: %v", n, cut, got)
			}
			var args map[string]string
			if err := json.Unmarshal([]byte(got["3:partial_json"]), &args); err != nil || args["e"] != "bob@example.org" || args["f"] != `a"b\c@x.org` {
				t.Fatalf("n=%d cut=%d tool arguments wrong: %q err=%v", n, cut, got["3:partial_json"], err)
			}
			if !strings.Contains(out, "sig4155550199") || !strings.Contains(out, `"type":"message_stop"`) || strings.Contains(out, "[EMAIL_") {
				t.Fatalf("n=%d cut=%d envelope wrong:\n%s", n, cut, out)
			}
		}
	}
}

func TestStream_NoPlaceholderIsByteIdentical(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	stream := anthropicSSE(`{"type":"message_start","message":{"id":"m"}}`, delta(0, "text_delta", "text", "plain [x] text"), `{"type":"message_stop"}`)
	out := driveResponseStream(t, p, streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_ab12]"}), splitEvery(stream, 9))
	if out != stream {
		t.Fatalf("changed:\n%s", out)
	}
}

func TestStream_OpenAIToolCallArgumentsRestore(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	mk := func(args string) string {
		a, _ := json.Marshal(args)
		return `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":` + string(a) + `}}]}}]}` + "\n\n"
	}
	stream := mk(`{"e":"[EMA`) + mk(`IL_ab12]"}`) + "data: [DONE]\n\n"
	out := driveResponseStream(t, p, streamingRespCtx("text/event-stream", map[string]string{"bob@example.org": "[EMAIL_ab12]"}), splitEvery(stream, 11))
	if !strings.Contains(out, `bob@example.org`) || strings.Contains(out, "[EMAIL_") || !strings.Contains(out, "[DONE]") {
		t.Fatalf("wrong output: %s", out)
	}
}

func TestResponse_BufferedJSONRestoredInPlace(t *testing.T) {
	p := newPolicy(t, rootParams(map[string]interface{}{"email": true}))
	body := `{"b":1,"content":[{"type":"text","text":"hi [EMAIL_ab12]"},{"type":"tool_use","input":{"e":"[EMAIL_ab12]"}}],"a":2.0}`
	ctx := &policy.ResponseContext{
		SharedContext: &policy.SharedContext{Metadata: map[string]interface{}{MetadataKeyPIIEntities: map[string]string{"bob@example.org": "[EMAIL_ab12]"}}},
		ResponseBody:  &policy.Body{Content: []byte(body), Present: true},
	}
	mods := p.OnResponseBody(context.Background(), ctx, nil).(policy.DownstreamResponseModifications)
	want := strings.ReplaceAll(body, "[EMAIL_ab12]", "bob@example.org")
	if string(mods.Body) != want {
		t.Fatalf("got %s", mods.Body)
	}
}
