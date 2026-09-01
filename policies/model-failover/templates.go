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

package modelfailover

import (
	"encoding/json"
	"fmt"
)

// templateAdapter converts a request body already in the primary's (this POC: OpenAI
// chat-completions) shape into a fallback target's own wire format, and converts that
// target's response back — so the client never observes that failover crossed a template
// boundary. One adapter per template, reused by every fallback declaring it (O(n) adapters,
// not O(n²) pairwise translators — see the design discussion this POC implements).
//
// POC scope: plain string message content only. Multi-part content (images, tool calls,
// tool results) does not round-trip through either direction below and returns an error
// instead of silently dropping data — see ToTarget/FromTarget.
type templateAdapter interface {
	// ToTarget converts body (OpenAI-shaped, with "model" already set to the fallback's own
	// model name by the caller) into this template's request bytes.
	ToTarget(body map[string]interface{}) ([]byte, error)
	// FromTarget converts a response already received from this template's backend back into
	// OpenAI chat-completion response bytes.
	FromTarget(body []byte) ([]byte, error)
	// RequiredHeaders returns protocol headers this template always needs on the outbound
	// request (e.g. Anthropic's anthropic-version), independent of whatever auth resolver is
	// configured for the fallback.
	RequiredHeaders() map[string]string
}

// templateAdapters is keyed by the SAME transformer-policy-name convention
// additionalProviders[].transformer.type already uses on the platform (e.g.
// "openai-to-anthropic-transformer", the real shipped policy name) — not an
// ad hoc vendor string — so a fallback's resolvedTransformerType (gateway-controller-
// injected, see llm_transformer.go) maps directly with no translation step. Extending to a new
// provider is additive: implement templateAdapter and register it here under that provider's
// own transformer-policy name — nothing else in this package changes.
var templateAdapters = map[string]templateAdapter{
	"openai-to-anthropic-transformer": anthropicAdapter{},
}

// ─── anthropic ───────────────────────────────────────────────────────────────

const anthropicDefaultMaxTokens = 1024

type anthropicAdapter struct{}

func (anthropicAdapter) RequiredHeaders() map[string]string {
	return map[string]string{"anthropic-version": "2023-06-01"}
}

// ToTarget maps OpenAI's {model, messages:[{role,content}], max_tokens, temperature} onto
// Anthropic's {model, system, messages:[{role,content}], max_tokens, temperature}. A
// system-role message has no equivalent slot in Anthropic's messages array — its content is
// lifted into the top-level "system" field instead (multiple system messages are joined).
func (anthropicAdapter) ToTarget(body map[string]interface{}) ([]byte, error) {
	model, _ := body["model"].(string)
	rawMessages, _ := body["messages"].([]interface{})
	if rawMessages == nil {
		return nil, fmt.Errorf("anthropic adapter: request body has no messages array")
	}

	var systemParts []string
	messages := make([]map[string]interface{}, 0, len(rawMessages))
	for i, raw := range rawMessages {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("anthropic adapter: messages[%d] is not an object", i)
		}
		role, _ := m["role"].(string)
		content, ok := m["content"].(string)
		if !ok {
			return nil, fmt.Errorf("anthropic adapter: messages[%d].content is not a plain string (multi-part content is not supported by this adapter)", i)
		}
		if role == "system" {
			systemParts = append(systemParts, content)
			continue
		}
		messages = append(messages, map[string]interface{}{"role": role, "content": content})
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("anthropic adapter: request has no non-system messages")
	}

	maxTokens := anthropicDefaultMaxTokens
	if v, ok := toInt(body["max_tokens"]); ok && v > 0 {
		maxTokens = v
	}

	out := map[string]interface{}{
		"model":      model,
		"messages":   messages,
		"max_tokens": maxTokens,
	}
	if len(systemParts) > 0 {
		system := systemParts[0]
		for _, p := range systemParts[1:] {
			system += "\n\n" + p
		}
		out["system"] = system
	}
	if t, ok := body["temperature"]; ok {
		out["temperature"] = t
	}
	if p, ok := body["top_p"]; ok {
		out["top_p"] = p
	}

	return json.Marshal(out)
}

// anthropicResponse mirrors just the fields this adapter needs from Anthropic's Messages API
// response shape.
type anthropicResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// FromTarget maps an Anthropic response back onto an OpenAI-shaped chat.completion response.
// Only text content blocks are concatenated into the reply — a response containing a
// tool_use block (no text content at all) is reported as an error rather than silently
// returning an empty message, since that would look like a successful-but-empty reply to the
// client instead of the adapter gap it actually is.
func (anthropicAdapter) FromTarget(body []byte) ([]byte, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("anthropic adapter: parsing response: %w", err)
	}

	text := ""
	for _, block := range resp.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}
	if text == "" {
		return nil, fmt.Errorf("anthropic adapter: response has no text content block (e.g. a tool_use-only response is not supported by this adapter)")
	}

	out := map[string]interface{}{
		"id":     resp.ID,
		"object": "chat.completion",
		"model":  resp.Model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": text,
				},
				"finish_reason": anthropicStopReasonToOpenAI(resp.StopReason),
			},
		},
		"usage": map[string]interface{}{
			"prompt_tokens":     resp.Usage.InputTokens,
			"completion_tokens": resp.Usage.OutputTokens,
			"total_tokens":      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}
	return json.Marshal(out)
}

func anthropicStopReasonToOpenAI(reason string) string {
	switch reason {
	case "max_tokens":
		return "length"
	case "stop_sequence", "end_turn":
		return "stop"
	default:
		return "stop"
	}
}
