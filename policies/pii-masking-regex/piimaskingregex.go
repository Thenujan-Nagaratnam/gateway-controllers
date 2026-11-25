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

package piimaskingregex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	APIMInternalErrorCode     = 500
	APIMInternalExceptionCode = 900967
	MetadataKeyPIIEntities    = "piimaskingregex:pii_entities"
	DefaultEmailEntityName    = "EMAIL"
	DefaultPhoneEntityName    = "PHONE"
	DefaultSSNEntityName      = "SSN"
	DefaultJSONPath           = "$.messages[-1].content"
	DefaultEmailRegex         = `(?i)\b[a-z0-9.!#$%&'*+/=?^_{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\b`
	TextCleanRegex            = "^\"|\"$"
	DefaultPhoneRegex         = `(?:\+?1[-.\s]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b`
	DefaultSSNRegex           = `(?:00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6(?:[0-57-9][0-9]|6[0-57-9])|[7-8][0-9]{2})[- ]?(?:0[1-9]|[1-9][0-9])[- ]?(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b`

	// SSE constants for streaming responses
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
)

// DefaultStreamingJSONPaths locate the assistant text inside one SSE data frame.
// They are tried in order and the first match wins, so this policy is not bound
// to any single vendor's wire format. A shape that is not listed here is not
// restored: the frame passes through untouched and the client sees the masked
// placeholder, so a new provider format is added by extending this list.
var DefaultStreamingJSONPaths = []string{
	// OpenAI chat completions — also Azure OpenAI, Mistral, Groq, DeepSeek,
	// Together, Fireworks and everything else speaking the OpenAI wire format.
	"$.choices[0].delta.content",
	// Anthropic Messages — content_block_delta carries delta.text.
	"$.delta.text",
	// Google Gemini streamGenerateContent.
	"$.candidates[0].content.parts[0].text",
	// Amazon Bedrock Converse — contentBlockDelta wraps the same delta.text.
	"$.contentBlockDelta.delta.text",
	// Amazon Bedrock (Titan) and Anthropic legacy text completions.
	"$.outputText",
	"$.completion",
	// OpenAI legacy completions.
	"$.choices[0].text",
	// OpenAI Responses API (also Azure OpenAI and Azure AI Foundry /responses)
	// — response.output_text.delta carries the text as a plain string, not an
	// object. Last on purpose: it is the most generic shape here, so every
	// specific path above gets first refusal. Anthropic's delta is an object,
	// and ExtractStringValueFromJsonpath errors on non-scalars, so this cannot
	// steal a match from "$.delta.text".
	"$.delta",
}

// PIIMaskingRegexPolicy implements regex-based PII masking
type PIIMaskingRegexPolicy struct {
	params PIIMaskingRegexPolicyParams
}

type PIIMaskingRegexPolicyParams struct {
	PIIEntities map[string]*regexp.Regexp
	// Builtin marks the entities that come from the email, phone and ssn toggles
	// rather than customPIIEntities. Only those get the digit-boundary check.
	Builtin   map[string]bool
	JsonPath  string
	RedactPII bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &PIIMaskingRegexPolicy{}

	// Parse parameters.
	policyParams, err := parseParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	p.params = policyParams

	return p, nil
}

// Mode returns the processing mode for the PII masking regex policy.
func (p *PIIMaskingRegexPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// parseParams parses and validates parameters from map to struct.
func parseParams(params map[string]interface{}) (PIIMaskingRegexPolicyParams, error) {
	var result PIIMaskingRegexPolicyParams
	result.JsonPath = DefaultJSONPath
	piiEntities := make(map[string]*regexp.Regexp)
	result.Builtin = make(map[string]bool)

	// Extract customPIIEntities parameter if provided.
	piiEntitiesRaw, ok := params["customPIIEntities"]
	if ok {
		// Parse custom PII entities.
		var piiEntitiesArray []map[string]interface{}
		switch v := piiEntitiesRaw.(type) {
		case string:
			if err := json.Unmarshal([]byte(v), &piiEntitiesArray); err != nil {
				return result, fmt.Errorf("error unmarshaling PII entities: %w", err)
			}
		case []interface{}:
			piiEntitiesArray = make([]map[string]interface{}, 0, len(v))
			for idx, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					piiEntitiesArray = append(piiEntitiesArray, itemMap)
				} else {
					return result, fmt.Errorf("'customPIIEntities[%d]' must be an object", idx)
				}
			}
		default:
			return result, fmt.Errorf("'customPIIEntities' must be an array or JSON string")
		}

		// Validate each custom PII entity.
		for i, entityConfig := range piiEntitiesArray {
			piiEntity, ok := entityConfig["piiEntity"].(string)
			if !ok || strings.TrimSpace(piiEntity) == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' is required and must be a non-empty string", i)
			}

			normalizedPIIEntity := strings.ToUpper(strings.TrimSpace(piiEntity))
			if !regexp.MustCompile(`^[A-Z_]+$`).MatchString(normalizedPIIEntity) {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' must contain only letters and underscores", i)
			}

			piiRegex, ok := entityConfig["piiRegex"].(string)
			if !ok || piiRegex == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is required and must be a non-empty string", i)
			}

			compiledPattern, err := regexp.Compile(piiRegex)
			if err != nil {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is invalid: %w", i, err)
			}

			if _, exists := piiEntities[normalizedPIIEntity]; exists {
				return result, fmt.Errorf("duplicate piiEntity: %q", normalizedPIIEntity)
			}
			piiEntities[normalizedPIIEntity] = compiledPattern
		}
	}

	// Extract built-in entity toggles.
	enableEmail, err := parseBoolParam(params, "email")
	if err != nil {
		return result, err
	}
	enablePhone, err := parseBoolParam(params, "phone")
	if err != nil {
		return result, err
	}
	enableSSN, err := parseBoolParam(params, "ssn")
	if err != nil {
		return result, err
	}

	if enableEmail {
		if _, exists := piiEntities[DefaultEmailEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultEmailEntityName)
		}
		piiEntities[DefaultEmailEntityName] = regexp.MustCompile(DefaultEmailRegex)
		result.Builtin[DefaultEmailEntityName] = true
	}
	if enablePhone {
		if _, exists := piiEntities[DefaultPhoneEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultPhoneEntityName)
		}
		piiEntities[DefaultPhoneEntityName] = regexp.MustCompile(DefaultPhoneRegex)
		result.Builtin[DefaultPhoneEntityName] = true
	}
	if enableSSN {
		if _, exists := piiEntities[DefaultSSNEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultSSNEntityName)
		}
		piiEntities[DefaultSSNEntityName] = regexp.MustCompile(DefaultSSNRegex)
		result.Builtin[DefaultSSNEntityName] = true
	}

	if len(piiEntities) == 0 {
		return result, fmt.Errorf("at least one PII detector must be configured using 'customPIIEntities' or one of 'email', 'phone', 'ssn'")
	}
	result.PIIEntities = piiEntities

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional redactPII parameter
	if redactPIIRaw, ok := params["redactPII"]; ok {
		if redactPII, ok := redactPIIRaw.(bool); ok {
			result.RedactPII = redactPII
		} else {
			return result, fmt.Errorf("'redactPII' must be a boolean")
		}
	}

	return result, nil
}

func parseBoolParam(params map[string]interface{}, key string) (bool, error) {
	valRaw, ok := params[key]
	if !ok {
		return false, nil
	}
	val, ok := valRaw.(bool)
	if !ok {
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
	return val, nil
}

// logPIIDetection emits a debug log describing which PII entities matched.
// Only entity names (from policy config) and counts are logged — never the
// matched values, which are the PII this policy exists to keep out of logs.
func (p *PIIMaskingRegexPolicy) logPIIDetection(action string, entityHits map[string]int) {
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	total := 0
	for _, n := range entityHits {
		total += n
	}
	if total == 0 {
		slog.Debug("PIIMaskingRegex: no PII detected",
			"action", action,
			"jsonPath", p.params.JsonPath)
		return
	}
	slog.Debug("PIIMaskingRegex: PII detected",
		"action", action,
		"jsonPath", p.params.JsonPath,
		"entities", entityHits,
		"matchCount", total)
}

// restorePIIInResponse handles PII restoration in responses when redactPII is disabled
func (p *PIIMaskingRegexPolicy) restorePIIInResponse(originalContent string, maskedPIIEntities map[string]string) string {
	if len(maskedPIIEntities) == 0 {
		return originalContent
	}

	transformedContent := originalContent

	for original, placeholder := range maskedPIIEntities {
		if strings.Contains(transformedContent, placeholder) {
			transformedContent = strings.ReplaceAll(transformedContent, placeholder, original)
		}
	}

	return transformedContent
}

// updatePayloadWithMaskedContent updates the original payload by replacing the extracted content
func (p *PIIMaskingRegexPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) ([]byte, bool) {
	if jsonPath == "" || jsonPath == "$" {
		// If no JSONPath, the entire payload was processed, return the modified content
		return []byte(modifiedContent), true
	}

	// If JSONPath is specified, update only the specific field in the JSON structure.
	// Every failure here is reported, never answered with the original payload:
	// that would forward the values that were just found, unmasked.
	jsonData, err := decodeObject(originalPayload)
	if err != nil {
		return nil, false
	}
	if err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent); err != nil {
		return nil, false
	}

	// Numbers were decoded as json.Number and HTML characters are not escaped, so
	// the rest of the document comes back as it went in.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(jsonData); err != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

// decodeAny decodes any JSON document keeping every number as written.
func decodeAny(payload []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(payload, []byte("\xef\xbb\xbf"))))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return v, nil
}

// decodeObject decodes a JSON object keeping every number as written.
func decodeObject(payload []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return m, nil
}

// OnRequestHeaders implements v2alpha.RequestHeaderPolicy.
// PII masking operates on the body, so headers are passed through unchanged.
func (p *PIIMaskingRegexPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders implements v2alpha.ResponseHeaderPolicy.
// PII masking operates on the body, so headers are passed through unchanged.
func (p *PIIMaskingRegexPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody masks PII in the request body before forwarding to upstream.
func (p *PIIMaskingRegexPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	return p.processRequestBody(reqCtx, nil)
}

// processRequestBody masks PII in the request body before forwarding to upstream.
// Placeholders (e.g. [EMAIL_0000]) or redaction markers (*****) replace
// detected PII. Placeholder→original mappings are stored in shared metadata
// so processResponseBody can restore them.
func (p *PIIMaskingRegexPolicy) processRequestBody(reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if len(p.params.PIIEntities) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || reqCtx.Body.Content == nil {
		return policy.UpstreamRequestModifications{}
	}
	payload := reqCtx.Body.Content

	// Whole payload: mask the decoded string values the application's users and
	// tools supplied, and leave every other byte of the request as it was.
	if p.params.JsonPath == "" || p.params.JsonPath == "$" {
		roots, err := parseJSONValues(payload)
		if err != nil {
			// Not JSON, so there is no structure to damage: mask it as text rather
			// than forward it unmasked.
			masked, mapping, changed := p.maskPlainText(string(payload))
			if !changed {
				return policy.UpstreamRequestModifications{}
			}
			p.recordMapping(reqCtx, mapping)
			return policy.UpstreamRequestModifications{Body: []byte(masked)}
		}
		var targets []*node
		for _, root := range roots {
			targets = append(targets, collectTargets(payload, root)...)
		}
		return p.applyMask(reqCtx, payload, targets)
	}

	// A specific path: replace just those values in place.
	if root, err := parseJSON(payload); err == nil {
		// A simple path (names and indexes) is resolved on the scanned document.
		if nodes, ok := resolvePath(root, p.params.JsonPath); ok {
			return p.applyMask(reqCtx, payload, p.selectedTargets(payload, nodes, true))
		}
		// Wildcards, filters, slices and the rest of RFC 9535: the SDK evaluates
		// the query and reports where each match is, and each location is found
		// again on the scanned document so only those bytes are rewritten.
		if q, err := utils.CompileJSONPath(p.params.JsonPath); err == nil {
			return p.processRequestBodyByQuery(reqCtx, payload, root, q)
		}
	}
	return p.processRequestBodyByPath(reqCtx, payload)
}

// selectedTargets turns the nodes a path selected into the string and number
// nodes to mask. An array or an object (a content list of blocks, a tool input)
// has every string inside it masked, so a multimodal message is not forwarded as
// it came. A scalar the path names exactly (explicit) is masked as asked; one that
// a wildcard, filter or descendant segment swept up gets the same protection as in
// the whole-payload mode, so that "$..*" cannot turn max_tokens, a signature or a
// tool-call id into a placeholder.
func (p *PIIMaskingRegexPolicy) selectedTargets(payload []byte, nodes []*node, explicit bool) []*node {
	var targets []*node
	seen := make(map[*node]struct{}, len(nodes))
	walked := make(map[*node]bool)
	add := func(n *node) {
		if _, dup := seen[n]; !dup {
			seen[n] = struct{}{}
			targets = append(targets, n)
		}
	}
	for _, n := range nodes {
		typed := typedContext(payload, n)
		// The object that holds an array is the one that describes its elements
		// (a "data" array next to "format"), so look past arrays.
		parent := n.parent
		for parent != nil && parent.kind == kindArray {
			parent = parent.parent
		}
		switch n.kind {
		case kindString:
			if explicit || !opaqueString(payload, n, n.key, parent) {
				add(n)
			}
		case kindNumber:
			if explicit || (!typed && !typedNumberKeys[n.key]) {
				add(n)
			}
		default:
			// A container selected together with something inside it (as "$..*"
			// does) is already covered when an ancestor was walked: walking it
			// again would visit the same strings once per ancestor.
			covered := false
			for a := n.parent; a != nil; a = a.parent {
				if walked[a] {
					covered = true
					break
				}
			}
			if covered || walked[n] {
				continue
			}
			walked[n] = true
			for _, t := range walkValues(payload, n, n.key, parent, typed, nil) {
				add(t)
			}
		}
	}
	return targets
}

// maxQueryDepth is how deep a document may nest for a jsonPath query: the query
// reports the location of each match as a path as long as the nesting is deep.
// maxQueryWork bounds body size times depth, which is what a descendant query over
// a large, deeply nested body costs in memory.
const (
	maxQueryDepth = 128
	maxQueryWork  = 32_000_000
)

// processRequestBodyByQuery masks every value an RFC 9535 query selects. A query
// that can select several values and selects none masks nothing: there is nothing
// in the request to protect.
func (p *PIIMaskingRegexPolicy) processRequestBodyByQuery(reqCtx *policy.RequestContext, payload []byte, root *node, q *utils.JSONPathQuery) policy.RequestAction {
	if root.hasDupKeys {
		// The query is evaluated on one reading of the document, and parsers disagree
		// about which copy of a repeated key counts. A filter could select by one copy
		// and leave the other unmasked, so such a body is refused.
		return p.buildErrorResponse("request body repeats a JSON key, which a jsonPath query cannot be applied to safely").(policy.RequestAction)
	}
	if root.depth > maxQueryDepth || len(payload)*(root.depth+1) > maxQueryWork {
		return p.buildErrorResponse("request body is nested too deeply for a jsonPath query").(policy.RequestAction)
	}
	doc, err := decodeAny(payload)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("request body could not be read for jsonPath: %v", err)).(policy.RequestAction)
	}
	matches := q.Select(doc)
	if len(matches) == 0 && q.IsSingular() {
		// A path that names one exact place and finds nothing there has always been
		// reported as an error, and still is.
		return p.processRequestBodyByPath(reqCtx, payload)
	}
	var nodes []*node
	for _, m := range matches {
		// A normalized path is only names and indexes, so it resolves exactly.
		found, ok := resolvePath(root, m.Path)
		if !ok {
			return p.buildErrorResponse("jsonPath match could not be located in the request body").(policy.RequestAction)
		}
		nodes = append(nodes, found...)
	}
	return p.applyMask(reqCtx, payload, p.selectedTargets(payload, nodes, q.IsSingular()))
}

// applyMask masks the given nodes of payload and turns the result into an action.
func (p *PIIMaskingRegexPolicy) applyMask(reqCtx *policy.RequestContext, payload []byte, targets []*node) policy.RequestAction {
	out, mapping, changed := p.maskTargets(payload, targets)
	if !changed {
		return policy.UpstreamRequestModifications{}
	}
	p.recordMapping(reqCtx, mapping)
	return policy.UpstreamRequestModifications{Body: out}
}

// recordMapping stores the original→placeholder mapping for the response phase.
func (p *PIIMaskingRegexPolicy) recordMapping(reqCtx *policy.RequestContext, mapping map[string]string) {
	if len(mapping) == 0 {
		return
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]interface{})
	}
	mergePIIMetadata(reqCtx.Metadata, mapping)
}

// processRequestBodyByPath handles a jsonPath the in-place resolver does not
// support (wildcards, filters), through the JSONPath library. The extracted value
// is masked exactly as found: no trimming, no quote stripping.
func (p *PIIMaskingRegexPolicy) processRequestBodyByPath(reqCtx *policy.RequestContext, payload []byte) policy.RequestAction {
	extractedValue, ok, err := extractStringFromPath(payload, p.params.JsonPath)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}
	if !ok {
		// The path selects an array or object that only the general JSONPath
		// library could locate. This policy cannot rewrite it in place, and
		// forwarding it unmasked would leak, so the request is refused.
		return p.buildErrorResponse("jsonPath selects a value that is not a string and cannot be masked in place").(policy.RequestAction)
	}
	masked, mapping, changed := p.maskPlainText(extractedValue)
	if !changed {
		return policy.UpstreamRequestModifications{}
	}
	p.recordMapping(reqCtx, mapping)
	body, ok := p.updatePayloadWithMaskedContent(payload, extractedValue, masked, p.params.JsonPath)
	if !ok {
		return p.buildErrorResponse("jsonPath value could not be replaced with its masked form").(policy.RequestAction)
	}
	return policy.UpstreamRequestModifications{Body: body}
}

// OnResponseBody restores PII placeholders in a buffered response body.
func (p *PIIMaskingRegexPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	return p.processResponseBody(respCtx, nil)
}

// processResponseBody restores PII placeholders in a buffered response body.
//
// Two body formats are handled:
//   - Plain JSON (non-streaming): choices[*].message.content
//   - SSE-buffered (chunked transfer of streaming response that this chain could not
//     process in streaming mode): multiple "data: {...}" lines, choices[*].delta.content.
//     The same restoreSSEChunk logic used by OnResponseBodyChunk is reused here.
func (p *PIIMaskingRegexPolicy) processResponseBody(respCtx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	if p.params.RedactPII {
		return policy.DownstreamResponseModifications{}
	}

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.DownstreamResponseModifications{}
	}

	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.ResponseBody == nil || respCtx.ResponseBody.Content == nil {
		return policy.DownstreamResponseModifications{}
	}

	bodyStr := string(respCtx.ResponseBody.Content)

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	if isSSEChunk(bodyStr) {
		// SSE-buffered: reuse the streaming restoration logic.
		action := p.restoreSSEChunk(bodyStr, restoreMap)
		if action.Body == nil {
			return policy.DownstreamResponseModifications{}
		}
		return policy.DownstreamResponseModifications{Body: action.Body}
	}

	// Plain JSON buffered response: restore placeholders directly in the raw bytes,
	// so key order, whitespace and every other byte stay exactly as the upstream sent
	// them and any provider shape (message content, thinking, tool input) is covered.
	action := p.restoreJSONChunk(bodyStr, restoreMap)
	if action.Body != nil {
		return policy.DownstreamResponseModifications{Body: action.Body}
	}
	return policy.DownstreamResponseModifications{}
}

// ─── Streaming restore ───────────────────────────────────────────
//
// Accumulation is the kernel's job, not the policy's. The policy engine buffers
// response chunks and only hands them to policies once no policy asks for more
// (anyPolicyNeedsMoreResponseData in the policy-engine kernel), and it now does
// that identically on the plain and compressed paths. NeedsMoreResponseData is
// how this policy makes that request, so no cross-chunk state is kept here:
// every flush is restored on its own, statelessly.
//
// What restoration needs is a *complete* placeholder. An LLM emits "[EMAIL_0000]"
// as several tokens ("[", "EMAIL", "_0000", "]"), each in its own SSE event, so a
// flush cut in the middle would match nothing and leak the masked text to the
// client. Waiting until a trailing unclosed "[" is closed is the entire rule.

// maxPlaceholderTailBytes bounds how much assistant text may accumulate after an
// unclosed "[" before it is released regardless of shape. Entity names are
// operator-configurable and so unbounded in principle; without a ceiling, prose
// opening a bracket onto a long uppercase run would buffer to the kernel's
// accumulator limit before anything reached the client. 128 bytes is far past any
// real placeholder — "[CREDIT_CARD_NUMBER_0000]" is 25.
const maxPlaceholderTailBytes = 128

// placeholderTailPattern matches the text after an unclosed "[" when that text
// could still become a placeholder.
//
// Placeholders are built as "[%s_%08x]" with the entity name uppercased, and the
// request side validates them with ^\[[A-Z_]+_[0-9a-f]{8}\]$. The two halves draw
// on disjoint character sets — the name is [A-Z_], the counter is [0-9a-f] — so a
// half-emitted placeholder is exactly a run of the first followed by up to eight
// of the second. Anything else after the bracket (a space, lowercase prose,
// punctuation) proves no placeholder can complete, so the stream is released now.
var placeholderTailPattern = regexp.MustCompile(`^[A-Z_]*[0-9a-f]{0,8}$`)

// couldCompletePlaceholder reports whether content ends in an unclosed "[" whose
// trailing text is still a viable placeholder prefix — that is, whether waiting
// for more data could turn it into something restorable.
//
// This is what replaced counting SSE data events. Whether a placeholder is still
// arriving is a property of the *text*, not of how many frames the upstream split
// it across, so a placeholder emitted one character per event is held exactly as
// long as one emitted whole. An event-count bound could not express that: any
// fixed number is both too small for a finely-tokenised placeholder (it leaks)
// and too large for prose (it stalls).
func couldCompletePlaceholder(content string) bool {
	lastOpen := strings.LastIndex(content, "[")
	if lastOpen == -1 {
		return false
	}
	tail := content[lastOpen+1:]
	if strings.Contains(tail, "]") {
		return false // already closed — a whole placeholder is present
	}
	if len(tail) > maxPlaceholderTailBytes {
		return false
	}
	return placeholderTailPattern.MatchString(tail)
}

// NeedsMoreResponseData implements v2alpha.StreamingResponsePolicy.
//
// For non-SSE (plain JSON) responses delivered via chunked transfer encoding,
// accumulates until the full JSON body is complete and parseable. For SSE,
// accumulates while the assembled assistant text ends in a bracket that could
// still be completing a placeholder.
func (p *PIIMaskingRegexPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	// Redaction is one-way: nothing is restored on the response path, so there is
	// never a reason to hold a chunk back.
	if p.params.RedactPII {
		return false
	}

	s := string(accumulated)

	if !isSSEChunk(s) {
		return !json.Valid([]byte(strings.TrimSpace(s)))
	}

	// A partially-received event carries a partially-received JSON payload, which
	// no JSONPath can be read from. Flushing it would hand the client the first
	// half of a placeholder and restore nothing, so wait for the event terminator.
	if !endsAtSSEEventBoundary(s) {
		return true
	}

	return anyChannelMayComplete(s)
}

// endsAtSSEEventBoundary reports whether s ends on a complete SSE event. Both
// terminators are legal and a CRLF stream contains no "\n\n" at all, so matching
// LF alone would treat every CRLF event as incomplete and buffer the whole
// response to the kernel's accumulator ceiling.
func endsAtSSEEventBoundary(s string) bool {
	return strings.HasSuffix(s, "\n\n") || strings.HasSuffix(s, "\r\n\r\n")
}

// OnResponseBodyChunk implements v2alpha.StreamingResponsePolicy.
// Restores masked PII in a flushed response chunk.
//
// LLMs always use Transfer-Encoding: chunked, so this method handles two formats:
//   - SSE streaming: lines prefixed with "data: ", restores in choices[*].delta.content
//   - Full JSON (non-streaming, chunked transfer): restores in raw JSON bytes
//
// NeedsMoreResponseData guarantees the chunk seen here holds whole placeholders,
// so no state is carried between calls.
func (p *PIIMaskingRegexPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if p.params.RedactPII {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ForwardResponseChunk{}
	}

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.ForwardResponseChunk{}
	}
	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.ForwardResponseChunk{}
	}

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	chunkStr := string(chunk.Chunk)
	if isSSEChunk(chunkStr) {
		return p.restoreSSEChunk(chunkStr, restoreMap)
	}
	return p.restoreJSONChunk(chunkStr, restoreMap)
}

// sseLineBody drops the trailing CR left on every line when a CRLF-delimited
// frame is split on "\n", so field parsing is terminator-agnostic.
func sseLineBody(line string) string {
	return strings.TrimSuffix(line, "\r")
}

// sseDataPayload returns the payload of an SSE "data: " field line and whether
// line is one at all. CR-tolerant, so "data: [DONE]\r" yields "[DONE]".
func sseDataPayload(line string) (string, bool) {
	body := sseLineBody(line)
	if !strings.HasPrefix(body, "data:") {
		return "", false
	}
	// One optional space follows the colon; "data:{...}" is as valid as "data: {...}".
	return strings.TrimPrefix(strings.TrimPrefix(body, "data:"), " "), true
}

// rebuildSSEDataLine reassembles a data line around a rewritten payload,
// preserving the line's original spacing and CR terminator.
func rebuildSSEDataLine(line, payload string) string {
	prefix := sseDataPrefix
	if !strings.HasPrefix(sseLineBody(line), sseDataPrefix) {
		prefix = "data:"
	}
	if strings.HasSuffix(line, "\r") {
		return prefix + payload + "\r"
	}
	return prefix + payload
}

// isSSEFieldLine reports whether line is an SSE field that belongs to the event
// block it precedes. Comments (": keep-alive") are deliberately excluded: they
// are valid standalone and are preserved wherever they appear.
func isSSEFieldLine(line string) bool {
	body := sseLineBody(line)
	return strings.HasPrefix(body, sseEventPrefix) ||
		strings.HasPrefix(body, "id:") ||
		strings.HasPrefix(body, "retry:")
}

// markEventBlockForRemoval marks the whole SSE block owning the data line at
// dataIdx: the field lines immediately preceding it and the blank separator
// terminating it. Dropping only the data line would leave its "event:" line
// orphaned — a block with no data — which is malformed for providers that emit
// a field line per event, Anthropic being the one that does.
func markEventBlockForRemoval(lines []string, dataIdx int, removeLines map[int]bool) {
	removeLines[dataIdx] = true
	// Walk back over this block's field lines. A blank line, a comment, or the
	// preceding event's data line all stop the walk, so no other block is touched.
	for j := dataIdx - 1; j >= 0 && isSSEFieldLine(lines[j]); j-- {
		removeLines[j] = true
	}
	if dataIdx+1 < len(lines) && sseLineBody(lines[dataIdx+1]) == "" {
		removeLines[dataIdx+1] = true
	}
}

// placeholderToken finds a bracketed token that may be a placeholder. Restoring
// reads the text once and looks each token up, so the result never depends on map
// order and an original that itself looks like a placeholder is not expanded again.
var placeholderToken = regexp.MustCompile(`\[[^\[\]\s]+\]`)

// restoreJSONBytes replaces every complete placeholder in s with its
// JSON-escaped original, preserving all other bytes exactly.
func restoreJSONBytes(s string, restoreMap map[string]string) string {
	return placeholderToken.ReplaceAllStringFunc(s, func(tok string) string {
		original, ok := restoreMap[tok]
		if !ok {
			return tok
		}
		enc := encodeJSONString(original)
		return string(enc[1 : len(enc)-1])
	})
}

// ─── SSE / Streaming helpers ─────────────────────────────────────────────────

// isSSEChunk reports whether the chunk looks like SSE data (has at least one "data: " or "event:" line).
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		if strings.HasPrefix(line, "data:") || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// extractFirstDeltaContent parses a single SSE JSON line and returns the
// delta.content value from the first choice, or empty string if absent/empty.
func extractFirstDeltaContent(jsonStr string, paths []string) string {
	content, _ := extractFirstDeltaContentKeyed(jsonStr, paths)
	return content
}

// extractFirstDeltaContentKeyed returns the assistant text carried by one SSE
// data payload along with the JSONPath it was found at, so an in-place rewrite
// can target that same field. Paths are tried in order; the first that yields a
// non-empty string wins.
func extractFirstDeltaContentKeyed(jsonStr string, paths []string) (string, string) {
	for _, path := range paths {
		text, err := utils.ExtractStringValueFromJsonpath([]byte(jsonStr), path)
		if err == nil && text != "" {
			return text, path
		}
	}
	return "", ""
}

// restoreJSONChunk handles full JSON responses delivered via chunked transfer encoding.
// Placeholders are replaced directly in the raw JSON bytes so that key order,
// whitespace, and any trailing newline from the LLM are preserved exactly.
func (p *PIIMaskingRegexPolicy) restoreJSONChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	result := restoreJSONBytes(chunkStr, maskedMap)
	if result == chunkStr {
		return policy.ForwardResponseChunk{}
	}
	return policy.ForwardResponseChunk{Body: []byte(result)}
}

// invertStringMap returns a new map with keys and values swapped.
func invertStringMap(m map[string]string) map[string]string {
	inv := make(map[string]string, len(m))
	for k, v := range m {
		inv[v] = k
	}
	return inv
}

// restore replaces placeholders with their original values.
// maskedMap is placeholder → original.
func restore(content string, maskedMap map[string]string) string {
	return placeholderToken.ReplaceAllStringFunc(content, func(tok string) string {
		if original, ok := maskedMap[tok]; ok {
			return original
		}
		return tok
	})
}

// extractStringFromPath extracts the value at jsonPath from payload as a string.
// Returns (value, true, nil) when the value is a scalar string or number.
// Returns ("", false, nil) when the value exists but is not a scalar (e.g. array/object).
// Returns ("", false, err) on path or parse errors.
func extractStringFromPath(payload []byte, jsonPath string) (string, bool, error) {
	if jsonPath == "" || jsonPath == "$" {
		return string(payload), true, nil
	}
	jsonData, err := decodeObject(payload)
	if err != nil {
		return "", false, err
	}
	raw, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return "", false, err
	}
	switch v := raw.(type) {
	case string:
		return v, true, nil
	case json.Number:
		return v.String(), true, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true, nil
	case int:
		return strconv.Itoa(v), true, nil
	default:
		return "", false, nil
	}
}

func (p *PIIMaskingRegexPolicy) buildErrorResponse(reason string) interface{} {
	responseBody := map[string]interface{}{
		"code":    APIMInternalExceptionCode,
		"message": "Error occurred during pii-masking-regex mediation: " + reason,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(fmt.Sprintf(`{"code":%d,"type":"PII_MASKING_REGEX","message":"Internal error"}`, APIMInternalExceptionCode))
	}

	// For PII masking, errors typically occur in request phase, but return as ImmediateResponse
	return policy.ImmediateResponse{
		StatusCode: APIMInternalErrorCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:    bodyBytes,
		IsFault: true,
		Fault: &policy.FaultDetails{
			Code:      policy.FaultCodeMediationFailed,
			Type:      policy.FaultTypeMediation,
			Direction: policy.DirectionRequest,
			// reason already goes to the client in the body above, so it is client-safe
			// here and belongs in Message. It is NOT moved into Description: Description
			// is for detail a renderer withholds, and putting an already-published string
			// there would misrepresent it as withheld.
			Message: "Error occurred during pii-masking-regex mediation: " + reason,
		},
	}
}
