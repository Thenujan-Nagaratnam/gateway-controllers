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
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	APIMInternalErrorCode     = 500
	APIMInternalExceptionCode = 900967
	TextCleanRegex            = "^\"|\"$"
	MetadataKeyPIIEntities    = "piimaskingregex:pii_entities"
	DefaultEmailEntityName    = "EMAIL"
	DefaultPhoneEntityName    = "PHONE"
	DefaultSSNEntityName      = "SSN"
	DefaultJSONPath           = "$.messages[-1].content"
	DefaultEmailRegex         = `(?i)\b[a-z0-9.!#$%&'*+/=?^_{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\b`
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
	// Anthropic Messages — extended thinking and streamed tool-call arguments.
	"$.delta.thinking",
	"$.delta.partial_json",
	// OpenAI chat completions — streamed tool-call arguments.
	"$.choices[0].delta.tool_calls[0].function.arguments",
	"$.delta",
}

var textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)

// PIIMaskingRegexPolicy implements regex-based PII masking
type PIIMaskingRegexPolicy struct {
	params PIIMaskingRegexPolicyParams
}

type PIIMaskingRegexPolicyParams struct {
	PIIEntities map[string]*regexp.Regexp
	// Builtin marks entities enabled through the email, phone and ssn toggles.
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

// maskState lets every string of one request share placeholders.
type maskState struct {
	placeholders map[string]string // original -> placeholder
	used         map[string]bool
	noNumbers    bool // leave number values alone (set for chat requests)
}

func newMaskState() *maskState {
	return &maskState{placeholders: map[string]string{}, used: map[string]bool{}}
}

// placeholderFor returns the placeholder of an original value. It is derived from the
// entity and the value alone, so the same value gets the same placeholder on every
// request (prompt caching and signed thinking blocks need that). A clash between two
// values of one request steps to the next free tag.
func (st *maskState) placeholderFor(entity, original string) string {
	if ph, ok := st.placeholders[original]; ok {
		return ph
	}
	sum := sha256.Sum256([]byte("pii-masking-regex\x00" + entity + "\x00" + original))
	tag := int(sum[0])<<8 | int(sum[1])
	for i := 0; ; i++ {
		ph := fmt.Sprintf("[%s_%04x]", entity, (tag+i)&0xffff)
		if !st.used[ph] {
			st.used[ph] = true
			st.placeholders[original] = ph
			return ph
		}
	}
}

// numberBoundaryOK keeps the built-in phone and SSN patterns from matching the middle
// of a longer number (a timestamp, a 64-bit id, the tail of a UUID, a decimal).
func numberBoundaryOK(content string, s, e int) bool {
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	if s > 0 && (isDigit(content[s-1]) || (content[s-1] == '.' && s > 1 && isDigit(content[s-2]))) {
		return false
	}
	if e < len(content) && (isDigit(content[e]) || (content[e] == '.' && e+1 < len(content) && isDigit(content[e+1]))) {
		return false
	}
	return true
}

// maskText replaces PII in content with placeholders from st and returns the result.
func (p *PIIMaskingRegexPolicy) maskText(content string, piiEntities map[string]*regexp.Regexp, st *maskState) string {
	if content == "" {
		return content
	}

	// Pre-compile placeholder pattern for efficiency
	placeholderPattern := regexp.MustCompile(`^\[[A-Z_]+_[0-9a-f]{4}\]$`)

	// Entities are visited in name order so the result never depends on map order.
	names := make([]string, 0, len(piiEntities))
	for name := range piiEntities {
		names = append(names, name)
	}
	sort.Strings(names)

	// First pass: find all matches without replacing to avoid nested replacements
	found := map[string]string{}       // original -> entity
	entityHits := make(map[string]int) // entity name -> occurrences, for debug logging
	for _, key := range names {
		for _, loc := range piiEntities[key].FindAllStringIndex(content, -1) {
			match := content[loc[0]:loc[1]]
			if placeholderPattern.MatchString(match) {
				continue
			}
			if p.params.Builtin[key] && key != DefaultEmailEntityName && !numberBoundaryOK(content, loc[0], loc[1]) {
				continue
			}
			entityHits[key]++
			if _, exists := found[match]; !exists {
				found[match] = key
			}
		}
	}

	// Second pass: replace all matches, longest first
	originals := make([]string, 0, len(found))
	for original := range found {
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool {
		if len(originals[i]) != len(originals[j]) {
			return len(originals[i]) > len(originals[j])
		}
		return originals[i] < originals[j]
	})
	maskedContent := content
	for _, original := range originals {
		maskedContent = strings.ReplaceAll(maskedContent, original, st.placeholderFor(found[original], original))
	}

	p.logPIIDetection("mask", entityHits)
	return maskedContent
}

// recordMapping stores original->placeholder for the response phase. Several instances
// of the policy can share one route, so each adds to the mapping instead of replacing it.
func recordMapping(metadata map[string]interface{}, mapping map[string]string) {
	if len(mapping) == 0 {
		return
	}
	merged := make(map[string]string, len(mapping))
	if existing, ok := metadata[MetadataKeyPIIEntities].(map[string]string); ok {
		for k, v := range existing {
			merged[k] = v
		}
	}
	for k, v := range mapping {
		merged[k] = v
	}
	metadata[MetadataKeyPIIEntities] = merged
}

// maskPIIFromContent masks PII from content using regex patterns
func (p *PIIMaskingRegexPolicy) maskPIIFromContent(content string, piiEntities map[string]*regexp.Regexp, metadata map[string]interface{}) (string, error) {
	st := newMaskState()
	masked := p.maskText(content, piiEntities, st)
	if len(st.placeholders) == 0 {
		return "", nil
	}
	recordMapping(metadata, st.placeholders)
	return masked, nil
}

// redactPIIFromContent redacts PII from content using regex patterns
func (p *PIIMaskingRegexPolicy) redactPIIFromContent(content string, piiEntities map[string]*regexp.Regexp) string {
	if content == "" {
		return ""
	}

	maskedContent := content
	entityHits := make(map[string]int) // entity name -> occurrences, for debug logging

	for key, pattern := range piiEntities {
		if n := len(pattern.FindAllStringIndex(maskedContent, -1)); n > 0 {
			entityHits[key] = n
			maskedContent = pattern.ReplaceAllString(maskedContent, "*****")
		}
	}

	p.logPIIDetection("redact", entityHits)

	if len(entityHits) > 0 {
		return maskedContent
	}

	return ""
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
func (p *PIIMaskingRegexPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) []byte {
	if jsonPath == "" || jsonPath == "$" {
		// If no JSONPath, the entire payload was processed, return the modified content
		return []byte(modifiedContent)
	}

	// If JSONPath is specified, update only the specific field in the JSON structure
	var jsonData map[string]interface{}
	if err := json.Unmarshal(originalPayload, &jsonData); err != nil {
		// Fallback to returning the modified content as-is
		return []byte(modifiedContent)
	}

	// Set the new value at the JSONPath location
	err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent)
	if err != nil {
		// Fallback to returning the original payload
		return originalPayload
	}

	// Marshal back to JSON to get the full modified payload
	updatedPayload, err := json.Marshal(jsonData)
	if err != nil {
		// Fallback to returning the original payload
		return originalPayload
	}

	return updatedPayload
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

	// Whole payload: mask the JSON document's string values, not its raw text.
	if p.params.JsonPath == "" || p.params.JsonPath == "$" {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		if out, changed, ok := p.maskJSONPayload(payload, reqCtx.Metadata); ok {
			if !changed {
				return policy.UpstreamRequestModifications{}
			}
			return policy.UpstreamRequestModifications{Body: out}
		}
	}

	extractedValue, ok, err := extractStringFromPath(payload, p.params.JsonPath)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}
	if !ok {
		// Value at path is not a scalar (e.g. multimodal content array); skip masking.
		return policy.UpstreamRequestModifications{}
	}

	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	var modifiedContent string
	if p.params.RedactPII {
		modifiedContent = p.redactPIIFromContent(extractedValue, p.params.PIIEntities)
	} else {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		modifiedContent, err = p.maskPIIFromContent(extractedValue, p.params.PIIEntities, reqCtx.Metadata)
		if err != nil {
			return p.buildErrorResponse(fmt.Sprintf("error masking PII: %v", err)).(policy.RequestAction)
		}
	}

	if modifiedContent != "" && modifiedContent != extractedValue {
		modifiedPayload := p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, p.params.JsonPath)
		return policy.UpstreamRequestModifications{
			Body: modifiedPayload,
		}
	}

	return policy.UpstreamRequestModifications{}
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

	// Plain JSON buffered response: restore placeholders directly in the raw JSON bytes,
	// which covers message content, tool-call arguments and any other provider shape.
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
// accumulator limit before anything reached the client. 64 bytes is far past any
// real placeholder — "[CREDIT_CARD_NUMBER_0000]" is 25.
const maxPlaceholderTailBytes = 64

// placeholderTailPattern matches the text after an unclosed "[" when that text
// could still become a placeholder.
//
// Placeholders are built as "[%s_%04x]" with the entity name uppercased, and the
// request side validates them with ^\[[A-Z_]+_[0-9a-f]{4}\]$. The two halves draw
// on disjoint character sets — the name is [A-Z_], the counter is [0-9a-f] — so a
// half-emitted placeholder is exactly a run of the first followed by up to four
// of the second. Anything else after the bracket (a space, lowercase prose,
// punctuation) proves no placeholder can complete, so the stream is released now.
var placeholderTailPattern = regexp.MustCompile(`^[A-Z_]*[0-9a-f]{0,4}$`)

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

	return couldCompletePlaceholder(extractSSEDeltaContent(s))
}

// endsAtSSEEventBoundary reports whether s ends on a complete SSE event. Both
// terminators are legal and a CRLF stream contains no "\n\n" at all, so matching
// LF alone would treat every CRLF event as incomplete and buffer the whole
// response to the kernel's accumulator ceiling.
func endsAtSSEEventBoundary(s string) bool {
	return strings.HasSuffix(s, "\n\n") || strings.HasSuffix(s, "\r\n\r\n")
}

// extractSSEDeltaContent concatenates the assistant text carried by every data
// event in an SSE buffer, which is the text a client ultimately assembles and so
// the only thing placeholder detection should look at. Frame boundaries are
// deliberately not preserved: a placeholder split across events is contiguous
// here, which is what lets the shape test in couldCompletePlaceholder work
// regardless of how finely the upstream tokenised it.
func extractSSEDeltaContent(s string) string {
	var sb strings.Builder
	for _, line := range strings.Split(s, "\n") {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		sb.WriteString(extractFirstDeltaContent(jsonStr, DefaultStreamingJSONPaths))
	}
	return sb.String()
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
	if !strings.HasPrefix(body, sseDataPrefix) {
		return "", false
	}
	return strings.TrimPrefix(body, sseDataPrefix), true
}

// rebuildSSEDataLine reassembles a data line around a rewritten payload,
// preserving the line's original CR terminator.
func rebuildSSEDataLine(line, payload string) string {
	if strings.HasSuffix(line, "\r") {
		return sseDataPrefix + payload + "\r"
	}
	return sseDataPrefix + payload
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

// restoreJSONBytes replaces every complete placeholder in s with its
// JSON-escaped original, preserving all other bytes exactly.
func restoreJSONBytes(s string, restoreMap map[string]string) string {
	result := s
	for placeholder, original := range restoreMap {
		if !strings.Contains(result, placeholder) {
			continue
		}
		encodedBytes, err := json.Marshal(original)
		if err != nil {
			continue
		}
		escapedOriginal := string(encodedBytes[1 : len(encodedBytes)-1])
		result = strings.ReplaceAll(result, placeholder, escapedOriginal)
	}
	return result
}

// ─── SSE / Streaming helpers ─────────────────────────────────────────────────

// isSSEChunk reports whether the chunk looks like SSE data (has at least one "data: " or "event:" line).
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// restoreSSEChunk handles SSE streaming format: "data: {...}\n\n" lines.
//
// When the accumulator flushes a batch of SSE events (e.g. the placeholder
// [EMAIL_0000] split across " [", "EMAIL", "_", "0000", "]" in separate events),
// no single event contains the full placeholder. We therefore concatenate all
// delta.content values, restore on the full string, then redistribute: the
// first content-bearing event gets the complete restored text, and all subsequent
// events whose content has been merged into the first are dropped entirely.
func (p *PIIMaskingRegexPolicy) restoreSSEChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	lines := strings.Split(chunkStr, "\n")

	// Collect every SSE data line that carries a non-empty delta, grouped by the stream it
	// belongs to: the same kind of delta (text, thinking, tool arguments) of the same
	// content block. A placeholder is split across the pieces of one stream, never
	// across streams, so each stream is joined and restored on its own.
	type contentLine struct {
		lineIdx int
		content string
	}
	var order []string
	groups := map[string][]contentLine{}
	paths := map[string]string{}
	for i, line := range lines {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		c, path := extractFirstDeltaContentKeyed(jsonStr, DefaultStreamingJSONPaths)
		if c == "" {
			continue
		}
		key := path + "|" + sseBlockIndex(jsonStr)
		if _, seen := groups[key]; !seen {
			order = append(order, key)
			paths[key] = path
		}
		groups[key] = append(groups[key], contentLine{lineIdx: i, content: c})
	}

	if len(order) == 0 {
		return policy.ForwardResponseChunk{}
	}

	removeLines := map[int]bool{}
	changed := false
	for _, key := range order {
		cls := groups[key]
		var sb strings.Builder
		for _, cl := range cls {
			sb.WriteString(cl.content)
		}
		fullContent := sb.String()
		var restoredContent string
		if strings.HasSuffix(paths[key], "partial_json") || strings.HasSuffix(paths[key], "arguments") {
			// The text is a piece of JSON, so an original must be JSON-escaped to fit in it.
			restoredContent = restoreJSONBytes(fullContent, maskedMap)
		} else {
			restoredContent = restore(fullContent, maskedMap)
		}
		if restoredContent == fullContent {
			continue
		}
		changed = true

		// Redistribute: the first event of the stream gets the full restored text;
		// the rest of that stream's events are dropped.
		lines[cls[0].lineIdx] = replaceContentInSSELine(
			lines[cls[0].lineIdx], cls[0].content, restoredContent,
			DefaultStreamingJSONPaths,
		)
		for _, cl := range cls[1:] {
			markEventBlockForRemoval(lines, cl.lineIdx, removeLines)
		}
	}
	if !changed {
		return policy.ForwardResponseChunk{}
	}

	filtered := lines[:0:0]
	for i, line := range lines {
		if removeLines[i] {
			continue
		}
		filtered = append(filtered, line)
	}

	return policy.ForwardResponseChunk{Body: []byte(strings.Join(filtered, "\n"))}
}

// sseBlockIndex returns the content block index of an SSE payload, or "" when it has none.
func sseBlockIndex(jsonStr string) string {
	var ev struct {
		Index *json.Number `json:"index"`
	}
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	if err := dec.Decode(&ev); err != nil || ev.Index == nil {
		return ""
	}
	return ev.Index.String()
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

// jsonPathLeafKey returns the final field name of a JSONPath, e.g. "content"
// for "$.choices[0].delta.content". Used to locate the value in the raw JSON so
// a rewrite can preserve the frame's original key order and spacing instead of
// re-marshaling it.
func jsonPathLeafKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return ""
}

// replaceContentInSSELine replaces the delta.content value in a "data: {...}" SSE
// line in-place, touching only the JSON-encoded content value and leaving all
// other fields intact. Falls back to a full re-marshal if the in-place
// replacement cannot locate the expected token.
func replaceContentInSSELine(line, oldContent, newContent string, paths []string) string {
	jsonStr, ok := sseDataPayload(line)
	if !ok {
		return line
	}
	_, matchedPath := extractFirstDeltaContentKeyed(jsonStr, paths)
	if matchedPath == "" {
		return line
	}
	key := jsonPathLeafKey(matchedPath)
	oldJSON, err1 := json.Marshal(oldContent)
	newJSON, err2 := json.Marshal(newContent)
	if err1 != nil || err2 != nil {
		return updateDeltaContentInLine(line, newContent, matchedPath)
	}
	updated := strings.Replace(jsonStr, `"`+key+`":`+string(oldJSON), `"`+key+`":`+string(newJSON), 1)
	if updated == jsonStr {
		// Token not found (e.g. whitespace around colon) — fall back.
		return updateDeltaContentInLine(line, newContent, matchedPath)
	}
	return rebuildSSEDataLine(line, updated)
}

// updateDeltaContentInLine is the fallback full-remarshal path used when
// replaceContentInSSELine cannot locate the content token in the raw JSON.
// It writes through the same JSONPath the text was extracted from, so it stays
// correct for any provider shape without knowing which one this is.
func updateDeltaContentInLine(line, newContent, matchedPath string) string {
	jsonStr, ok := sseDataPayload(line)
	if !ok {
		return line
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return line
	}
	if err := utils.SetValueAtJSONPath(data, matchedPath, newContent); err != nil {
		return line
	}
	b, err := json.Marshal(data)
	if err != nil {
		return line
	}
	return rebuildSSEDataLine(line, string(b))
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
	result := content
	for placeholder, original := range maskedMap {
		result = strings.ReplaceAll(result, placeholder, original)
	}
	return result
}

// extractStringFromPath extracts the value at jsonPath from payload as a string.
// Returns (value, true, nil) when the value is a scalar string or number.
// Returns ("", false, nil) when the value exists but is not a scalar (e.g. array/object).
// Returns ("", false, err) on path or parse errors.
func extractStringFromPath(payload []byte, jsonPath string) (string, bool, error) {
	if jsonPath == "" || jsonPath == "$" {
		return string(payload), true, nil
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return "", false, err
	}
	raw, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return "", false, err
	}
	switch v := raw.(type) {
	case string:
		return v, true, nil
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
