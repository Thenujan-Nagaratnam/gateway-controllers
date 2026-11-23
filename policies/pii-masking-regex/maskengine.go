/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package piimaskingregex

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// redactedText replaces a value when redactPII is on.
const redactedText = "*****"

// placeholderSpanPattern finds a placeholder token inside text. Anything the policy
// itself produced (here or in an earlier instance on the same route) is never
// masked again, and a user's own text that merely looks like one is left alone.
var placeholderSpanPattern = regexp.MustCompile(`\[[A-Z_]+_[0-9a-f]{4}\]`)

// match is one detected value, as byte offsets into the text it was found in.
type match struct {
	start, end int
	entity     string
}

// findMatches returns the non-overlapping PII matches in text, from every
// configured entity. Where two entities overlap (a phone-like run inside an email
// address) the one that starts first wins, then the longer, then the entity name,
// so the result never depends on map iteration order.
func (p *PIIMaskingRegexPolicy) findMatches(text string) []match {
	if text == "" {
		return nil
	}
	names := make([]string, 0, len(p.params.PIIEntities))
	for name := range p.params.PIIEntities {
		names = append(names, name)
	}
	sort.Strings(names)

	var skip [][]int
	if strings.Contains(text, "[") {
		skip = placeholderSpanPattern.FindAllStringIndex(text, -1)
	}

	var all []match
	for _, name := range names {
		for _, loc := range p.params.PIIEntities[name].FindAllStringIndex(text, -1) {
			if loc[1] <= loc[0] || overlapsAny(skip, loc[0], loc[1]) {
				continue
			}
			if p.params.Builtin[name] && name != DefaultEmailEntityName && !numberBoundaryOK(text, loc[0], loc[1]) {
				continue
			}
			all = append(all, match{start: loc[0], end: loc[1], entity: name})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.end != b.end {
			return a.end > b.end
		}
		return a.entity < b.entity
	})
	out := all[:0:0]
	last := 0
	for _, m := range all {
		if m.start < last {
			continue
		}
		out = append(out, m)
		last = m.end
	}
	return out
}

func overlapsAny(spans [][]int, s, e int) bool {
	for _, sp := range spans {
		if s < sp[1] && sp[0] < e {
			return true
		}
	}
	return false
}

// numberBoundaryOK reports whether a numeric match stands on its own. The built-in
// phone and SSN patterns need ten and nine digits, so without this they also match
// the middle of a longer number: a millisecond timestamp, a 64-bit id, the tail of
// a UUID, or the digits of a decimal. Cutting a placeholder into one of those
// corrupts it, which is worse than leaving it alone.
func numberBoundaryOK(text string, s, e int) bool {
	if s > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:s])
		if isDigit(r) {
			return false
		}
		if r == '.' && s > 1 {
			if r2, _ := utf8.DecodeLastRuneInString(text[:s-1]); isDigit(r2) {
				return false
			}
		}
	}
	if e < len(text) {
		r, w := utf8.DecodeRuneInString(text[e:])
		if isDigit(r) {
			return false
		}
		if r == '.' && e+w < len(text) {
			if r2, _ := utf8.DecodeRuneInString(text[e+w:]); isDigit(r2) {
				return false
			}
		}
	}
	return true
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// ─── Placeholders ────────────────────────────────────────────────────────────

// pair is a detected value and the entity that matched it.
type pair struct{ entity, value string }

// assignPlaceholders gives every distinct (entity, value) a placeholder that
// depends only on that pair, never on its position, on the other values in the
// request, or on how many requests came before. The same address therefore gets
// the same placeholder on every request, which is what keeps the request prefix
// byte-identical across the turns of a conversation (prompt caching) and keeps a
// signed thinking block valid when the client sends it back.
//
// The four hex digits are the start of a SHA-256 of the pair. A clash between two
// different values of one entity inside one request is resolved by stepping to the
// next free tag, in sorted order, so the outcome is deterministic and no two values
// of a request ever share a placeholder.
func assignPlaceholders(pairs []pair) map[pair]string {
	sorted := append([]pair(nil), pairs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].entity != sorted[j].entity {
			return sorted[i].entity < sorted[j].entity
		}
		return sorted[i].value < sorted[j].value
	})
	out := make(map[pair]string, len(sorted))
	used := make(map[string]bool, len(sorted))
	for _, pr := range sorted {
		if _, done := out[pr]; done {
			continue
		}
		sum := sha256.Sum256([]byte("pii-masking-regex\x00" + pr.entity + "\x00" + pr.value))
		tag := int(sum[0])<<8 | int(sum[1])
		for i := 0; i < 0x10000; i++ {
			ph := fmt.Sprintf("[%s_%04x]", pr.entity, (tag+i)&0xffff)
			if !used[ph] {
				used[ph] = true
				out[pr] = ph
				break
			}
		}
	}
	return out
}

// ─── Splicing ────────────────────────────────────────────────────────────────

// pending is a match located in the source document by raw byte offsets.
type pending struct {
	start, end int // raw span to overwrite
	entity     string
	value      string
	quote      bool // the span is a bare JSON number: the replacement becomes a string
}

// maskTargets masks the PII found in the given string and number nodes of the
// document b, rewriting only the matched bytes. It returns the new document, the
// original→placeholder mapping to restore the response with (nil when redacting),
// and whether anything changed.
func (p *PIIMaskingRegexPolicy) maskTargets(b []byte, targets []*node) ([]byte, map[string]string, bool) {
	var found []pending
	entityHits := make(map[string]int)
	for _, n := range targets {
		switch n.kind {
		case kindString:
			d, ok := decodeJSONString(b[n.start:n.end])
			if !ok {
				continue
			}
			for _, m := range p.findMatches(d.text) {
				rs, re := d.rawSpan(m.start, m.end)
				found = append(found, pending{start: n.start + rs, end: n.start + re, entity: m.entity, value: d.text[m.start:m.end]})
				entityHits[m.entity]++
			}
		case kindNumber:
			lit := string(b[n.start:n.end])
			ms := p.findMatches(lit)
			// Only a number that is entirely PII is replaced, and then by a string. A
			// match inside a longer number is a coincidence of digits, not a value.
			if len(ms) == 1 && ms[0].start == 0 && ms[0].end == len(lit) {
				found = append(found, pending{start: n.start, end: n.end, entity: ms[0].entity, value: lit, quote: true})
				entityHits[ms[0].entity]++
			}
		}
	}
	if p.params.RedactPII {
		p.logPIIDetection("redact", entityHits)
	} else {
		p.logPIIDetection("mask", entityHits)
	}
	if len(found) == 0 {
		return b, nil, false
	}

	var ph map[pair]string
	var mapping map[string]string
	if !p.params.RedactPII {
		pairs := make([]pair, 0, len(found))
		for _, f := range found {
			pairs = append(pairs, pair{f.entity, f.value})
		}
		ph = assignPlaceholders(pairs)
		mapping = make(map[string]string, len(ph))
		for pr, tag := range ph {
			mapping[pr.value] = tag
		}
	}

	sort.Slice(found, func(i, j int) bool { return found[i].start < found[j].start })
	out := make([]byte, 0, len(b)+len(found)*8)
	pos := 0
	for _, f := range found {
		if f.start < pos {
			continue
		}
		out = append(out, b[pos:f.start]...)
		text := redactedText
		if ph != nil {
			text = ph[pair{f.entity, f.value}]
		}
		if f.quote {
			out = append(out, '"')
			out = append(out, text...)
			out = append(out, '"')
		} else {
			out = append(out, text...)
		}
		pos = f.end
	}
	out = append(out, b[pos:]...)
	return out, mapping, true
}

// maskPlainText masks a body that is not JSON. It is the fail-safe: a payload the
// scanner cannot read is still masked, as text, rather than forwarded as sent.
func (p *PIIMaskingRegexPolicy) maskPlainText(text string) (string, map[string]string, bool) {
	ms := p.findMatches(text)
	if len(ms) == 0 {
		return text, nil, false
	}
	pairs := make([]pair, 0, len(ms))
	for _, m := range ms {
		pairs = append(pairs, pair{m.entity, text[m.start:m.end]})
	}
	var ph map[pair]string
	var mapping map[string]string
	if !p.params.RedactPII {
		ph = assignPlaceholders(pairs)
		mapping = make(map[string]string, len(ph))
		for pr, tag := range ph {
			mapping[pr.value] = tag
		}
	}
	var sb strings.Builder
	pos := 0
	for _, m := range ms {
		sb.WriteString(text[pos:m.start])
		if ph != nil {
			sb.WriteString(ph[pair{m.entity, text[m.start:m.end]}])
		} else {
			sb.WriteString(redactedText)
		}
		pos = m.end
	}
	sb.WriteString(text[pos:])
	return sb.String(), mapping, true
}

// mergePIIMetadata records mapping (original→placeholder) for the response phase.
// Several instances of this policy can sit on one route, each with its own
// detectors, and they share one metadata map. Each must add to it, never replace
// it, or the instance that ran last is the only one whose values get restored.
func mergePIIMetadata(metadata map[string]interface{}, mapping map[string]string) {
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
