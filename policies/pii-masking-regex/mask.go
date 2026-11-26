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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// redactionMarker replaces matched text when redactPII is enabled.
const redactionMarker = "*****"

// placeholderShape matches a complete placeholder: [ENTITY_xxxx].
var placeholderShape = regexp.MustCompile(`^\[[A-Z_]+_[0-9a-f]{4}\]$`)

// entityDetector is one PII entity with its compiled pattern.
type entityDetector struct {
	name string
	re   *regexp.Regexp
}

// match is one detected span of PII.
type match struct {
	start, end int
	entity     string
	original   string
}

// masker detects PII and replaces it with placeholders (or the redaction
// marker). One masker serves one request: collect every value first, assign
// placeholders, then apply, so the assignment does not depend on the order in
// which text is visited.
type masker struct {
	detectors []entityDetector
	// found maps an original value to the entity that claimed it. The first
	// entity by name wins when two entities match the same text.
	found map[string]string
	// assigned maps an original value to its placeholder.
	assigned map[string]string
	hits     map[string]int
}

// newMasker builds a masker from the configured entities. Detectors are kept in
// name order so results never depend on map iteration order.
func newMasker(entities map[string]*regexp.Regexp) *masker {
	names := make([]string, 0, len(entities))
	for name := range entities {
		names = append(names, name)
	}
	sort.Strings(names)
	detectors := make([]entityDetector, 0, len(names))
	for _, name := range names {
		detectors = append(detectors, entityDetector{name: name, re: entities[name]})
	}
	return &masker{
		detectors: detectors,
		found:     make(map[string]string),
		assigned:  make(map[string]string),
		hits:      make(map[string]int),
	}
}

// findMatches returns the non-overlapping PII spans in text, left to right.
func (m *masker) findMatches(text string) []match {
	var all []match
	for _, d := range m.detectors {
		for _, loc := range d.re.FindAllStringIndex(text, -1) {
			if loc[0] == loc[1] {
				continue
			}
			original := text[loc[0]:loc[1]]
			if placeholderShape.MatchString(original) {
				continue
			}
			all = append(all, match{start: loc[0], end: loc[1], entity: d.name, original: original})
		}
	}
	if len(all) == 0 {
		return nil
	}
	// Earliest start first, then the longest span, then entity name order (the
	// detectors were appended in name order and the sort is stable).
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return all[i].end > all[j].end
	})
	out := all[:0:0]
	lastEnd := -1
	for _, mt := range all {
		if mt.start < lastEnd {
			continue
		}
		out = append(out, mt)
		lastEnd = mt.end
	}
	return out
}

// collect records every PII value found in text. It does not change the text.
func (m *masker) collect(text string) {
	for _, mt := range m.findMatches(text) {
		m.hits[mt.entity]++
		if _, ok := m.found[mt.original]; !ok {
			m.found[mt.original] = mt.entity
		}
	}
}

// assign gives every collected value its placeholder. Values are processed in
// byte order, so the numbering does not depend on the order text was visited.
func (m *masker) assign() {
	originals := make([]string, 0, len(m.found))
	for original := range m.found {
		originals = append(originals, original)
	}
	sort.Strings(originals)
	for i, original := range originals {
		m.assigned[original] = fmt.Sprintf("[%s_%04x]", m.found[original], i)
	}
}

// apply replaces every PII span in text with its placeholder.
func (m *masker) apply(text string) string {
	return m.replace(text, func(original string) string { return m.assigned[original] })
}

// redact replaces every PII span in text with the redaction marker.
func (m *masker) redact(text string) string {
	return m.replace(text, func(string) string { return redactionMarker })
}

func (m *masker) replace(text string, with func(original string) string) string {
	matches := m.findMatches(text)
	if len(matches) == 0 {
		return text
	}
	var sb strings.Builder
	sb.Grow(len(text))
	last := 0
	for _, mt := range matches {
		repl := with(mt.original)
		if repl == "" {
			continue
		}
		sb.WriteString(text[last:mt.start])
		sb.WriteString(repl)
		last = mt.end
	}
	sb.WriteString(text[last:])
	return sb.String()
}

// mapping returns the original-to-placeholder map for response restoration.
func (m *masker) mapping() map[string]string {
	if len(m.assigned) == 0 {
		return nil
	}
	out := make(map[string]string, len(m.assigned))
	for k, v := range m.assigned {
		out[k] = v
	}
	return out
}
