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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// stringVisitor is called for every JSON string value (never for object keys).
// path is the RFC 9535 normalized path of the value, or "" when the scan was
// started without path tracking. It returns the replacement text and whether
// the text changed.
type stringVisitor func(path, text string) (string, bool)

// scanJSONStrings walks a valid JSON document and offers every string value to
// visit. Only the tokens whose text changed are rewritten; every other byte
// (keys, numbers, whitespace, key order, escapes in untouched strings) is copied
// from the input unchanged. The caller must have checked json.Valid(body).
//
// trackPaths enables normalized-path tracking. It costs one string build per
// value, so it is only switched on for scoped masking.
func scanJSONStrings(body []byte, trackPaths bool, visit stringVisitor) ([]byte, bool, error) {
	s := &jsonScanner{src: body, track: trackPaths, visit: visit}
	s.skipSpace()
	if err := s.value("$"); err != nil {
		return nil, false, err
	}
	if !s.changed {
		return body, false, nil
	}
	s.out.Write(body[s.copied:])
	return s.out.Bytes(), true, nil
}

type jsonScanner struct {
	src     []byte
	pos     int
	track   bool
	visit   stringVisitor
	out     bytes.Buffer
	copied  int
	changed bool
}

func (s *jsonScanner) skipSpace() {
	for s.pos < len(s.src) {
		switch s.src[s.pos] {
		case ' ', '\t', '\r', '\n':
			s.pos++
		default:
			return
		}
	}
}

func (s *jsonScanner) value(path string) error {
	if s.pos >= len(s.src) {
		return fmt.Errorf("unexpected end of JSON")
	}
	switch s.src[s.pos] {
	case '{':
		return s.object(path)
	case '[':
		return s.array(path)
	case '"':
		return s.stringValue(path)
	default:
		// number, true, false, null: copied untouched.
		for s.pos < len(s.src) {
			switch s.src[s.pos] {
			case ',', ']', '}', ' ', '\t', '\r', '\n':
				return nil
			}
			s.pos++
		}
		return nil
	}
}

func (s *jsonScanner) object(path string) error {
	s.pos++ // {
	s.skipSpace()
	if s.pos < len(s.src) && s.src[s.pos] == '}' {
		s.pos++
		return nil
	}
	for {
		s.skipSpace()
		keyStart := s.pos
		keyEnd, err := s.scanStringEnd()
		if err != nil {
			return err
		}
		memberPath := ""
		if s.track {
			var key string
			if err := json.Unmarshal(s.src[keyStart:keyEnd], &key); err != nil {
				return err
			}
			memberPath = path + "['" + escapeNormalizedName(key) + "']"
		}
		s.pos = keyEnd
		s.skipSpace()
		if s.pos >= len(s.src) || s.src[s.pos] != ':' {
			return fmt.Errorf("expected ':' in JSON object")
		}
		s.pos++
		s.skipSpace()
		if err := s.value(memberPath); err != nil {
			return err
		}
		s.skipSpace()
		if s.pos >= len(s.src) {
			return fmt.Errorf("unexpected end of JSON object")
		}
		if s.src[s.pos] == ',' {
			s.pos++
			continue
		}
		if s.src[s.pos] == '}' {
			s.pos++
			return nil
		}
		return fmt.Errorf("unexpected byte %q in JSON object", s.src[s.pos])
	}
}

func (s *jsonScanner) array(path string) error {
	s.pos++ // [
	s.skipSpace()
	if s.pos < len(s.src) && s.src[s.pos] == ']' {
		s.pos++
		return nil
	}
	for idx := 0; ; idx++ {
		s.skipSpace()
		elemPath := ""
		if s.track {
			elemPath = path + "[" + strconv.Itoa(idx) + "]"
		}
		if err := s.value(elemPath); err != nil {
			return err
		}
		s.skipSpace()
		if s.pos >= len(s.src) {
			return fmt.Errorf("unexpected end of JSON array")
		}
		if s.src[s.pos] == ',' {
			s.pos++
			continue
		}
		if s.src[s.pos] == ']' {
			s.pos++
			return nil
		}
		return fmt.Errorf("unexpected byte %q in JSON array", s.src[s.pos])
	}
}

// scanStringEnd returns the offset just past the string token starting at s.pos.
func (s *jsonScanner) scanStringEnd() (int, error) {
	if s.pos >= len(s.src) || s.src[s.pos] != '"' {
		return 0, fmt.Errorf("expected string in JSON")
	}
	i := s.pos + 1
	for i < len(s.src) {
		switch s.src[i] {
		case '\\':
			i += 2
		case '"':
			return i + 1, nil
		default:
			i++
		}
	}
	return 0, fmt.Errorf("unterminated JSON string")
}

func (s *jsonScanner) stringValue(path string) error {
	start := s.pos
	end, err := s.scanStringEnd()
	if err != nil {
		return err
	}
	s.pos = end
	var text string
	if err := json.Unmarshal(s.src[start:end], &text); err != nil {
		return err
	}
	replacement, changed := s.visit(path, text)
	if !changed {
		return nil
	}
	encoded, err := encodeJSONString(replacement)
	if err != nil {
		return err
	}
	s.out.Write(s.src[s.copied:start])
	s.out.Write(encoded)
	s.copied = end
	s.changed = true
	return nil
}

// encodeJSONString encodes text as a JSON string without HTML escaping, so
// characters such as < and & stay as they are.
func encodeJSONString(text string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(text); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// escapeNormalizedName escapes a member name for use inside the single-quoted
// form of an RFC 9535 normalized path.
func escapeNormalizedName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		switch {
		case r == '\'':
			sb.WriteString(`\'`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
