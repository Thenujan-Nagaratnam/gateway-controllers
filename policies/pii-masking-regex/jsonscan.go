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
	"bytes"
	"errors"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// A span-preserving JSON scanner.
//
// Masking must change only the bytes that hold PII. Decoding a request into Go
// values and encoding it again does not do that: it reorders keys, rewrites
// number spellings (9007199254740993 becomes ...992, 1.0 becomes 1), re-escapes
// characters, and drops whitespace, any of which changes the upstream's prompt
// cache prefix or invalidates a signed thinking block. The scanner instead
// records where every value sits in the original bytes, so a caller can decode a
// string to match against it, then splice a replacement over exactly the matched
// bytes and leave everything else as it was.

// maxJSONDepth matches encoding/json, which the policy this replaces relied on.
const maxJSONDepth = 10000

type nodeKind byte

const (
	kindObject nodeKind = iota
	kindArray
	kindString
	kindNumber
	kindLiteral // true, false, null
)

// node is one JSON value with its byte span in the source. For a string the span
// includes the quotes. Object keys are decoded; values are in kids at the same index.
type node struct {
	kind  nodeKind
	start int
	end   int
	keys  []string
	kids  []*node

	// key is the member name the node sits under (an array element inherits the
	// name of its array), and parent is the node that holds it. They tell a
	// signature from a sentence, and a tool schema from a message.
	key    string
	parent *node
	index  map[string][]*node // built on first lookup in a wide object

	// Set on a document's root only.
	hasDupKeys bool // an object somewhere writes the same key twice
	depth      int  // the deepest nesting
}

var errBadJSON = errors.New("invalid JSON")

// inheritKeys gives every array element the member name its array sits under.
// An object member already has its own name.
func inheritKeys(n *node) {
	for _, c := range n.kids {
		if n.kind == kindArray {
			c.key = n.key
		}
		inheritKeys(c)
	}
}

// parseJSON scans b as exactly one JSON value (surrounding whitespace allowed).
func parseJSON(b []byte) (*node, error) {
	vals, err := parseJSONValues(b)
	if err != nil {
		return nil, err
	}
	if len(vals) != 1 {
		return nil, errBadJSON
	}
	return vals[0], nil
}

// parseJSONValues scans b as one or more JSON values separated by whitespace (a
// single document, or newline-delimited JSON). Anything else is an error.
func parseJSONValues(b []byte) ([]*node, error) {
	s := &scanner{b: b}
	if bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		s.i = 3 // a UTF-8 byte order mark is not part of the document
	}
	var out []*node
	for {
		s.skipWS()
		if s.i == len(b) && len(out) > 0 {
			for _, n := range out {
				n.hasDupKeys, n.depth = s.dup, s.maxDepth
				inheritKeys(n)
			}
			return out, nil
		}
		n, err := s.value(0)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
}

type scanner struct {
	b        []byte
	i        int
	dup      bool
	maxDepth int
}

func (s *scanner) skipWS() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

func (s *scanner) value(depth int) (*node, error) {
	if s.i >= len(s.b) || depth > maxJSONDepth {
		return nil, errBadJSON
	}
	if depth > s.maxDepth {
		s.maxDepth = depth
	}
	switch c := s.b[s.i]; {
	case c == '{':
		return s.object(depth)
	case c == '[':
		return s.array(depth)
	case c == '"':
		start := s.i
		if err := s.skipString(); err != nil {
			return nil, err
		}
		return &node{kind: kindString, start: start, end: s.i}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	default:
		for _, lit := range []string{"true", "false", "null"} {
			if len(s.b)-s.i >= len(lit) && string(s.b[s.i:s.i+len(lit)]) == lit {
				n := &node{kind: kindLiteral, start: s.i, end: s.i + len(lit)}
				s.i += len(lit)
				return n, nil
			}
		}
		return nil, errBadJSON
	}
}

func (s *scanner) object(depth int) (*node, error) {
	n := &node{kind: kindObject, start: s.i}
	s.i++
	s.skipWS()
	if s.i < len(s.b) && s.b[s.i] == '}' {
		s.i++
		n.end = s.i
		return n, nil
	}
	for {
		s.skipWS()
		if s.i >= len(s.b) || s.b[s.i] != '"' {
			return nil, errBadJSON
		}
		ks := s.i
		if err := s.skipString(); err != nil {
			return nil, err
		}
		key, _ := decodeJSONString(s.b[ks:s.i])
		s.skipWS()
		if s.i >= len(s.b) || s.b[s.i] != ':' {
			return nil, errBadJSON
		}
		s.i++
		s.skipWS()
		v, err := s.value(depth + 1)
		if err != nil {
			return nil, err
		}
		if s.seenKey(n, key.text) {
			s.dup = true
		}
		v.key, v.parent = key.text, n
		n.keys = append(n.keys, key.text)
		n.kids = append(n.kids, v)
		if n.index != nil {
			n.index[key.text] = append(n.index[key.text], v)
		}
		s.skipWS()
		if s.i >= len(s.b) {
			return nil, errBadJSON
		}
		if s.b[s.i] == ',' {
			s.i++
			continue
		}
		if s.b[s.i] == '}' {
			s.i++
			n.end = s.i
			return n, nil
		}
		return nil, errBadJSON
	}
}

func (s *scanner) array(depth int) (*node, error) {
	n := &node{kind: kindArray, start: s.i}
	s.i++
	s.skipWS()
	if s.i < len(s.b) && s.b[s.i] == ']' {
		s.i++
		n.end = s.i
		return n, nil
	}
	for {
		s.skipWS()
		v, err := s.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.parent = n
		n.kids = append(n.kids, v)
		s.skipWS()
		if s.i >= len(s.b) {
			return nil, errBadJSON
		}
		if s.b[s.i] == ',' {
			s.i++
			continue
		}
		if s.b[s.i] == ']' {
			s.i++
			n.end = s.i
			return n, nil
		}
		return nil, errBadJSON
	}
}

// seenKey reports whether key is already a member of n.
func (s *scanner) seenKey(n *node, key string) bool {
	if len(n.keys) < 12 {
		for _, k := range n.keys {
			if k == key {
				return true
			}
		}
		return false
	}
	if n.index == nil {
		n.index = make(map[string][]*node, len(n.keys)*2)
		for i, k := range n.keys {
			n.index[k] = append(n.index[k], n.kids[i])
		}
	}
	_, dup := n.index[key]
	return dup
}

// skipString advances over a string literal, validating escapes and rejecting raw
// control characters, exactly as encoding/json does.
func (s *scanner) skipString() error {
	s.i++ // opening quote
	for s.i < len(s.b) {
		c := s.b[s.i]
		switch {
		case c == '"':
			s.i++
			return nil
		case c < 0x20:
			return errBadJSON
		case c == '\\':
			s.i++
			if s.i >= len(s.b) {
				return errBadJSON
			}
			switch s.b[s.i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.i++
			case 'u':
				if s.i+4 >= len(s.b) {
					return errBadJSON
				}
				for k := 1; k <= 4; k++ {
					if !isHex(s.b[s.i+k]) {
						return errBadJSON
					}
				}
				s.i += 5
			default:
				return errBadJSON
			}
		default:
			s.i++
		}
	}
	return errBadJSON
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func (s *scanner) number() (*node, error) {
	start := s.i
	if s.b[s.i] == '-' {
		s.i++
	}
	if s.i >= len(s.b) {
		return nil, errBadJSON
	}
	if s.b[s.i] == '0' {
		s.i++
	} else if s.b[s.i] >= '1' && s.b[s.i] <= '9' {
		for s.i < len(s.b) && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
			s.i++
		}
	} else {
		return nil, errBadJSON
	}
	if s.i < len(s.b) && s.b[s.i] == '.' {
		s.i++
		d := s.i
		for s.i < len(s.b) && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
			s.i++
		}
		if s.i == d {
			return nil, errBadJSON
		}
	}
	if s.i < len(s.b) && (s.b[s.i] == 'e' || s.b[s.i] == 'E') {
		s.i++
		if s.i < len(s.b) && (s.b[s.i] == '+' || s.b[s.i] == '-') {
			s.i++
		}
		d := s.i
		for s.i < len(s.b) && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
			s.i++
		}
		if s.i == d {
			return nil, errBadJSON
		}
	}
	return &node{kind: kindNumber, start: start, end: s.i}, nil
}

// get returns the value of key in an object, or nil. A key written twice is read
// as the last one, as encoding/json does.
func (n *node) get(key string) *node {
	if n == nil || n.kind != kindObject {
		return nil
	}
	if len(n.keys) >= 12 {
		all := n.getAll(key)
		if len(all) == 0 {
			return nil
		}
		return all[len(all)-1]
	}
	var found *node
	for i, k := range n.keys {
		if k == key {
			found = n.kids[i]
		}
	}
	return found
}

// getAll returns every value written under key. Parsers disagree on which copy of
// a repeated key wins, so a path that names it has to cover them all.
func (n *node) getAll(key string) []*node {
	if n == nil || n.kind != kindObject {
		return nil
	}
	if len(n.keys) >= 12 {
		if n.index == nil {
			n.index = make(map[string][]*node, len(n.keys)*2)
			for i, k := range n.keys {
				n.index[k] = append(n.index[k], n.kids[i])
			}
		}
		return n.index[key]
	}
	var out []*node
	for i, k := range n.keys {
		if k == key {
			out = append(out, n.kids[i])
		}
	}
	return out
}

// str returns the decoded text of a string node.
func (n *node) str(b []byte) (string, bool) {
	if n == nil || n.kind != kindString {
		return "", false
	}
	d, ok := decodeJSONString(b[n.start:n.end])
	return d.text, ok
}

// ─── Decoded strings with byte maps ──────────────────────────────────────────

// segment maps a run of decoded bytes to the raw bytes it came from. A run of
// plain characters maps one to one; an escape sequence is its own segment.
type segment struct {
	decStart, decEnd int
	rawStart, rawEnd int
	plain            bool
}

// decodedString is a decoded JSON string together with the map back to its raw
// bytes, so a match found on the decoded text can be replaced in the source
// without touching the escapes around it.
type decodedString struct {
	text string
	segs []segment
	base int // offset of the opening quote in the source
}

// decodeJSONString decodes raw, which must be a complete string literal with its
// quotes. Offsets in the returned segments are relative to raw.
func decodeJSONString(raw []byte) (decodedString, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return decodedString{}, false
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	var segs []segment
	i := 0
	for i < len(in) {
		if in[i] != '\\' {
			j := i
			for j < len(in) && in[j] != '\\' {
				j++
			}
			segs = append(segs, segment{decStart: len(out), decEnd: len(out) + (j - i), rawStart: 1 + i, rawEnd: 1 + j, plain: true})
			out = append(out, in[i:j]...)
			i = j
			continue
		}
		if i+1 >= len(in) {
			return decodedString{}, false
		}
		start := i
		var r rune
		switch in[i+1] {
		case '"', '\\', '/':
			r = rune(in[i+1])
			i += 2
		case 'b':
			r, i = '\b', i+2
		case 'f':
			r, i = '\f', i+2
		case 'n':
			r, i = '\n', i+2
		case 'r':
			r, i = '\r', i+2
		case 't':
			r, i = '\t', i+2
		case 'u':
			if i+6 > len(in) {
				return decodedString{}, false
			}
			v, err := strconv.ParseUint(string(in[i+2:i+6]), 16, 32)
			if err != nil {
				return decodedString{}, false
			}
			r = rune(v)
			i += 6
			if utf16.IsSurrogate(r) {
				r2 := rune(-1)
				if i+6 <= len(in) && in[i] == '\\' && in[i+1] == 'u' {
					if v2, err := strconv.ParseUint(string(in[i+2:i+6]), 16, 32); err == nil {
						r2 = rune(v2)
					}
				}
				if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
					r = dec
					i += 6
				} else {
					r = utf8.RuneError
				}
			}
		default:
			return decodedString{}, false
		}
		var buf [4]byte
		w := utf8.EncodeRune(buf[:], r)
		segs = append(segs, segment{decStart: len(out), decEnd: len(out) + w, rawStart: 1 + start, rawEnd: 1 + i})
		out = append(out, buf[:w]...)
	}
	return decodedString{text: string(out), segs: segs}, true
}

// rawSpan maps the decoded byte range [ds, de) to the raw byte range it came from.
// Matches always begin and end on rune boundaries, which are segment boundaries
// for escape sequences, so the result never cuts an escape in half.
func (d decodedString) rawSpan(ds, de int) (int, int) {
	find := func(off int) int {
		return sort.Search(len(d.segs), func(k int) bool { return d.segs[k].decEnd > off })
	}
	a := d.segs[find(ds)]
	rs := a.rawStart
	if a.plain {
		rs += ds - a.decStart
	}
	z := d.segs[find(de-1)]
	re := z.rawEnd
	if z.plain {
		re = z.rawStart + (de - z.decStart)
	}
	return rs, re
}
