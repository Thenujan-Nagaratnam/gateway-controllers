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

package mistralmoderation

// A small JSONPath evaluator, written here instead of imported so the policy has no
// dependency beyond the gateway SDK (a local `filePath` policy with a third-party module
// would depend on the image build being able to resolve it).
//
// Supported syntax (the commonly used part of RFC 9535):
//
//	$                      the root
//	.name  ['name']        child by name (single or double quotes; \' \" \\ escapes)
//	.*  [*]                every child of an object or array
//	[n]  [-n]              array element; negative counts from the end
//	[a:b]  [a:b:c]         array slice, Python semantics
//	[0,2]  ['a','b']       union of any of the selectors above
//	..name  ..*  ..[...]   recursive descent
//	[?(<expr>)]            filter over children; <expr> is built from
//	                         @ paths (@.a.b, @['a'], @.items[0], @ itself),
//	                         string / number / true / false / null literals,
//	                         == != < <= > >=, && || ! and parentheses.
//	                       A bare @ path is an existence test.
//
// Not supported: functions (length, match, ...), absolute paths inside a filter, and
// wildcard or descent inside a filter path. Unsupported syntax is rejected when the path is
// compiled, which happens when the policy is built, not on a request.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxPathNodes bounds how many JSON nodes one evaluation may visit, so a hostile document
// combined with `..` cannot burn unbounded CPU.
const maxPathNodes = 200000

type jsonPath struct {
	src  string
	segs []segment
}

type segment struct {
	descend bool
	sels    []selector
}

type selector interface {
	// children calls emit for each child of node the selector picks, in document order.
	children(node interface{}, emit func(interface{}))
}

// compileJSONPath parses a JSONPath expression.
func compileJSONPath(src string) (*jsonPath, error) {
	p := &pathParser{s: src}
	jp, err := p.parsePath()
	if err != nil {
		return nil, fmt.Errorf("invalid jsonPath %q: %w", src, err)
	}
	jp.src = src
	return jp, nil
}

// evaluate returns every node the path selects in the already-decoded document; none if the
// path selects nothing.
func (jp *jsonPath) evaluate(doc interface{}) ([]interface{}, error) {
	budget := maxPathNodes
	nodes := []interface{}{doc}
	for _, seg := range jp.segs {
		var next []interface{}
		for _, n := range nodes {
			scope := []interface{}{n}
			if seg.descend {
				scope = nil
				if err := descendants(n, &scope, &budget); err != nil {
					return nil, err
				}
			}
			for _, s := range scope {
				for _, sel := range seg.sels {
					sel.children(s, func(c interface{}) { next = append(next, c) })
				}
			}
			if !seg.descend { // descendants() has already counted its own nodes
				budget--
			}
			if budget < 0 {
				return nil, errors.New("jsonPath evaluation exceeded the node limit")
			}
		}
		nodes = next
	}
	return nodes, nil // possibly empty: a path that selects nothing is not an error
}

// descendants appends node and all of its descendants, preorder, object keys sorted.
func descendants(node interface{}, out *[]interface{}, budget *int) error {
	*budget--
	if *budget < 0 {
		return errors.New("jsonPath evaluation exceeded the node limit")
	}
	*out = append(*out, node)
	switch v := node.(type) {
	case map[string]interface{}:
		for _, k := range sortedKeys(v) {
			if err := descendants(v[k], out, budget); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, e := range v {
			if err := descendants(e, out, budget); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ─── Selectors ──────────────────────────────────────────────────────────────

type nameSel struct{ name string }

func (s nameSel) children(node interface{}, emit func(interface{})) {
	if m, ok := node.(map[string]interface{}); ok {
		if v, ok := m[s.name]; ok {
			emit(v)
		}
	}
}

type wildcardSel struct{}

func (wildcardSel) children(node interface{}, emit func(interface{})) {
	switch v := node.(type) {
	case map[string]interface{}:
		for _, k := range sortedKeys(v) {
			emit(v[k])
		}
	case []interface{}:
		for _, e := range v {
			emit(e)
		}
	}
}

type indexSel struct{ idx int }

func (s indexSel) children(node interface{}, emit func(interface{})) {
	arr, ok := node.([]interface{})
	if !ok {
		return
	}
	i := s.idx
	if i < 0 {
		i += len(arr)
	}
	if i >= 0 && i < len(arr) {
		emit(arr[i])
	}
}

type sliceSel struct{ start, end, step *int }

func (s sliceSel) children(node interface{}, emit func(interface{})) {
	arr, ok := node.([]interface{})
	if !ok {
		return
	}
	n := len(arr)
	step := 1
	if s.step != nil {
		step = *s.step
	}
	if step == 0 {
		return
	}
	norm := func(i int) int {
		if i < 0 {
			return i + n
		}
		return i
	}
	clamp := func(i, lo, hi int) int {
		if i < lo {
			return lo
		}
		if i > hi {
			return hi
		}
		return i
	}
	if step > 0 {
		lo, hi := 0, n
		if s.start != nil {
			lo = clamp(norm(*s.start), 0, n)
		}
		if s.end != nil {
			hi = clamp(norm(*s.end), 0, n)
		}
		for i := lo; i < hi; i += step {
			emit(arr[i])
		}
		return
	}
	lo, hi := n-1, -1
	if s.start != nil {
		lo = clamp(norm(*s.start), -1, n-1)
	}
	if s.end != nil {
		hi = clamp(norm(*s.end), -1, n-1)
	}
	for i := lo; i > hi; i += step {
		emit(arr[i])
	}
}

type filterSel struct{ cond expr }

func (s filterSel) children(node interface{}, emit func(interface{})) {
	switch v := node.(type) {
	case map[string]interface{}:
		for _, k := range sortedKeys(v) {
			if s.cond.eval(v[k]) {
				emit(v[k])
			}
		}
	case []interface{}:
		for _, e := range v {
			if s.cond.eval(e) {
				emit(e)
			}
		}
	}
}

// ─── Filter expressions ─────────────────────────────────────────────────────

type expr interface {
	eval(current interface{}) bool
}

type orExpr struct{ l, r expr }
type andExpr struct{ l, r expr }
type notExpr struct{ e expr }

func (e orExpr) eval(c interface{}) bool  { return e.l.eval(c) || e.r.eval(c) }
func (e andExpr) eval(c interface{}) bool { return e.l.eval(c) && e.r.eval(c) }
func (e notExpr) eval(c interface{}) bool { return !e.e.eval(c) }

// operand yields a value (and whether there is one) for the node a filter is testing.
type operand interface {
	value(current interface{}) (interface{}, bool)
}

type literalOp struct{ v interface{} }

func (o literalOp) value(interface{}) (interface{}, bool) { return o.v, true }

// relPathOp is a path starting at @. Only name and index steps are allowed, so it selects
// at most one node.
type relPathOp struct{ steps []selector }

func (o relPathOp) value(current interface{}) (interface{}, bool) {
	nodes := []interface{}{current}
	for _, st := range o.steps {
		var next []interface{}
		for _, n := range nodes {
			st.children(n, func(c interface{}) { next = append(next, c) })
		}
		nodes = next
		if len(nodes) == 0 {
			return nil, false
		}
	}
	return nodes[0], true
}

type existsExpr struct{ op relPathOp }

func (e existsExpr) eval(c interface{}) bool { _, ok := e.op.value(c); return ok }

type cmpExpr struct {
	l, r operand
	op   string
}

func (e cmpExpr) eval(c interface{}) bool {
	lv, lok := e.l.value(c)
	rv, rok := e.r.value(c)
	switch e.op {
	case "==":
		return equal(lv, lok, rv, rok)
	case "!=":
		return !equal(lv, lok, rv, rok)
	}
	if !lok || !rok {
		return false
	}
	switch l := lv.(type) {
	case float64:
		r, ok := rv.(float64)
		if !ok {
			return false
		}
		return orderOK(e.op, compareFloat(l, r))
	case string:
		r, ok := rv.(string)
		if !ok {
			return false
		}
		return orderOK(e.op, strings.Compare(l, r))
	}
	return false
}

func compareFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func orderOK(op string, cmp int) bool {
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}
	return false
}

func equal(l interface{}, lok bool, r interface{}, rok bool) bool {
	if !lok || !rok {
		return !lok && !rok
	}
	switch lv := l.(type) {
	case nil:
		return r == nil
	case bool:
		rv, ok := r.(bool)
		return ok && lv == rv
	case float64:
		rv, ok := r.(float64)
		return ok && lv == rv
	case string:
		rv, ok := r.(string)
		return ok && lv == rv
	}
	return false // objects and arrays are not comparable here
}

// ─── Parser ─────────────────────────────────────────────────────────────────

type pathParser struct {
	s   string
	pos int
}

func (p *pathParser) eof() bool { return p.pos >= len(p.s) }

func (p *pathParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.pos]
}

func (p *pathParser) skipSpace() {
	for !p.eof() && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == '\n' || p.s[p.pos] == '\r') {
		p.pos++
	}
}

func (p *pathParser) errf(format string, a ...interface{}) error {
	return fmt.Errorf("%s at position %d", fmt.Sprintf(format, a...), p.pos)
}

func (p *pathParser) parsePath() (*jsonPath, error) {
	p.skipSpace()
	if p.peek() != '$' {
		return nil, p.errf("path must start with '$'")
	}
	p.pos++
	jp := &jsonPath{}
	for {
		p.skipSpace()
		if p.eof() {
			return jp, nil
		}
		seg, err := p.parseSegment()
		if err != nil {
			return nil, err
		}
		jp.segs = append(jp.segs, seg)
	}
}

func (p *pathParser) parseSegment() (segment, error) {
	switch p.peek() {
	case '.':
		p.pos++
		if p.peek() == '.' { // descent
			p.pos++
			seg := segment{descend: true}
			switch {
			case p.peek() == '[':
				sels, err := p.parseBracket()
				if err != nil {
					return seg, err
				}
				seg.sels = sels
			case p.peek() == '*':
				p.pos++
				seg.sels = []selector{wildcardSel{}}
			default:
				name, err := p.parseDotName()
				if err != nil {
					return seg, err
				}
				seg.sels = []selector{nameSel{name}}
			}
			return seg, nil
		}
		if p.peek() == '*' {
			p.pos++
			return segment{sels: []selector{wildcardSel{}}}, nil
		}
		name, err := p.parseDotName()
		if err != nil {
			return segment{}, err
		}
		return segment{sels: []selector{nameSel{name}}}, nil
	case '[':
		sels, err := p.parseBracket()
		return segment{sels: sels}, err
	}
	return segment{}, p.errf("expected '.' or '['")
}

func isNameByte(c byte) bool {
	return c == '_' || c == '-' || c == '$' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func (p *pathParser) parseDotName() (string, error) {
	start := p.pos
	for !p.eof() && isNameByte(p.s[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", p.errf("expected a member name")
	}
	return p.s[start:p.pos], nil
}

// parseBracket parses "[ ... ]" and returns its selectors.
func (p *pathParser) parseBracket() ([]selector, error) {
	p.pos++ // '['
	p.skipSpace()
	if p.peek() == '?' {
		p.pos++
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.peek() != ']' {
			return nil, p.errf("expected ']' after filter")
		}
		p.pos++
		return []selector{filterSel{e}}, nil
	}
	var sels []selector
	for {
		p.skipSpace()
		sel, err := p.parseBracketSelector()
		if err != nil {
			return nil, err
		}
		sels = append(sels, sel)
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return sels, nil
		default:
			return nil, p.errf("expected ',' or ']'")
		}
	}
}

func (p *pathParser) parseBracketSelector() (selector, error) {
	switch c := p.peek(); {
	case c == '*':
		p.pos++
		return wildcardSel{}, nil
	case c == '\'' || c == '"':
		name, err := p.parseQuoted()
		if err != nil {
			return nil, err
		}
		return nameSel{name}, nil
	case c == '-' || c == ':' || (c >= '0' && c <= '9'):
		return p.parseIndexOrSlice()
	case c == '?':
		return nil, p.errf("a filter cannot be combined with other selectors")
	}
	return nil, p.errf("unexpected character %q in brackets", p.peek())
}

func (p *pathParser) parseInt() (*int, error) {
	p.skipSpace()
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	for !p.eof() && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start || (p.pos == start+1 && p.s[start] == '-') {
		return nil, nil
	}
	n, err := strconv.Atoi(p.s[start:p.pos])
	if err != nil {
		return nil, p.errf("invalid integer")
	}
	return &n, nil
}

func (p *pathParser) parseIndexOrSlice() (selector, error) {
	first, err := p.parseInt()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.peek() != ':' {
		if first == nil {
			return nil, p.errf("expected an integer")
		}
		return indexSel{*first}, nil
	}
	p.pos++ // ':'
	end, err := p.parseInt()
	if err != nil {
		return nil, err
	}
	var step *int
	p.skipSpace()
	if p.peek() == ':' {
		p.pos++
		if step, err = p.parseInt(); err != nil {
			return nil, err
		}
	}
	return sliceSel{start: first, end: end, step: step}, nil
}

func (p *pathParser) parseQuoted() (string, error) {
	quote := p.s[p.pos]
	p.pos++
	var sb strings.Builder
	for !p.eof() {
		c := p.s[p.pos]
		switch {
		case c == quote:
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.eof() {
				return "", p.errf("unterminated escape")
			}
			switch e := p.s[p.pos]; e {
			case '\'', '"', '\\', '/':
				sb.WriteByte(e)
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case 'u':
				if p.pos+4 >= len(p.s) {
					return "", p.errf("bad \\u escape")
				}
				n, err := strconv.ParseUint(p.s[p.pos+1:p.pos+5], 16, 32)
				if err != nil {
					return "", p.errf("bad \\u escape")
				}
				sb.WriteRune(rune(n))
				p.pos += 4
			default:
				return "", p.errf("unknown escape \\%c", e)
			}
			p.pos++
		default:
			r, size := utf8.DecodeRuneInString(p.s[p.pos:])
			sb.WriteRune(r)
			p.pos += size
		}
	}
	return "", p.errf("unterminated string")
}

// Filter grammar: or -> and ("||" and)* ; and -> unary ("&&" unary)* ;
// unary -> "!" unary | "(" or ")" | comparison | existence.

func (p *pathParser) parseOr() (expr, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !strings.HasPrefix(p.s[p.pos:], "||") {
			return l, nil
		}
		p.pos += 2
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = orExpr{l, r}
	}
}

func (p *pathParser) parseAnd() (expr, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !strings.HasPrefix(p.s[p.pos:], "&&") {
			return l, nil
		}
		p.pos += 2
		r, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		l = andExpr{l, r}
	}
}

func (p *pathParser) parseUnary() (expr, error) {
	p.skipSpace()
	switch {
	case p.peek() == '!' && !strings.HasPrefix(p.s[p.pos:], "!="):
		p.pos++
		e, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notExpr{e}, nil
	case p.peek() == '(':
		p.pos++
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.peek() != ')' {
			return nil, p.errf("expected ')'")
		}
		p.pos++
		return e, nil
	}
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	op := ""
	for _, cand := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if strings.HasPrefix(p.s[p.pos:], cand) {
			op = cand
			break
		}
	}
	if op == "" {
		rp, ok := left.(relPathOp)
		if !ok {
			return nil, p.errf("a literal must be compared with something")
		}
		return existsExpr{rp}, nil
	}
	p.pos += len(op)
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	return cmpExpr{l: left, r: right, op: op}, nil
}

func (p *pathParser) parseOperand() (operand, error) {
	p.skipSpace()
	switch c := p.peek(); {
	case c == '@':
		p.pos++
		return p.parseRelPath()
	case c == '\'' || c == '"':
		s, err := p.parseQuoted()
		if err != nil {
			return nil, err
		}
		return literalOp{s}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case c == '$':
		return nil, p.errf("absolute paths are not supported inside a filter")
	}
	for _, lit := range []struct {
		word string
		v    interface{}
	}{{"true", true}, {"false", false}, {"null", nil}} {
		if strings.HasPrefix(p.s[p.pos:], lit.word) && !isNameByteAt(p.s, p.pos+len(lit.word)) {
			p.pos += len(lit.word)
			return literalOp{lit.v}, nil
		}
	}
	return nil, p.errf("expected a value or an @ path")
}

func isNameByteAt(s string, i int) bool { return i < len(s) && isNameByte(s[i]) }

func (p *pathParser) parseNumber() (operand, error) {
	start := p.pos
	for !p.eof() && strings.IndexByte("+-.eE0123456789", p.s[p.pos]) >= 0 {
		p.pos++
	}
	f, err := strconv.ParseFloat(p.s[start:p.pos], 64)
	if err != nil {
		return nil, p.errf("invalid number")
	}
	return literalOp{f}, nil
}

// parseRelPath parses the steps after '@': names and single indexes only.
func (p *pathParser) parseRelPath() (operand, error) {
	op := relPathOp{}
	for {
		switch p.peek() {
		case '.':
			p.pos++
			if p.peek() == '.' || p.peek() == '*' {
				return nil, p.errf("wildcards and recursive descent are not supported inside a filter path")
			}
			name, err := p.parseDotName()
			if err != nil {
				return nil, err
			}
			op.steps = append(op.steps, nameSel{name})
		case '[':
			p.pos++
			p.skipSpace()
			switch c := p.peek(); {
			case c == '\'' || c == '"':
				name, err := p.parseQuoted()
				if err != nil {
					return nil, err
				}
				op.steps = append(op.steps, nameSel{name})
			case c == '-' || (c >= '0' && c <= '9'):
				n, err := p.parseInt()
				if err != nil || n == nil {
					return nil, p.errf("expected an integer index")
				}
				op.steps = append(op.steps, indexSel{*n})
			default:
				return nil, p.errf("only a name or a single index is supported inside a filter path")
			}
			p.skipSpace()
			if p.peek() != ']' {
				return nil, p.errf("expected ']'")
			}
			p.pos++
		default:
			return op, nil
		}
	}
}

// ─── Public helper ──────────────────────────────────────────────────────────

// selectNodes decodes payload as JSON and evaluates the path against it.
func selectNodes(payload []byte, jp *jsonPath) ([]interface{}, error) {
	var doc interface{}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("payload is not valid JSON: %w", err)
	}
	return jp.evaluate(doc)
}
