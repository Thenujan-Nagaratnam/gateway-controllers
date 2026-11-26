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
	"strconv"
	"strings"
	"testing"
)

func builtinMasker(t *testing.T, params map[string]interface{}) *masker {
	t.Helper()
	parsed, err := parseParams(params)
	if err != nil {
		t.Fatal(err)
	}
	return newMasker(parsed.PIIEntities)
}

func maskText(m *masker, text string) string {
	m.collect(text)
	m.assign()
	return m.apply(text)
}

func TestPlaceholderShapeAndStability(t *testing.T) {
	first := placeholderFor("EMAIL", "bob@example.org", 0)
	if !placeholderShape.MatchString(first) {
		t.Fatalf("placeholder %q does not match the documented shape", first)
	}
	for i := 0; i < 100; i++ {
		if got := placeholderFor("EMAIL", "bob@example.org", 0); got != first {
			t.Fatalf("placeholder changed: %q vs %q", got, first)
		}
	}
	if placeholderFor("PHONE", "bob@example.org", 0) == first {
		t.Fatal("different entities must give different placeholders for the same value")
	}
	if placeholderFor("EMAIL", "alice@example.org", 0) == first {
		t.Fatal("different values must give different placeholders")
	}
}

func TestPlaceholderShapeRejectsOldCounterFormat(t *testing.T) {
	if placeholderShape.MatchString("[EMAIL_0000]") {
		t.Fatal("the old 4-digit counter format must not be treated as a placeholder shape")
	}
}

func TestTailPatternAcceptsEightDigitPartialPlaceholders(t *testing.T) {
	for _, tail := range []string{"", "EMAIL", "EMAIL_", "EMAIL_3fa9", "EMAIL_3fa91c0b"} {
		if !placeholderTailPattern.MatchString(tail) {
			t.Errorf("tail %q should still be a viable placeholder prefix", tail)
		}
	}
	if placeholderTailPattern.MatchString("EMAIL_3fa91c0b9") {
		t.Error("nine hex digits cannot be a placeholder")
	}
}

func TestMasker_SameOutputRegardlessOfEntityMix(t *testing.T) {
	emailOnly := builtinMasker(t, map[string]interface{}{"email": true})
	both := builtinMasker(t, map[string]interface{}{"email": true, "phone": true})
	text := "write to bob@example.org or call (415) 555-0199"
	a := maskText(emailOnly, text)
	b := maskText(both, text)
	ph := placeholderFor("EMAIL", "bob@example.org", 0)
	if !strings.Contains(a, ph) || !strings.Contains(b, ph) {
		t.Fatalf("email placeholder must be identical with and without phone enabled:\n%s\n%s", a, b)
	}
}

func TestMasker_RepeatedValueGetsOnePlaceholderAndDifferentValuesDiffer(t *testing.T) {
	m := builtinMasker(t, map[string]interface{}{"email": true})
	out := maskText(m, "a@example.org, b@example.org, a@example.org")
	parts := strings.Split(out, ", ")
	if parts[0] != parts[2] {
		t.Fatalf("same value must have the same placeholder: %v", parts)
	}
	if parts[0] == parts[1] {
		t.Fatalf("different values must have different placeholders: %v", parts)
	}
}

func TestMasker_OutputIsIndependentOfVisitOrder(t *testing.T) {
	texts := []string{"x@example.org", "y@example.org", "z@example.org"}
	build := func(order []int) map[string]string {
		m := builtinMasker(t, map[string]interface{}{"email": true})
		for _, i := range order {
			m.collect(texts[i])
		}
		m.assign()
		return m.mapping()
	}
	a := build([]int{0, 1, 2})
	b := build([]int{2, 0, 1})
	for k, v := range a {
		if b[k] != v {
			t.Fatalf("assignment depends on visit order: %q -> %q vs %q", k, v, b[k])
		}
	}
}

// Two different values that hash to the same placeholder are separated, and the
// outcome does not depend on the order in which the values were seen.
func TestMasker_CollisionIsResolvedDeterministically(t *testing.T) {
	orig := placeholderDigest
	defer func() { placeholderDigest = orig }()
	placeholderDigest = func(entity, value string, attempt int) uint32 {
		if attempt == 0 {
			return 0xdeadbeef // every value collides on the first attempt
		}
		return orig(entity, value, attempt)
	}

	build := func(order []string) map[string]string {
		m := builtinMasker(t, map[string]interface{}{"email": true})
		for _, v := range order {
			m.collect(v)
		}
		m.assign()
		return m.mapping()
	}
	a := build([]string{"a@example.org", "b@example.org", "c@example.org"})
	b := build([]string{"c@example.org", "a@example.org", "b@example.org"})
	seen := map[string]bool{}
	for k, v := range a {
		if b[k] != v {
			t.Fatalf("assignment depends on order: %q -> %q vs %q", k, v, b[k])
		}
		if seen[v] {
			t.Fatalf("two values share the placeholder %q", v)
		}
		seen[v] = true
	}
	if len(a) != 3 {
		t.Fatalf("all three values must be masked, got %v", a)
	}
	if a["a@example.org"] != "[EMAIL_deadbeef]" {
		t.Fatalf("the value that sorts first keeps the natural placeholder, got %q", a["a@example.org"])
	}
}

func TestMasker_ManyValuesNeverShareAPlaceholder(t *testing.T) {
	m := builtinMasker(t, map[string]interface{}{"email": true})
	for i := 0; i < 5000; i++ {
		m.found["user"+strconv.Itoa(i)+"@example.org"] = "EMAIL"
	}
	m.assign()
	seen := map[string]struct{}{}
	for _, ph := range m.assigned {
		if _, dup := seen[ph]; dup {
			t.Fatalf("duplicate placeholder %q", ph)
		}
		seen[ph] = struct{}{}
	}
	if len(seen) != 5000 {
		t.Fatalf("expected 5000 distinct placeholders, got %d", len(seen))
	}
}

func TestMasker_AlreadyPlaceholderShapedTextIsNotMaskedAgain(t *testing.T) {
	m := builtinMasker(t, map[string]interface{}{
		"customPIIEntities": []interface{}{map[string]interface{}{"piiEntity": "ANY", "piiRegex": `\[[A-Z_]+_[0-9a-f]{8}\]`}},
	})
	text := "keep [EMAIL_3fa91c0b] as is"
	if got := maskText(m, text); got != text {
		t.Fatalf("got %q", got)
	}
}

func TestMasker_RedactReplacesWithMarker(t *testing.T) {
	m := builtinMasker(t, map[string]interface{}{"email": true, "redactPII": true})
	m.collect("mail bob@example.org now")
	if got := m.redact("mail bob@example.org now"); got != "mail ***** now" {
		t.Fatalf("got %q", got)
	}
}

func TestMergePIIMapping_KeepsExistingEntries(t *testing.T) {
	md := map[string]interface{}{MetadataKeyPIIEntities: map[string]string{"a": "[A_00000001]"}}
	mergePIIMapping(md, map[string]string{"b": "[B_00000002]", "a": "[Z_ffffffff]"})
	got := md[MetadataKeyPIIEntities].(map[string]string)
	if got["a"] != "[A_00000001]" || got["b"] != "[B_00000002]" || len(got) != 2 {
		t.Fatalf("unexpected merged mapping %v", got)
	}
	mergePIIMapping(md, nil)
	if len(md[MetadataKeyPIIEntities].(map[string]string)) != 2 {
		t.Fatal("merging nothing must not change the mapping")
	}
}
