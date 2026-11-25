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
	"strings"
	"testing"
)

func maskSecret(_, text string) (string, bool) {
	out := strings.ReplaceAll(text, "SECRET", "[X]")
	return out, out != text
}

func TestScanJSONStrings_KeysAndNumbersAreNeverTouched(t *testing.T) {
	in := []byte(`{"SECRET":1,"max":9007199254740991,"neg":-0.5e+10,"t":true,"n":null,"v":"a SECRET b"}`)
	out, changed, err := scanJSONStrings(in, false, maskSecret)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	want := `{"SECRET":1,"max":9007199254740991,"neg":-0.5e+10,"t":true,"n":null,"v":"a [X] b"}`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestScanJSONStrings_UnchangedInputIsReturnedAsIs(t *testing.T) {
	in := []byte(" {\n  \"a\" : [ 1 , \"b\" ] ,\n \"c\":{ } }\n")
	out, changed, err := scanJSONStrings(in, true, maskSecret)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("input was not returned unchanged: %q", out)
	}
}

func TestScanJSONStrings_WhitespaceAndOrderPreserved(t *testing.T) {
	in := []byte("{\n\t\"z\" : \"SECRET\" ,\n\t\"a\" : [ \"x\" , \"SECRET\" ]\n}\n")
	out, _, err := scanJSONStrings(in, false, maskSecret)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n\t\"z\" : \"[X]\" ,\n\t\"a\" : [ \"x\" , \"[X]\" ]\n}\n"
	if string(out) != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

// Item 1: a regex that runs on raw JSON text can swallow the letter of an
// escape. The scanner masks decoded text, so an escape is never part of a match.
func TestScanJSONStrings_EscapesAreDecodedBeforeMasking(t *testing.T) {
	cases := map[string]string{
		"newline":   `{"v":"line1\nSECRET"}`,
		"tab":       `{"v":"line1\tSECRET"}`,
		"return":    `{"v":"line1\rSECRET"}`,
		"lt":        `{"v":"line1<SECRET"}`,
		"backslash": `{"v":"line1\\SECRET"}`,
		"quote":     `{"v":"line1\"SECRET"}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, changed, err := scanJSONStrings([]byte(in), false, maskSecret)
			if err != nil || !changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if !strings.Contains(string(out), "[X]") || strings.Contains(string(out), "SECRET") {
				t.Fatalf("not masked: %s", out)
			}
			if !json.Valid(out) {
				t.Fatalf("output is not valid JSON: %s", out)
			}
		})
	}
}

func TestScanJSONStrings_PathsAreNormalized(t *testing.T) {
	in := []byte(`{"a":[{"b'c":"x"},"y"],"d":{"e":"z"}}`)
	var got []string
	_, _, err := scanJSONStrings(in, true, func(path, text string) (string, bool) {
		got = append(got, path)
		return text, false
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`$['a'][0]['b\'c']`, "$['a'][1]", "$['d']['e']"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestScanJSONStrings_UnicodeAndEmpty(t *testing.T) {
	in := []byte(`{"v":"héllo 日本語 😀 SECRET","e":"","a":[]}`)
	out, changed, err := scanJSONStrings(in, false, maskSecret)
	if err != nil || !changed || !json.Valid(out) {
		t.Fatalf("changed=%v err=%v out=%s", changed, err, out)
	}
	if !strings.Contains(string(out), "héllo 日本語 😀 [X]") {
		t.Fatalf("unexpected output %s", out)
	}
}

func TestScanJSONStrings_TopLevelString(t *testing.T) {
	out, changed, err := scanJSONStrings([]byte(`"SECRET"`), false, maskSecret)
	if err != nil || !changed || string(out) != `"[X]"` {
		t.Fatalf("out=%s changed=%v err=%v", out, changed, err)
	}
}

func TestScanJSONStrings_HTMLCharactersAreNotEscaped(t *testing.T) {
	out, _, _ := scanJSONStrings([]byte(`{"v":"<a> & SECRET"}`), false, maskSecret)
	if string(out) != `{"v":"<a> & [X]"}` {
		t.Fatalf("got %s", out)
	}
}
