/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package mcpspecvalidation

import "testing"

func TestDecodeSentinel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "a well-formed sentinel decodes",
			input: "=?base64?Z2V0X2ZvcmVjYXN0?=", // get_forecast
			want:  "get_forecast",
		},
		{
			name:  "a non-ASCII value survives the round trip",
			input: "=?base64?w7xtbGF1dA==?=", // ümlaut
			want:  "ümlaut",
		},
		{
			// The ordinary case: most names need no encoding at all.
			name:  "a plain value is returned unchanged",
			input: "get_forecast",
			want:  "get_forecast",
		},
		{
			// The markers are lowercase and case-sensitive. Decoding this would corrupt a
			// legitimate literal that happens to be spelled in capitals.
			name:  "an uppercase marker is a literal, not a sentinel",
			input: "=?BASE64?Z2V0X2ZvcmVjYXN0?=",
			want:  "=?BASE64?Z2V0X2ZvcmVjYXN0?=",
		},
		{
			name:  "a prefix without the suffix is a literal",
			input: "=?base64?Z2V0X2ZvcmVjYXN0",
			want:  "=?base64?Z2V0X2ZvcmVjYXN0",
		},
		{
			name:  "a suffix without the prefix is a literal",
			input: "Z2V0X2ZvcmVjYXN0?=",
			want:  "Z2V0X2ZvcmVjYXN0?=",
		},
		{
			// Announced as encoded but undecodable. Rejected rather than passed through,
			// because a value claiming to be encoded and not being so is malformed input,
			// not a literal.
			name:    "a malformed payload is an error",
			input:   "=?base64?not!valid!base64?=",
			wantErr: true,
		},
		{
			// The two markers share the trailing "?=", so this satisfies both HasPrefix
			// and HasSuffix while carrying no payload. Without an explicit length guard it
			// would slice out of range.
			name:    "the degenerate overlapping-marker case does not panic",
			input:   "=?base64?=",
			wantErr: true,
		},
		{
			// The spec says base64, meaning the standard RFC 4648 alphabet. The URL-safe
			// variant substitutes "-" and "_" for "+" and "/", so a value encoded that way
			// is not decodable here and is correctly rejected rather than silently mangled.
			name:    "the URL-safe alphabet is not accepted",
			input:   "=?base64?dG9vbF_DvG1sYXV0?=",
			wantErr: true,
		},
		{
			name:  "an empty value is left alone",
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSentinel(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeSentinel(%q) = %q, want an error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeSentinel(%q) returned unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("decodeSentinel(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestIsValidFieldValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"ordinary method name", "tools/call", true},
		{"space is permitted", "two words", true},
		{"horizontal tab is permitted", "a\tb", true},
		{"the printable ASCII bounds", "\x21\x7e", true},
		{"empty", "", true},

		// The reason this check exists: CR and LF are how header injection is attempted.
		{"carriage return is rejected", "tools/call\r", false},
		{"line feed is rejected", "tools/call\nX-Injected: 1", false},
		{"NUL is rejected", "tools\x00call", false},
		{"DEL is rejected", "tools\x7fcall", false},
		{"non-ASCII bytes are rejected", "tool_ümlaut", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidFieldValue(tc.input); got != tc.want {
				t.Errorf("isValidFieldValue(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// A non-ASCII value must be rejected raw and accepted only through the sentinel. This is
// the pairing that makes the two functions correct together: the charset check is what
// forces well-behaved clients to encode, and decoding is what lets the encoded form
// through.
func TestCharsetCheckAndSentinelAgree(t *testing.T) {
	const raw = "tool_ümlaut"
	const encoded = "=?base64?dG9vbF/DvG1sYXV0?=" // the same value, sentinel-wrapped

	if isValidFieldValue(raw) {
		t.Fatal("a non-ASCII value must not be accepted as a raw field value")
	}
	if !isValidFieldValue(encoded) {
		t.Fatal("the sentinel form must be accepted as a raw field value")
	}
	decoded, err := decodeSentinel(encoded)
	if err != nil {
		t.Fatalf("decoding the sentinel form failed: %v", err)
	}
	if decoded != raw {
		t.Errorf("decoded %q, want %q", decoded, raw)
	}
}
