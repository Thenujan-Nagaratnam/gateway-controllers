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

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Sentinel markers are lowercase and case-sensitive: "=?BASE64?…?=" is a literal value.
const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// errMalformedSentinel marks a value that announced itself as sentinel-encoded but whose
// payload is not decodable base64.
var errMalformedSentinel = errors.New("value is in sentinel form but its payload is not valid base64")

// decodeSentinel unwraps the "=?base64?<standard-base64>?=" form MCP defines for header values
// that cannot be written as visible ASCII, returning anything else unchanged. The spec requires
// the wrapping even for a colliding plain value, so sentinel form always means encoded, and it
// requires an intermediary to decode before comparing against the body.
func decodeSentinel(value string) (string, error) {
	if !strings.HasPrefix(value, sentinelPrefix) || !strings.HasSuffix(value, sentinelSuffix) {
		return value, nil
	}
	// The markers share the trailing "?=", so "=?base64?=" passes both checks carrying no
	// payload; without this the slice below runs out of range.
	if len(value) < len(sentinelPrefix)+len(sentinelSuffix) {
		return "", errMalformedSentinel
	}
	encoded := value[len(sentinelPrefix) : len(value)-len(sentinelSuffix)]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errMalformedSentinel
	}
	return string(raw), nil
}

// isValidFieldValue reports whether a value uses only the octets RFC 9110 permits in a field
// value: visible ASCII, space and horizontal tab. Applied to the raw header, before decoding:
// the sentinel payload is allowed to fall outside that set, which is what the wrapper is for.
func isValidFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7E) {
			continue
		}
		return false
	}
	return true
}
