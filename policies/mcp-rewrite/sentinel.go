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

package mcprewrite

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	sentinelPrefix = "=?base64?"
	sentinelSuffix = "?="
)

// errMalformedSentinel marks a value that announced itself as sentinel-encoded but whose
// payload is not decodable base64.
var errMalformedSentinel = errors.New("malformed base64 sentinel value")

// decodeSentinel unwraps the "=?base64?<standard-base64>?=" form MCP defines for header values
// that cannot be written as visible ASCII, returning anything else unchanged. The spec requires
// the wrapping even for a colliding plain value, so sentinel form always means encoded.
func decodeSentinel(value string) (string, error) {
	if !strings.HasPrefix(value, sentinelPrefix) || !strings.HasSuffix(value, sentinelSuffix) {
		return value, nil
	}
	// The markers share the trailing "?=", so "=?base64?=" passes both checks carrying no
	// payload; without this the slice below runs out of range.
	if len(value) < len(sentinelPrefix)+len(sentinelSuffix) {
		return "", errMalformedSentinel
	}
	raw, err := base64.StdEncoding.DecodeString(value[len(sentinelPrefix) : len(value)-len(sentinelSuffix)])
	if err != nil {
		return "", errMalformedSentinel
	}
	return string(raw), nil
}

// encodeSentinel wraps a value for transport in an Mcp-Name header, inverting decodeSentinel.
// The rewrite target is operator configuration and unconstrained, so writing it raw would be both
// a conformance bug and a header-injection vector.
func encodeSentinel(value string) string {
	if !needsSentinel(value) {
		return value
	}
	return sentinelPrefix + base64.StdEncoding.EncodeToString([]byte(value)) + sentinelSuffix
}

// needsSentinel reports whether a value has to be wrapped to travel in a header field: it is
// outside visible ASCII, or it merely looks like sentinel form, which a reader would otherwise
// decode into something the operator never wrote.
func needsSentinel(value string) bool {
	if strings.HasPrefix(value, sentinelPrefix) && strings.HasSuffix(value, sentinelSuffix) {
		return true
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x21 || c > 0x7E {
			return true
		}
	}
	return false
}
