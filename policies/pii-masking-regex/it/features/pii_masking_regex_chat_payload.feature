# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@pii-masking-regex
Feature: PII masking regex policy on chat and agent payloads
  As an API developer fronting an LLM agent
  I want the whole-payload mode to mask only what users and tools said
  So that the request stays valid JSON, the application's own prompt and schemas are untouched,
  and the same value always gets the same placeholder

  Background:
    Given the gateway services are running
    And I authenticate using basic auth as "admin"
    And I resolve the "capture" service URL at "" and store it as "captureUpstream"

  Scenario: A JSON escape before an email keeps the upstream request valid JSON
    Given I generate a unique value from "pii-chat-escape" and store it as "apiName"
    And I generate a unique API version from "pii-chat-escape" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-escape" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/escape","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/escape" with body:
      """
      {"messages":[{"role":"user","content":"line1\nbob@example.org"}]}
      """
    Then the response status code should be 200
    And the response body should contain "bob@example.org"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/escape"
    Then the response should be valid JSON
    And the response body should not contain "bob@example.org"
    And the response body should contain "[EMAIL_"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: The system prompt, tool definitions and parameters are not masked
    Given I generate a unique value from "pii-chat-scope" and store it as "apiName"
    And I generate a unique API version from "pii-chat-scope" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-scope" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/scope","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"phone":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/scope" with body:
      """
      {
        "model": "claude-sonnet",
        "max_tokens": 4155550199,
        "system": "Escalate to ops@corp.example.org",
        "tools": [
          {"name": "lookup", "description": "Mail ops@corp.example.org or call 415-555-0199",
           "input_schema": {"type": "object", "maximum": 9007199254740991}}
        ],
        "messages": [
          {"role": "user", "content": "Please mail bob@example.org"}
        ]
      }
      """
    Then the response status code should be 200
    And the response body should contain "bob@example.org"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/scope"
    Then the response should be valid JSON
    And the response body should contain "Escalate to ops@corp.example.org"
    And the response body should contain "Mail ops@corp.example.org or call 415-555-0199"
    And the response body should contain "4155550199"
    And the response body should contain "9007199254740991"
    And the response body should not contain "bob@example.org"
    And the response body should contain "[EMAIL_"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: A request with nothing to mask reaches the upstream unchanged
    Given I generate a unique value from "pii-chat-noop" and store it as "apiName"
    And I generate a unique API version from "pii-chat-noop" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-noop" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/noop","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"phone":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/noop" with body:
      """
      {"max_tokens":9007199254740993,"x":1.0,"y":1e2,"messages":[{"role":"user","content":"hello \u003c there"}]}
      """
    Then the response status code should be 200
    And the response body should contain "hello"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/noop"
    Then the response body should contain "9007199254740993"
    And the response body should contain ":1.0,"
    And the response body should contain ":1e2,"
    And the response body should contain "hello \\u003c there"
    And the response body should not contain "[EMAIL_"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: The same value always gets the same placeholder
    Given I generate a unique value from "pii-chat-stable" and store it as "apiName"
    And I generate a unique API version from "pii-chat-stable" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-stable" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/stable","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"phone":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/stable" with body:
      """
      {"messages":[{"role":"user","content":"mail bob@example.org or call 415-555-0199"}]}
      """
    Then the response status code should be 200
    And the response body should contain "bob@example.org"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/stable"
    Then the response body should contain "[EMAIL_9b71]"
    And the response body should contain "[PHONE_0ccd]"

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/stable" with body:
      """
      {"messages":[{"role":"user","content":"first alice@example.com then call 415-555-0199 and mail bob@example.org"}]}
      """
    Then the response status code should be 200
    And the response body should contain "alice@example.com"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/stable"
    Then the response body should contain "[EMAIL_9b71]"
    And the response body should contain "[PHONE_0ccd]"
    And the response body should not contain "alice@example.com"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Digits inside a longer number are never cut
    Given I generate a unique value from "pii-chat-digits" and store it as "apiName"
    And I generate a unique API version from "pii-chat-digits" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-digits" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/digits","policies":[{"name":"pii-masking-regex","version":"v1","params":{"phone":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/digits" with body:
      """
      {"messages":[{"role":"user","content":"started 1795104230191, id 9007199254740991, call (415) 555-0199"}]}
      """
    Then the response status code should be 200
    And the response body should contain "1795104230191"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/digits"
    Then the response should be valid JSON
    And the response body should contain "1795104230191"
    And the response body should contain "9007199254740991"
    And the response body should not contain "(415) 555-0199"
    And the response body should contain "[PHONE_"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Tool calls and results are masked while ids and typed arguments are kept
    Given I generate a unique value from "pii-chat-tools" and store it as "apiName"
    And I generate a unique API version from "pii-chat-tools" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-tools" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/tools","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"phone":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/tools" with body:
      """
      {
        "messages": [
          {"role": "user", "content": "look up bob@example.org"},
          {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_4155550199", "name": "lookup", "input": {"email": "bob@example.org", "limit": 5}}]},
          {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_4155550199", "content": "found 415-555-0199"}]}
        ]
      }
      """
    Then the response status code should be 200
    And the response body should contain "found 415-555-0199"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/tools"
    Then the response should be valid JSON
    And the response body should contain "toolu_4155550199"
    And the response body should contain ": 5}"
    And the response body should not contain "bob@example.org"
    And the response body should not contain "found 415-555-0199"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: An API-level and an operation-level instance both mask and both restore
    Given I generate a unique value from "pii-chat-instances" and store it as "apiName"
    And I generate a unique API version from "pii-chat-instances" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-instances" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.policies          | [{"name":"pii-masking-regex","version":"v1","params":{"email":true,"jsonPath":"$"}}] |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/instances","policies":[{"name":"pii-masking-regex","version":"v1","params":{"phone":true,"jsonPath":"$"}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/instances" with body:
      """
      {"messages":[{"role":"user","content":"mail bob@example.org call 415-555-0199"}]}
      """
    Then the response status code should be 200
    And the response body should contain "bob@example.org"
    And the response body should contain "415-555-0199"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/instances"
    Then the response body should not contain "bob@example.org"
    And the response body should not contain "415-555-0199"
    And the response body should contain "[EMAIL_"
    And the response body should contain "[PHONE_"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404

  Scenario: Redaction keeps a chat request valid and leaves the application prompt alone
    Given I generate a unique value from "pii-chat-redact" and store it as "apiName"
    And I generate a unique API version from "pii-chat-redact" and store it as "apiVersion"
    And I generate a unique API context from "/pii-chat-redact" and store it as "apiContext"
    When I create API from "resources/templates/rest-api.yaml" with values:
      | apiVersion             | ${CTX:gatewaySpecVersion} |
      | name                   | ${CTX:apiName}                   |
      | spec.displayName       | ${CTX:apiName}                   |
      | spec.version           | ${CTX:apiVersion}                |
      | spec.context           | ${CTX:apiContext}/$version       |
      | spec.upstream.main.url | ${CTX:captureUpstream}           |
      | spec.operations        | [{"method":"GET","path":"/get"},{"method":"POST","path":"/redact","policies":[{"name":"pii-masking-regex","version":"v1","params":{"email":true,"jsonPath":"$","redactPII":true}}]}] |
    Then the resource creation response should indicate successful deployment
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 200

    When I set header "Content-Type" to "application/json"
    And I send a "POST" request to "${CTX:apiContext}/${CTX:apiVersion}/redact" with body:
      """
      {"system":"ops@corp.example.org","messages":[{"role":"user","content":"x\nbob@example.org"}]}
      """
    Then the response status code should be 200
    And the response body should not contain "[EMAIL_"
    When I send a "GET" request to the "capture" service at "/test/captured?path=/redact"
    Then the response should be valid JSON
    And the response body should contain "ops@corp.example.org"
    And the response body should contain "*****"
    And the response body should not contain "bob@example.org"

    When I delete the API "${CTX:apiName}"
    Then the response should be successful
    And I send a "GET" request to "${CTX:apiContext}/${CTX:apiVersion}/get" until status 404
