module github.com/wso2/gateway-controllers/policies/pii-masking-regex

go 1.26.10

require github.com/wso2/api-platform/sdk/core v0.5.2

// RFC 9535 JSONPath queries (wso2/api-platform#3571) come from this release until
// it is published upstream; then drop the replace and require that version.
replace github.com/wso2/api-platform/sdk/core => github.com/Thenujan-Nagaratnam/api-platform/sdk/core v0.5.2-rfc9535.2
