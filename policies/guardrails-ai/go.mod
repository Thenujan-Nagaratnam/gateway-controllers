module github.com/Thenujan-Nagaratnam/gateway-controllers/policies/guardrails-ai

go 1.26.2

require github.com/wso2/api-platform/sdk/core v0.4.1

// TEMPORARY, local-checkout only: this policy uses utils.SharedHTTPClient, added to the
// local api-platform/sdk/core checkout but not yet published as a tagged release (see
// model-failover/go.mod for the same situation). Points sideways to the sibling
// api-platform checkout on this machine, not a subdirectory of this repo. Remove this
// replace once a tagged sdk/core release carrying SharedHTTPClient is available and this
// module's require above is bumped to it.
replace github.com/wso2/api-platform/sdk/core => ../../../api-platform/sdk/core
