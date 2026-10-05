module github.com/wso2/gateway-controllers/policies/openai-error-format

go 1.26.2

require github.com/wso2/api-platform/sdk/core v0.4.1

// Tracks the fault-policy contract (FaultPolicy, FaultContext, FaultResponse) from
// wso2/api-platform PR #3622, which no sdk/core release contains yet. Drop this line and
// bump the require above once that PR merges and sdk/core is tagged.
replace github.com/wso2/api-platform/sdk/core => ../../../../api-platform/sdk/core
