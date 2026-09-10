module github.com/wso2/gateway-controllers/policies/model-failover

go 1.26.5

require github.com/wso2/api-platform/sdk/core v0.4.1

// TEMPORARY, local-checkout only: this policy now uses sdk/core fields (Body on
// DownstreamRequest, AttemptNumber/AttemptNumberHeader/CurrentAttemptNumber on
// SharedContext) added to the local api-platform/sdk/core checkout but not yet published as
// a tagged release. Points sideways to the sibling api-platform checkout on this machine,
// not a subdirectory of this repo. Remove this replace once a tagged sdk/core release
// carrying those additions is available and this module's require above is bumped to it.
replace github.com/wso2/api-platform/sdk/core => ../../../api-platform/sdk/core
