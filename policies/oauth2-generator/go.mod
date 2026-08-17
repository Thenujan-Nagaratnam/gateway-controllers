module github.com/wso2/gateway-controllers/policies/oauth2-generator

go 1.26.5

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/redis/go-redis/v9 v9.22.0
	github.com/wso2/api-platform/sdk/core v0.2.18
	golang.org/x/oauth2 v0.36.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

// TEMPORARY, local-validation only - see api-platform PR tracking issue.
// sdk/core v0.2.18 (required above) predates redisclient.Shared/Resolve/
// InitFromConfig, policy.UpstreamAttemptPolicy's OnUpstreamAttemptRequest
// rename, and RetryTriggerDeclaration - all on api-platform's main checkout
// (`decoupled-retry-source` branch) but not yet a tagged sdk/core release.
// Absolute, unlike the mirrored replace in api-platform's own dev-policies
// copy of this go.mod - this repo has no relative path to sdk/core, since
// it's a separate repo, not nested under api-platform. Remove this replace
// and bump the require above to a real tagged sdk/core release before
// merging.
replace github.com/wso2/api-platform/sdk/core => /Users/thenujan/Desktop/Git-Repos/api-platform/sdk/core
