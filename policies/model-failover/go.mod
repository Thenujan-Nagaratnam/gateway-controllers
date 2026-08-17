module github.com/wso2/gateway-controllers/policies/model-failover

go 1.26.5

require github.com/wso2/api-platform/sdk/core v0.2.18

// TEMPORARY, local-validation only - see api-platform PR tracking issue.
// sdk/core v0.2.18 (required above) predates policy.RetrySourceUpstreamName,
// policy.UpstreamAttemptPolicy's OnUpstreamAttemptRequest rename, and
// UpstreamAttemptContext.Body/UpstreamAttemptRequestModifications.Body - all
// on api-platform's main checkout (`decoupled-retry-source` branch) but not
// yet a tagged sdk/core release. Absolute, unlike the mirrored replace in
// api-platform's own dev-policies copy of this go.mod - this repo has no
// relative path to sdk/core, since it's a separate repo, not nested under
// api-platform. Remove this replace and bump the require above to a real
// tagged sdk/core release before merging.
replace github.com/wso2/api-platform/sdk/core => /Users/thenujan/Desktop/Git-Repos/api-platform/sdk/core
