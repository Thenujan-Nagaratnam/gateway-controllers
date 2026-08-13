module github.com/wso2/gateway-controllers/policies/model-failover

go 1.26.5

require github.com/wso2/api-platform/sdk/core v0.2.18

// TEMPORARY, local-validation only - see api-platform PR tracking issue.
// sdk/core v0.2.18 (required above) predates UpstreamAttemptContext.Body /
// UpstreamAttemptHeaderModifications.Body, added on api-platform's
// `redisclient` branch (main api-platform checkout, commit 6d659f270 "feat
// (sdk): add Body support to the upstream-attempt phase for model-failover")
// - NOT the separate `upstream-attempt-retry-refresh` worktree oauth2-generator
// points at, which predates the Body field and is for a different, earlier
// plan. Absolute, unlike the mirrored replace in api-platform's own
// dev-policies copy of this go.mod - this repo has no relative path to
// sdk/core, since it's a separate repo, not nested under api-platform.
// Remove this replace and bump the require above to a real tagged sdk/core
// release before merging.
replace github.com/wso2/api-platform/sdk/core => /Users/thenujan/Desktop/Git-Repos/api-platform/sdk/core
