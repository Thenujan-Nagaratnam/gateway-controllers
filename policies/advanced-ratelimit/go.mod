module github.com/wso2/gateway-controllers/policies/advanced-ratelimit

go 1.26.2

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/google/cel-go v0.26.1
	github.com/redis/go-redis/v9 v9.22.0
	github.com/wso2/api-platform/sdk/core v0.2.4
)

require (
	cel.dev/expr v0.24.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20260112195511-716be5621a96 // indirect
	golang.org/x/sys v0.31.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260128011058-8636f8732409 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// TEMPORARY, local-validation only - see api-platform PR tracking issue.
// sdk/core v0.2.4 (required above) predates redisclient.Shared/Resolve/
// GetOrCreateRedisClient's TLS/protocol/credentials-provider hardening,
// added on api-platform's `redisclient` branch. Absolute, since this repo
// has no relative path to sdk/core - it's a separate repo, not nested under
// api-platform. Remove this replace and bump the require above to a real
// tagged sdk/core release before merging.
replace github.com/wso2/api-platform/sdk/core => /Users/thenujan/Desktop/Git-Repos/api-platform/sdk/core
