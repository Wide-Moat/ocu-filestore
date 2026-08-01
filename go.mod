module github.com/Wide-Moat/ocu-filestore

// The module directive stays on line 1 so tools that derive the module path
// from the first line of go.mod (go-gremlins v0.6.0's modPkg() calls
// TrimPrefix("module ") on the first line, not a real go.mod parser) resolve
// the true path and attribute coverage correctly. A leading comment block
// broke that: gremlins captured the comment text as the module name, so its
// coverage keys never matched the real package paths and every mutant was
// reported "Not covered"  -  a phantom 0/0 across every in-scope package. See
// .gremlins.yaml for the mutation-gate arming that this ordering unblocks.
//
// Dependency-policy note: this module reflects the public broker repo. Each
// dependency arrives through the architecture repo's dependency policy
// (license gate + supply-chain gate); see NOTICE for third-party license
// notices.

go 1.26.5

require (
	github.com/aws/aws-sdk-go-v2 v1.43.0
	github.com/aws/aws-sdk-go-v2/credentials v1.19.24
	github.com/aws/aws-sdk-go-v2/service/s3 v1.106.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.0
	github.com/aws/smithy-go v1.27.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	golang.org/x/text v0.40.0
	pgregory.net/rapid v1.3.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.32 // indirect
)
