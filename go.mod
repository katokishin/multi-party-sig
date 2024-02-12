module github.com/taurusgroup/multi-party-sig

go 1.21

require (
	github.com/cronokirby/saferith v0.33.0
	github.com/decred/dcrd/dcrec/secp256k1/v3 v3.0.1
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/stretchr/testify v1.8.4
	github.com/zeebo/blake3 v0.2.3
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/assert v1.3.1 // indirect
	golang.org/x/sys v0.16.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/zeebo/blake3 => ./blake3
