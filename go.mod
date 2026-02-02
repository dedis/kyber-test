module github.com/dedis/kyber-test

go 1.25.0

//when working locally with a newer version, uncomment the following line
replace go.dedis.ch/kyber/v4 => ../kyber

require (
	github.com/stretchr/testify v1.11.1
	go.dedis.ch/kyber/v3 v3.1.0
	go.dedis.ch/kyber/v4 v4.0.1-alpha.1
	go.dedis.ch/protobuf v1.0.11
)

require (
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/consensys/gnark-crypto v0.19.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
