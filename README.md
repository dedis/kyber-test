# kyber-test

High level tests for the kyber library that verify serialization and deserialization compatibility across different versions.

## Overview

This repository contains tests that ensure cross-version compatibility of the [kyber cryptographic library](https://github.com/dedis/kyber). The tests verify that:

- Scalars and Points serialize to the same bytes in v3 and v4
- Data serialized by one version can be deserialized by the other
- Cryptographic operations (addition, multiplication, etc.) produce the same results
- Schnorr signatures are compatible across versions
- Diffie-Hellman key exchange works across versions

## Running Tests

```bash
go test -v ./...
```

## Tested Versions

- kyber v3.1.0
- kyber v4.0.1-alpha.1
git
## Test Coverage

### Serialization Tests (`serialization_test.go`)
- Scalar serialization/deserialization for v3 and v4
- Point serialization/deserialization for v3 and v4
- Cross-version scalar compatibility
- Cross-version point compatibility
- Base point and null point serialization
- Scalar operations compatibility (add, sub, mul, neg)
- Point operations compatibility (add, mul, neg)
- Marshal size verification

### Signature Tests (`signature_test.go`)
- Schnorr signature creation and verification in v3
- Schnorr signature creation and verification in v4
- Cross-version signature verification
- Diffie-Hellman key exchange compatibility
- Signature encoding format compatibility
