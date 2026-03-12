# SGXWallet libff → mcl Compatibility Testing

This directory contains tools for ensuring compatibility when migrating sgxwallet from libff to any other version.

This document explains what is tested and how to run the validation tests for any new sgxwallet version.

## What is Tested?

Test coverage includes 20 different API calls. The majority tests deterministically. Since there are non-deterministic API calls, we only test for correctness on those (i.e, we check the returned structure is the expected)

### Deterministic Tests - CRITICAL
These **must** produce byte-identical outputs with the same inputs:

| Method | What it validates |
|--------|-------------------|
| `getBLSPublicKeyShare` | BLS key → public key derivation |
| `blsSignMessageHash` | BLS signatures are identical |
| `getPublicECDSAKey` | ECDSA key → public key derivation |
| `multG2` | G2 scalar multiplication (core curve op) |
| `popProve` | BLS proof of possession |
| `dkgVerification` | DKG share verification math |
| `createBLSPrivateKey` | BLS key reconstruction from shares |
| `dkgVerificationV2` | DKG verification (V2 protocol) |
| `createBLSPrivateKeyV2` | BLS key reconstruction (V2) |
| `calculateAllBLSPublicKeys` | BLS public key aggregation |

### Functional Tests - API CORRECTNESS
These involve randomness - validate structure and success:

| Method | Why functional (not deterministic) |
|--------|-----------------------------------|
| `importBLSKeyShare` | Encryption uses random SEK |
| `generateECDSAKey` | Random key generation |
| `generateDKGPoly` | Random polynomial coefficients |
| `getVerificationVector` | Depends on random poly |
| `importECDSAKey` | Encryption uses random SEK |
| `ecdsaSignMessageHash` | ECDSA uses random k value |
| `generateBLSPrivateKey` | Random key generation |
| `getSecretShare` | Depends on random poly |
| `getSecretShareV2` | Depends on random poly |
| `complaintResponse` | Depends on random poly |

## Quick Start

To run the tests, you need to do 2 separate steps:

### 1: Generate test binaries
```bash
cd compatibility_tests
make all
```

### 2: Generate Golden Vectors (libff build)

```bash
# 1. Build sgxwallet with libff backend (see the build commands)


# 2. Clean database and start server
rm -rf sgx_data/
./sgxwallet -n -s -y -d -V
# Wait for server to start

# 3. (in a separate terminal) Generate golden vectors
cd compatibility_tests
./api_golden_generator > api_golden_vectors.json

# 4. Verify all 20 tests completed (the tool prints to the terminal)
```

### 3: Validate Compatibility (new backend)

```bash
# 1. Build sgxwallet with mcl or any newer backend

# 2. Clean database and start server
rm -rf sgx_data/
./sgxwallet -n -s -y -d -V

# 3. (in a separate terminal) Run validator
cd compatibility_tests
./api_validator api_golden_vectors.json

# 4. Check results
# ✓ All tests pass = New backend is 100% compatible!
# ✗ Any failures = Incompatibility found, review output
```

### Clean
```bash
make clean
```


## Files

### Production Tools
- **`api_golden_generator.cpp`** - Captures API responses from libff build & generates golden vec json
- **`api_validator.cpp`** - Validates mcl build against golden vectors
- **`api_golden_vectors.json`** - Generated test data
