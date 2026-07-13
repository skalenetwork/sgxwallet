# Functional Tests

Tests require a simulation build configured with test binaries and test-only
ECALLs:

```bash
./autoconf.bash
./configure --enable-tests --enable-sgx-simulation
make -j"$(nproc)"
```

Omit `--enable-tests` for normal and release builds; `make` will then not build
any test binaries.

Tests can be run in two ways.

## Run all tests

To run all unit, integration, and backward-compatibility tests, run:
```
make check
```

The Catch2 portion of the default suite runs tests tagged `[unit]` or
`[integration]` and excludes tests tagged `[performance]`.

Container test runs use `make run-tests`, which executes the already-built
test binaries without requiring their build dependencies to remain in the
image after cleanup.

The legacy Python wrapper is still available during migration:
```
python3 testw.py
```


## Run individual tests
To run an individual integration test named `[test_ex]`:
```bash
./integration_tests [test_ex]
```

To run a full category:
```bash
./unit_tests "[unit]~[performance]" --reporter compact
./integration_tests "[integration]~[performance]" --reporter compact
```

We follow the convention of tagging tests by type, component, and scenario, for
example `[integration][te][te-decryption-share]`.

---

# DB Tests

## DB Unit Tests

DB unit tests are built by the top-level Autotools build. They do not require
an SGX enclave.

```bash
make unit_tests
./unit_tests "[unit]~[performance]" --reporter compact
```

## DB Reencryption Integration Tests

DB reencryption integration tests exercise the full SGX enclave plus LevelDB
reencryption path. They are part of `integration_tests`; `--enable-tests`
automatically selects the required test-only enclave interface.

```bash
source /opt/intel/sgxsdk/environment
./autoconf.bash
./configure --enable-tests --enable-sgx-simulation
make integration_tests
./integration_tests "[integration][db]~[performance]" --reporter compact
```

If running against hardware SGX instead of simulation mode, omit
`--enable-sgx-simulation`.

---

# Performance Tests

We provide a small test set to measure the performance of the `sgxwallet` server for the following operations:

- `getDecryptionShares`
- `blsSignMessageHash`
- `ecdsaSignMessageHash`

To run the tests, please follow the instructions in the [performance-tests/README.md](../../tests/performance/README.md).


---

# Backward Compatibility Tests

To test that new sgxwallet versions with udpated backends are still compatible with old versions, [see this document](../../tests/backward_compatibility/README.md)
