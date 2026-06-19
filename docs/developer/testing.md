# Functional Tests

Tests require SGXWallet to have been built locally in simulation mode, as described in [this document](building.md).

Tests can be run in two ways.

## Run all tests

To run all unit and integration tests that are part of the default check suite,
run:
```
make check
```

The default check suite runs Catch2 tests tagged `[unit]` or `[integration]`
and excludes tests tagged `[performance]`.

The legacy Python wrapper is still available during migration:
```
python3 testw.py
```


## Run individual tests
To run an individual integration test named `[test_ex]`:
```bash
./testw [test_ex]
```

To run a full category:
```bash
./unit_tests "[unit]~[performance]" --reporter compact
./testw "[integration]~[performance]" --reporter compact
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
reencryption path. These tests require a test enclave interface, so configure
with `--enable-sgx-test-ecalls`.

```bash
source /opt/intel/sgxsdk/environment
./autoconf.bash
./configure --enable-sgx-test-ecalls --enable-sgx-simulation
make db_reencrypt_integration_tests
./db_reencrypt_integration_tests "[integration]~[performance]" --reporter compact
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
