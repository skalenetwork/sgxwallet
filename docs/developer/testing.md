# Functional Tests

Tests require SGXWallet to have been built locally in simulation mode, as described in [this document](building.md).

Tests can be run in two ways. 

## Run all tests

To run over all tests, run:
```
python3 testw.py
```

Tests can be added to the script by simply adding the test name to the list of tests in the script.


## Run individual tests
To run an individual test named `[test_ex]`:
```bash
./testw [test_ex]
```

We follow the convention of naming tests like `[test-name]`.

---

# DB Tests

## DB Unit Tests

DB unit tests are built with the standalone CMake test project under `tests/`.
They do not require an SGX enclave.

```bash
cmake -S tests -B build-tests
cmake --build build-tests --target unit_tests -j"$(nproc)"
ctest --test-dir build-tests -L unit --output-on-failure
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
./db_reencrypt_integration_tests --reporter compact
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
