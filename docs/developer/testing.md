# Testing

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


# Backward Compatibility Tests

To test that new sgxwallet versions with udpated backends are still compatible with old versions, [see this document](../../compatibility_tests/README.md)