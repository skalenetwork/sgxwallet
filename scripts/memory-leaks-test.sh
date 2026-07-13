#!/bin/bash

### This script tests for memory leaks by running the integration test suite.

### The script assumes the following:
### 1. SGXWallet was compiled using address sanitizer & is reporting the leaks in stdout / stderr
### 2. The script does not validate the project has been compiled with aSan correctly - please validate this


# Script will be executed in the project root.
TEST_EXECUTABLE="./integration_tests"
TEST_FILTER="[integration]~[performance]"

cd ..

echo "Memory Leak Detection Results"
echo "============================"
echo

# Run the integration suite and extract leak information.
echo "Running test filter: $TEST_FILTER"
output=$("$TEST_EXECUTABLE" "$TEST_FILTER" 2>&1)

# Check if the test passed or failed
if echo "$output" | grep -q "passed"; then
    echo "Test passed"
else
    echo "Test failed"
fi

# Extract only the leak-related information
leak_info=$(echo "$output" | awk '/=+ERROR: .*Sanitizer:/, /SUMMARY: AddressSanitizer:/')

# Check if leak info exists
if [ -n "$leak_info" ]; then
    echo "$leak_info"
else
    echo "No memory leaks detected"
fi
# go back to where it was
cd -
