#!/bin/bash

### This script tests for memory leaks by running all
### the tests in the test list in the testw.py script

### The script assumes the following:
### 1. The testw.py has all the test names in a list in thte format ["test1", "test2", ...]
### 2. SGXWallet was compiled using address sanitizer & is reporting the leaks in stdout / stderr
### 3. The script does not validate the project has been compiled with aSan correctly - please validate this


# Path to the Python script containing the testList
# Script will be executed in root directory - set paths according to root directory
PYTHON_SCRIPT="./testw.py"
TEST_EXECUTABLE="./testw"

cd ..

# Extract test names using grep and regex
tests=($(grep -o '"\[.*\]"' "$PYTHON_SCRIPT" | tr -d ' ",'))

echo "Memory Leak Detection Results"
echo "============================"
echo

# Run each test and extract leak information
for test in "${tests[@]}"; do
    echo "Running test: $test"
    # Run the test and capture the output
    output=$("$TEST_EXECUTABLE" "$test" 2>&1)

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
    echo "----------------------------"
    echo
done
# go back to where it was
cd - 