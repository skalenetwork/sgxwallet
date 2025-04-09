# Checking memory leaks

The current test environment is configured to support memory leak detection exclusively via AddressSanitizer (ASan). 

> **Note:** Valgrind is not supported in the current environment due to incompatibilities with the SGX runtime, even when running in simulation mode.

## 1. Enable AddressSanitizer

### 1.1 Modify `Makefile.am` in root directory

Add the following flags:
- `-fsanitize=address` - enable AddressSanitizer
- `O0` - disable optimizations
- `-g` - Includes debug symbols

To both `AM_CFLAGS` and `AM_CXXFLAGS` in `Makefile.am` like so:
```make
(...)
AM_CFLAGS = -fsanitize=address -g -DUSER_SPACE -O0 -rdynamic -Wl,--no-as-needed -DSGXWALLET_VERSION="$(WALLET_VERSION)"
AM_CXXFLAGS = -fsanitize=address -g ${AM_CPPFLAGS} -O0 -rdynamic -Wl,--no-as-needed -DSGXWALLET_VERSION="$(WALLET_VERSION)"
(---)
```

### 1.2 Recompile

After having modified the automake file, recompile the project.

```bash
cd scripts

python3 build deps.py

./autoconf.bash

./configure --enable-sgx-simulation

make -j$(nproc)
```

## 2. Run all tests to check memory leaks

Before running the script to check for memory leaks, **please run all tests first** as described [here](testing.md).

Run all tests to check for memory leaks:

```bash
cd scripts
bash memory-leaks-test.sh
```