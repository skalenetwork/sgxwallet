#!/bin/bash

set -euo pipefail

BUILD_TYPE="main"
for arg in "$@"; do
    case "$arg" in
        --build-type=*)
            BUILD_TYPE="${arg#--build-type=}"
            ;;
    esac
done

cd /usr/src/sdk

rm -rf \
    libBLS/deps/boost_1_* libBLS/deps/boost_1* libBLS/deps/openssl libBLS/deps/curl \
    libBLS/deps/gmp-6.1.2 libBLS/deps/libff libBLS/deps/jsoncpp \
    libBLS/deps/libjson-rpc-cpp libBLS/deps/libjson-rpc-cpp-develop \
    libBLS/deps/libmicrohttpd libBLS/deps/argtable2 libBLS/deps/zlib \
    libBLS/deps/pre_downloaded libBLS/deps/*.tar.* \
    libBLS/deps/deps_inst/x86_or_x64/include \
    libBLS/deps/deps_inst/x86_or_x64/share \
    libBLS/deps/deps_inst/x86_or_x64/bin \
    libBLS/build libBLS/test libBLS/docs \
    libzmq leveldb cppzmq rapidjson third_party \
    linux-sgx-driver intel-sgx-ssl jsonrpc \
    gmp-build tgmp-build sgx-gmp sgx-sdk-build \
    docs performance-tests \
    .deps secure_enclave/.deps autom4te.cache config.log \
    /opt/intel/sgxsdk/include /opt/intel/sgxsdk/SampleCode \
    /install_packages.sh /tmp/* /root/.cache

find . -name '*.o' -delete 2>/dev/null || true
find . -name '.git' -type d -exec rm -rf {} + 2>/dev/null || true
if [[ "${BUILD_TYPE}" != "simulation" ]]; then
    rm -f /opt/intel/sgxsdk/lib64/*_sim.so
fi
strip --strip-unneeded sgxwallet testw sgx_util tests/backward_compatibility/api_validator 2>/dev/null || true
