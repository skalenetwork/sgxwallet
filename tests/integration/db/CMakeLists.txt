# Integration tests for DB reencryption.
# Unlike unit tests, these require a live SGX enclave and LevelDB — they
# exercise the full encrypt/store/reencrypt/verify path end-to-end.
#
# NOT included in the standalone CMake test build (cmake -S tests -B build-tests).
# Build and run via Autotools instead: make testw && ./testw
# Will be wired into CMake when the root build is migrated from Autotools.
#
# This binary defines CATCH_CONFIG_MAIN itself so it does NOT link test_suite.
# Add new DB integration test files to the sources list below.

add_executable(db_reencrypt_integration_tests
    DBReencryptIntegrationTests.cpp
)

# Production sources exercised by these tests.
# All paths are relative to the project root.
target_sources(db_reencrypt_integration_tests PRIVATE
    ${REPO_ROOT}/CryptoTools.cpp
    ${REPO_ROOT}/DBReencrypt.cpp
    ${REPO_ROOT}/LevelDB.cpp
    ${REPO_ROOT}/SEKManager.cpp
    ${REPO_ROOT}/SGXException.cpp
    ${REPO_ROOT}/secure_enclave_u.c
    ${REPO_ROOT}/sgxwallet.c
)

target_include_directories(db_reencrypt_integration_tests PRIVATE
    ${REPO_ROOT}
    ${REPO_ROOT}/secure_enclave
)

# Link external libraries required by the production sources above.
# TODO: replace with the Find modules / imported targets used by the project.
target_link_libraries(db_reencrypt_integration_tests PRIVATE
    # sgx_urts          # SGX untrusted runtime
    # sgx_uae_service   # SGX platform service
    # leveldb           # LevelDB
    # jsoncpp           # JSON parsing (json/json.h)
    stdc++fs            # std::experimental::filesystem (GCC < 9)
)

# Register with CTest.
# Run only integration tests:  ctest -L integration
# Run only db subset:          ctest -R db_reencrypt
add_test(NAME db_reencrypt_integration_tests COMMAND db_reencrypt_integration_tests)
set_tests_properties(db_reencrypt_integration_tests PROPERTIES LABELS integration)
