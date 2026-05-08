# Each unit test file is listed here. Add new test files to this list.
add_executable(unit_tests
    DBDecryptorTests.cpp
)

# Share the Catch2 main() defined in tests/test_main.cpp so that each
# test binary does not define CATCH_CONFIG_MAIN itself.
target_link_libraries(unit_tests PRIVATE test_suite)

target_sources(unit_tests PRIVATE
    ${REPO_ROOT}/DBReencrypt.cpp
    ${REPO_ROOT}/ServerDataChecker.cpp
    ${REPO_ROOT}/SGXException.cpp
)

target_include_directories(unit_tests PRIVATE
    ${REPO_ROOT}
    ${REPO_ROOT}/libBLS/deps/deps_inst/x86_or_x64/include
    ${SGXSDK_INCLUDE_DIR}
)

target_compile_options(unit_tests PRIVATE -ffunction-sections -fdata-sections)
target_link_options(unit_tests PRIVATE -Wl,--gc-sections)

target_link_libraries(unit_tests PRIVATE
    ${REPO_ROOT}/libBLS/deps/deps_inst/x86_or_x64/lib/libjsoncpp.a
    ${REPO_ROOT}/libBLS/deps/deps_inst/x86_or_x64/lib/libgmp.a
    stdc++fs
)

# Register each TEST_CASE individually with CTest for per-test output.
include(CTest)
include(Catch)
catch_discover_tests(unit_tests EXTRA_ARGS --reporter compact PROPERTIES LABELS unit)
