cmake_minimum_required(VERSION 3.15)
project(sgxwallet_tests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Absolute, normalized path to the repository root (one level above tests/).
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(SGXSDK_INCLUDE_DIR "/opt/intel/sgxsdk/include" CACHE PATH "Intel SGX SDK include directory")

include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.10
)
FetchContent_MakeAvailable(Catch2)

# --- ADD THIS LINE ---
# This tells CMake where to find 'Catch.cmake' inside the downloaded source
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/contrib)

enable_testing()

add_library(test_suite OBJECT test_main.cpp)
# Note: In v2, the target is usually just 'Catch2', not 'Catch2::Catch2' 
# unless specifically aliased, but standard Catch2 works too.
target_link_libraries(test_suite PUBLIC Catch2)

add_subdirectory(unit)
# Integration tests require the full production dep tree (SGX, LevelDB, jsoncpp, etc.).
# They are built and run via Autotools: make testw && ./testw
# This will be wired into CMake when the root build is migrated from Autotools.
