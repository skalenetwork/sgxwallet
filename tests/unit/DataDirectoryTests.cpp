#include "LevelDB.h"
#include "SGXException.h"
#include "SGXWalletServer.hpp"
#include "sgxwallet_common.h"
#include "third_party/catch.hpp"

#include <cstdlib>
#include <experimental/filesystem>
#include <fstream>
#include <functional>
#include <sys/stat.h>

namespace {
namespace fs = std::experimental::filesystem;

struct DataDirectoryFixture {
  fs::path originalDirectory = fs::current_path();
  fs::path temporaryDirectory;

  DataDirectoryFixture() {
    char path[] = "/tmp/sgxwallet data-directory.XXXXXX";
    const char *directory = mkdtemp(path);
    REQUIRE(directory != nullptr);
    temporaryDirectory = directory;
    fs::current_path(temporaryDirectory);
  }

  ~DataDirectoryFixture() {
    LevelDB::closeDataFolderAndDBs();
    fs::current_path(originalDirectory);
    fs::remove_all(temporaryDirectory);
  }
};

void requireError(const std::function<void()> &operation, int status,
                  const std::string &message) {
  try {
    operation();
    FAIL("Expected data directory validation to fail");
  } catch (const SGXException &error) {
    REQUIRE(error.getStatus() == status);
    REQUIRE(error.getErrString().find(message) != std::string::npos);
  }
}
} // namespace

TEST_CASE_METHOD(
    DataDirectoryFixture,
    "Data directory is created before databases and can be reopened",
    "[unit][data-directory]") {
  LevelDB::initDataFolderAndDBs();
  struct stat info;
  REQUIRE(stat("sgx_data", &info) == 0);
  REQUIRE(S_ISDIR(info.st_mode));
  REQUIRE((info.st_mode & 0777) == 0700);
  REQUIRE(LevelDB::getLevelDb() != nullptr);
  REQUIRE(LevelDB::getCsrStatusDb() != nullptr);

  LevelDB::closeDataFolderAndDBs();
  REQUIRE(chmod("sgx_data", 0750) == 0);
  LevelDB::initDataFolderAndDBs();
  REQUIRE(stat("sgx_data", &info) == 0);
  REQUIRE((info.st_mode & 0777) == 0750);
}

TEST_CASE_METHOD(DataDirectoryFixture,
                 "Certificate provisioning rejects a missing data directory",
                 "[unit][data-directory]") {
  requireError(SGXWalletServer::createCertsIfNeeded, FAIL_TO_CREATE_CERTIFICATE,
               "Initialize the data directory");
  REQUIRE_FALSE(fs::exists("sgx_data"));
  REQUIRE_FALSE(fs::exists("cert"));
}

TEST_CASE_METHOD(DataDirectoryFixture,
                 "Data directory validation rejects a file and allows retry",
                 "[unit][data-directory]") {
  std::ofstream("sgx_data") << "not a directory";
  requireError(LevelDB::initDataFolderAndDBs, ERROR_CREATING_SGX_DATA_FOLDER,
               "sgx_data");
  requireError(SGXWalletServer::createCertsIfNeeded, FAIL_TO_CREATE_CERTIFICATE,
               "sgx_data");
  REQUIRE(fs::remove("sgx_data"));
  REQUIRE_NOTHROW(LevelDB::initDataFolderAndDBs());
}

TEST_CASE_METHOD(
    DataDirectoryFixture,
    "Data directory validation reports inspection and creation failures",
    "[unit][data-directory]") {
  SECTION("Inspection failure") { fs::create_symlink("sgx_data", "sgx_data"); }
  SECTION("Creation failure") {
    fs::create_symlink("missing-directory", "sgx_data");
  }
  requireError(LevelDB::initDataFolderAndDBs, ERROR_CREATING_SGX_DATA_FOLDER,
               "Could not initialize data directory");
  requireError(SGXWalletServer::createCertsIfNeeded, FAIL_TO_CREATE_CERTIFICATE,
               "cannot access data directory");
  REQUIRE_THROWS(LevelDB::getLevelDb());
  REQUIRE_THROWS(LevelDB::getCsrStatusDb());
}

TEST_CASE_METHOD(
    DataDirectoryFixture,
    "Failed database initialization releases handles and allows retry",
    "[unit][data-directory]") {
  REQUIRE(fs::create_directory("sgx_data"));
  std::ofstream("sgx_data/CSR_STATUS_DB") << "not a database directory";
  REQUIRE_THROWS(LevelDB::initDataFolderAndDBs());
  REQUIRE_THROWS(LevelDB::getLevelDb());
  REQUIRE(fs::remove("sgx_data/CSR_STATUS_DB"));
  REQUIRE_NOTHROW(LevelDB::initDataFolderAndDBs());
}
