/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#define CATCH_CONFIG_MAIN
#include "../../../third_party/catch.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <experimental/filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <json/json.h>

#include "../../../CryptoTools.h"
#include "../../../DBReencrypt.h"
#include "../../../LevelDB.h"
#include "../../../SEKManager.h"
#include "../../../SGXException.h"
#include "../../../WalletDBKeys.h"
#include "../../../common.h"
#include "../../../secure_enclave_u.h"
#include "../../../sgxwallet.h"
#include "../../../sgxwallet_common.h"

namespace fs = std::experimental::filesystem;

namespace {

struct RawDBEntry {
  std::string rawValue;
  std::string payload;
};

using DBSnapshot = std::map<std::string, RawDBEntry>;

std::string uniqueTestRoot() {
  std::ostringstream os;
  os << fs::temp_directory_path().string() << "/sgxwallet-db-reencrypt-test."
     << getpid() << "." << std::time(nullptr);
  return os.str();
}

bool startsWith(std::string_view value, std::string_view prefix) {
  return value.compare(0, prefix.size(), prefix) == 0;
}

bool isSEKEncryptedPayloadKey(std::string_view key) {
  if (key == WalletDBKeys::TEST_KEY) {
    return true;
  }

  for (std::size_t i = 0;
       i < WalletDBKeys::SEK_ENCRYPTED_PAYLOAD_KEY_PREFIX_COUNT; ++i) {
    if (startsWith(key, WalletDBKeys::SEK_ENCRYPTED_PAYLOAD_KEY_PREFIXES[i])) {
      return true;
    }
  }

  return false;
}

// -------------------------------------------------------------
// Enclave / DB wrappers
// -------------------------------------------------------------

/**
 * @brief RAII guard that sets the process-wide runtime flags required for
 * non-interactive test execution (autoconfirm=true, enterBackupKey=false)
 * and restores their original values on destruction.
 */
class TestRuntimeFlagsGuard {
public:
  TestRuntimeFlagsGuard()
      : previousEnterBackupKey(enterBackupKey),
        previousAutoconfirm(autoconfirm) {
    enterBackupKey = false;
    autoconfirm = true;
  }

  ~TestRuntimeFlagsGuard() {
    enterBackupKey = previousEnterBackupKey;
    autoconfirm = previousAutoconfirm;
  }

private:
  bool previousEnterBackupKey;
  bool previousAutoconfirm;
};

/**
 * @brief RAII wrapper for the SGX enclave lifecycle in tests.
 *
 * Creates and initializes the enclave on construction and destroys it on
 * destruction. Exposes encryptWithSEK() to produce SEK-encrypted hex
 * ciphertext via the trusted ECALL, for use when seeding the DB with
 * realistic encrypted rows before a reencryption run.
 */
class EnclaveTestWrapper {
public:
  EnclaveTestWrapper() { init(); }
  ~EnclaveTestWrapper() { destroy(); }

  EnclaveTestWrapper(const EnclaveTestWrapper &) = delete;
  EnclaveTestWrapper &operator=(const EnclaveTestWrapper &) = delete;

  std::string encryptWithSEK(const std::string &plaintext) const {
    std::vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    std::vector<uint8_t> encrypted(BUF_LEN, 0);
    uint64_t encryptedLen = 0;

    sgx_status_t status = SGX_SUCCESS;
    {
      READ_LOCK(sgxInitMutex);
      status =
          trustedEncryptKey(eid, &errStatus, errMsg.data(), plaintext.c_str(),
                            encrypted.data(), &encryptedLen);
    }

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    std::vector<char> encryptedHex = carray2Hex(encrypted.data(), encryptedLen);
    return std::string(encryptedHex.data());
  }

#ifdef SGX_ENABLE_TEST_ECALLS

  /**
   * Decrypts encrypted_payload_hex using sek_hex inside the enclave and
   * checks whether the plaintext matches expected_plaintext.
   * Returns true on match.
   * Returns false when the payload does not match OR decryption fails
   * (e.g. wrong key, tampered ciphertext).
   * This call is placed under #ifdef SGX_ENABLE_TEST_ECALLS because
   * it requires 'trustedTestDecryptAndMatch' to be defined.
   * This test file should thus always be compiled with this macro set
   */
  bool decryptAndMatch(const std::string &sekHex,
                       const std::string &encryptedPayloadHex,
                       const std::string &expectedPlaintext) const {
    std::vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    int matches = 0;

    std::vector<uint8_t> encryptedPayload(BUF_LEN, 0);
    uint64_t encryptedPayloadLen = 0;
    REQUIRE(hex2carray(encryptedPayloadHex.c_str(), &encryptedPayloadLen,
                       encryptedPayload.data(), BUF_LEN));

    sgx_status_t status = SGX_SUCCESS;

    status = trustedTestDecryptAndMatch(
        eid, &errStatus, errMsg.data(), sekHex.c_str(), encryptedPayload.data(),
        encryptedPayloadLen, expectedPlaintext.c_str(), &matches);

    INFO("trustedTestDecryptAndMatch errMsg: " << errMsg.data());
    REQUIRE(status == SGX_SUCCESS);

    // Wrong-key decrypts are expected to fail for negative assertions.
    if (errStatus != 0) {
      return false;
    }

    return matches == 1;
  }

#endif

private:
  void init() {
    sgx_status_t status = SGX_SUCCESS;

    {
      WRITE_LOCK(sgxInitMutex);

      if (eid != 0) {
        sgx_destroy_enclave(eid);
        eid = 0;
      }

      updated = 0;
      status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token,
                                         &updated, &eid, nullptr);
    }

    REQUIRE(status == SGX_SUCCESS);

    status = trustedEnclaveInit(eid, L_INFO);
    REQUIRE(status == SGX_SUCCESS);
  }

  void destroy() {
    if (eid == 0) {
      return;
    }

    trustedEnclaveClear(eid);
    const sgx_status_t status = sgx_destroy_enclave(eid);
    if (status != SGX_SUCCESS) {
      WARN("sgx_destroy_enclave failed with status " << status);
    }

    eid = 0;
  }
};

std::string extractPayload(const std::string &rawValue) {
  if (rawValue.empty() || rawValue[0] != '{') {
    return rawValue;
  }

  Json::Value parsed;
  Json::CharReaderBuilder builder;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  std::string errors;
  REQUIRE(reader->parse(rawValue.data(), rawValue.data() + rawValue.size(),
                        &parsed, &errors));
  REQUIRE(parsed.isObject());
  REQUIRE(parsed.isMember("value"));

  return parsed["value"].asString();
}

void assertKeySetsMatch(const DBSnapshot &before, const DBSnapshot &after) {
  REQUIRE(before.size() == after.size());

  for (const auto &entry : before) {
    INFO("Missing key after reencryption: " << entry.first);
    REQUIRE(after.count(entry.first) == 1);
  }
}

void assertExpectedCiphertextChanges(const DBSnapshot &before,
                                     const DBSnapshot &after) {
  for (const auto &entry : before) {
    const std::string &key = entry.first;
    const RawDBEntry &beforeEntry = entry.second;
    const RawDBEntry &afterEntry = after.at(key);

    INFO("Checking DB key: " << key);
    if (key == WalletDBKeys::SEK || isSEKEncryptedPayloadKey(key)) {
      REQUIRE(beforeEntry.payload != afterEntry.payload);
    } else {
      REQUIRE(beforeEntry.rawValue == afterEntry.rawValue);
    }
  }
}

std::string readBackupSEK() {
  std::ifstream in(SGXWALLET_BACKUP_KEY_PATH);
  REQUIRE(in.good());

  std::string sek((std::istreambuf_iterator<char>(in)),
                  std::istreambuf_iterator<char>());
  sek.erase(std::remove_if(sek.begin(), sek.end(), ::isspace), sek.end());
  return sek;
}

/**
 * @brief Visitor that collects every key-value pair from LevelDB into a
 * DBSnapshot map. Both the raw stored bytes and the extracted payload
 * (unwrapped from any JSON envelope) are kept per entry.
 */
class SnapshotVisitor : public LevelDB::KeyValueVisitor {
public:
  DBSnapshot snapshot;

  void visitDBKeyValue(const std::string &key,
                       const std::string &rawValue) override {
    snapshot[key] = RawDBEntry{rawValue, extractPayload(rawValue)};
  }
};

/**
 * @brief RAII wrapper for the wallet LevelDB lifecycle in tests.
 *
 * Opens the data folder and initialises a fresh SEK on construction;
 * closes the DB on destruction. Exposes snapshot() to capture the full
 * DB state and writeRepresentativeRows() to seed it with a mixed set of
 * plain and SEK-encrypted entries covering all key prefixes under test.
 */
class WalletDBTestWrapper {
public:
  WalletDBTestWrapper() {
    LevelDB::initDataFolderAndDBs();
    initSEK();
  }

  ~WalletDBTestWrapper() {
    try {
      LevelDB::closeDataFolderAndDBs();
    } catch (...) {
    }
  }

  WalletDBTestWrapper(const WalletDBTestWrapper &) = delete;
  WalletDBTestWrapper &operator=(const WalletDBTestWrapper &) = delete;

  DBSnapshot snapshot() const {
    SnapshotVisitor visitor;
    LevelDB::getLevelDb()->visitKeyValues(&visitor,
                                          std::numeric_limits<uint64_t>::max());
    return visitor.snapshot;
  }

  void writeRepresentativeRows(const EnclaveTestWrapper &enclave) const {
    LevelDB::getLevelDb()->writeString("plain:config", "not-encrypted");
    LevelDB::getLevelDb()->writeString("plain:json", R"({"still":"copied"})");

    LevelDB::getLevelDb()->writeString("NEK:test",
                                       enclave.encryptWithSEK("ecdsa payload"));
    LevelDB::getLevelDb()->writeString(
        "tmp_NEK:test", enclave.encryptWithSEK("temporary ecdsa"));
    LevelDB::getLevelDb()->writeString("BLS_KEY:test",
                                       enclave.encryptWithSEK("bls payload"));
    LevelDB::getLevelDb()->writeString("POLY:test",
                                       enclave.encryptWithSEK("poly payload"));
    LevelDB::getLevelDb()->writeString("DKG_DH_KEY_test",
                                       enclave.encryptWithSEK("dh payload"));
  }
};

// -------------------------------------------------------------
// Test fixtures
// -------------------------------------------------------------

/**
 * @brief RAII guard that redirects the process working directory to an
 * isolated temporary folder for the duration of a test.
 *
 * On construction a unique directory under /tmp is created, the enclave
 * binary is copied into it (so the SGX loader can find it by relative
 * name after the CWD change), and the process CWD is switched there.
 * On destruction the original CWD is restored and the whole temp tree is
 * deleted, leaving no test artefacts on the filesystem.
 */
class TempWorkingDirectory {
public:
  TempWorkingDirectory()
      : originalPath(fs::current_path()), testRoot(uniqueTestRoot()) {
    fs::create_directories(testRoot);

    const fs::path enclaveSource = originalPath / ENCLAVE_NAME;
    const fs::path enclaveDestination = testRoot / ENCLAVE_NAME;

    REQUIRE(fs::exists(enclaveSource));
    fs::copy(enclaveSource, enclaveDestination,
             fs::copy_options::overwrite_existing);

    fs::current_path(testRoot);
  }

  ~TempWorkingDirectory() {
    try {
      fs::current_path(originalPath);
      fs::remove_all(testRoot);
    } catch (const std::exception &e) {
      WARN("Failed to clean up temporary test directory: " << e.what());
    }
  }

private:
  fs::path originalPath;
  fs::path testRoot;
};

/**
 * @brief Catch2 test fixture that fully wires up an isolated test
 * environment for DB reencryption integration tests.
 *
 * Member construction order is significant and intentional:
 *   1. TestRuntimeFlagsGuard  – enables non-interactive mode
 *   2. TempWorkingDirectory   – creates temp CWD and copies enclave binary
 *   3. EnclaveTestWrapper     – loads and initializes the SGX enclave
 *   4. WalletDBTestWrapper    – opens LevelDB and generates a fresh SEK
 *
 * Destruction happens in reverse order, giving each member a clean
 * teardown sequence.
 */
class DBReencryptIntegrationFixture {
public:
  void writeRepresentativeRows() { db.writeRepresentativeRows(enclave); }
  DBSnapshot snapshotWalletDB() const { return db.snapshot(); }
  const EnclaveTestWrapper &getEnclave() const { return enclave; }

private:
  TestRuntimeFlagsGuard runtimeFlags;
  TempWorkingDirectory workingDirectory;
  EnclaveTestWrapper enclave;
  WalletDBTestWrapper db;
};

} // namespace

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

// Plaintext values written by writeRepresentativeRows(), keyed by DB key.
static const std::map<std::string, std::string> EXPECTED_PLAINTEXT = {
    {"NEK:test", "ecdsa payload"},     {"tmp_NEK:test", "temporary ecdsa"},
    {"BLS_KEY:test", "bls payload"},   {"POLY:test", "poly payload"},
    {"DKG_DH_KEY_test", "dh payload"},
};

TEST_CASE_METHOD(DBReencryptIntegrationFixture,
                 "DB reencryption preserves keys, changes ciphertexts, and "
                 "keeps plaintexts identical",
                 "[integration][db][db-reencrypt]") {
  writeRepresentativeRows();

  const std::string oldSEK = readBackupSEK();
  const DBSnapshot before = snapshotWalletDB();

  DBReencryptor reencryptor;
  reencryptor.reencryptWithNewSEK();

  const std::string newSEK = readBackupSEK();
  const DBSnapshot after = snapshotWalletDB();

  // --- structural checks ---
  REQUIRE(oldSEK != newSEK);
  assertKeySetsMatch(before, after);
  assertExpectedCiphertextChanges(before, after);

  // --- plaintext preservation checks ---
  // For each encrypted payload key, verify that:
  //   1. old ciphertext decrypts correctly with the old SEK
  //   2. new ciphertext decrypts correctly with the new SEK
  //   3. new ciphertext does NOT decrypt with the old SEK
  for (const auto &[key, expectedPlaintext] : EXPECTED_PLAINTEXT) {
    INFO("Checking plaintext preservation for DB key: " << key);

    const std::string &oldCipherHex = before.at(key).payload;
    const std::string &newCipherHex = after.at(key).payload;

#ifdef SGX_ENABLE_TEST_ECALLS
    REQUIRE(
        getEnclave().decryptAndMatch(oldSEK, oldCipherHex, expectedPlaintext));
    REQUIRE(
        getEnclave().decryptAndMatch(newSEK, newCipherHex, expectedPlaintext));
#endif
    REQUIRE_FALSE(
        getEnclave().decryptAndMatch(oldSEK, newCipherHex, expectedPlaintext));
  }
}
