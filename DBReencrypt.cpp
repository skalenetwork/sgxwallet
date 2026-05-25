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

#include "DBReencrypt.h"

#include <ctime>
#include <experimental/filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <jsonrpccpp/client.h>

#include "CryptoTools.h"
#include "LevelDB.h"
#include "SEKManager.h"
#include "SGXException.h"
#include "ServerDataChecker.h"
#include "WalletDBKeys.h"
#include "common.h"
#include "sgxwallet.h"
#include "sgxwallet_common.h"
#include "third_party/spdlog/spdlog.h"

namespace fs = std::experimental::filesystem;

void DBReencryptor::reencryptWithNewSEK() {
  spdlog::info("Starting wallet DB reencryption with a new SEK");

  std::string oldSEKHex = readBackupSEK(SGXWALLET_BACKUP_KEY_PATH);

  // may throw if there is already a reencryption process occuring
  NewSEK newSEK = beginDBReencrypt(oldSEKHex);

  bool committed = false;

  // suffix using current time + pid
  const std::string suffix = migrationSuffix();

  const std::string walletDBPath = LevelDB::getSgxDataFolder() + WALLETDB_NAME;
  const std::string temporaryDBPath = walletDBPath + ".reencrypting" + suffix;
  const std::string backupDBPath = walletDBPath + ".before_reencrypt" + suffix;
  const std::string backupKeyBackupPath =
      std::string(SGXWALLET_BACKUP_KEY_PATH) + ".before_reencrypt" + suffix;

  try {
    // save tmp new SEK
    writeBackupSEKTmp(newSEK.plaintextHex, SGXWALLET_BACKUP_KEY_TMP_PATH);

    // write new DB with reencrypted values and new SEK
    MigrationStats stats =
        writeReencryptedWalletDB(temporaryDBPath, newSEK.sealedHex);

    LevelDB::closeDataFolderAndDBs();

    // only need to swap sgxwallet.db
    // csr DBs are not encrypted
    DBSwapState swapState{walletDBPath, temporaryDBPath, backupDBPath};

    try {
      swapWalletDB(swapState);
      commitDBReencrypt();
      committed = true;
    } catch (...) {
      if (!committed) {
        rollbackWalletDBSwapNoThrow(swapState);
      }
      throw;
    }

    replaceBackupSEKFile(backupKeyBackupPath);
    LevelDB::initDataFolderAndDBs();
    validate_SEK();

    spdlog::warn("ATTENTION! A new backup key has been written into {}. "
                 "Copy it to a safe place and then securely delete it. "
                 "Example command: apt-get install secure-delete && srm -vz {}",
                 SGXWALLET_BACKUP_KEY_PATH, SGXWALLET_BACKUP_KEY_PATH);

    spdlog::info(
        "Wallet DB reencryption complete. Encrypted entries: {} "
        "(reencrypted: {}, replaced-only: {}). Plaintext copied: {}. "
        "Previous wallet DB kept at {}. Previous SEK backup kept at {}",
        stats.encrypted, stats.reencrypted, stats.encrypted - stats.reencrypted,
        stats.plaintextCopied, backupDBPath, backupKeyBackupPath);
  } catch (...) {
    if (!committed) {
      abortDBReencryptNoThrow();
    }
    throw;
  }
}

// --------------------------------------------------
//                      Private
// --------------------------------------------------

std::string DBReencryptor::readBackupSEK(const std::string_view &path) const {
  if (!fs::is_regular_file(path)) {
    spdlog::error("File does not exist: {}", path);
    throw SGXException(FILE_NOT_FOUND, "Backup SEK file does not exist");
  }

  std::ifstream sekFile{std::string(path)};

  if (!sekFile) {
    throw SGXException(FILE_NOT_FOUND, "Could not read backup SEK file");
  }

  std::string sek((std::istreambuf_iterator<char>(sekFile)),
                  std::istreambuf_iterator<char>());
  boost::trim(sek);

  if (sek.size() != 32 || !checkHex(sek, 16)) {
    throw SGXException(SET_SEK_INVALID_SEK_HEX,
                       "Backup SEK must be a 32-character hex string");
  }

  return sek;
}

bool DBReencryptor::startsWith(std::string_view value,
                               std::string_view prefix) const {
  return value.compare(0, prefix.size(), prefix) == 0;
}

std::string DBReencryptor::migrationSuffix() const {
  return "." + std::to_string(std::time(nullptr)) + "." +
         std::to_string(getpid());
}

void DBReencryptor::writeBackupSEKTmp(std::string_view sekHex,
                                      std::string_view path) const {
  std::ofstream sekFile(std::string(path), std::ios::trunc);
  if (!sekFile) {
    throw SGXException(FILE_NOT_FOUND, "Could not open temporary SEK file");
  }

  sekFile << sekHex;
  sekFile.close();

  if (!sekFile) {
    throw SGXException(FILE_NOT_FOUND, "Could not write temporary SEK file");
  }
}

DBReencryptor::ParsedDBValue
DBReencryptor::parseDBValue(const std::string &rawValue) const {
  ParsedDBValue parsed;

  // value is json format (new format):
  // { "value": <actual value>, "timestamp": <timestamp> }
  if (!rawValue.empty() && rawValue[0] == '{') {
    Json::Reader reader;
    if (!reader.parse(rawValue, parsed.jsonValue) ||
        !parsed.jsonValue.isObject() || !parsed.jsonValue.isMember("value")) {
      throw SGXException(CORRUPT_DATABASE,
                         "Could not parse JSON wallet DB value");
    }

    parsed.newStyle = true;
    parsed.payload = parsed.jsonValue["value"].asString();
    return parsed;
  }

  // value is in old format - just the raw value without JSON wrapper
  parsed.payload = rawValue;
  return parsed;
}

std::string DBReencryptor::encodeDBValue(const ParsedDBValue &parsed,
                                         const std::string &payload) const {
  if (!parsed.newStyle) {
    return payload;
  }

  Json::Value jsonValue = parsed.jsonValue;
  jsonValue["value"] = payload;

  Json::FastWriter fastWriter;
  return fastWriter.write(jsonValue);
}

bool DBReencryptor::isKeyHoldingEncryptedValue(std::string_view key) const {
  if (key == WalletDBKeys::TEST_KEY) {
    return true;
  }

  for (size_t i = 0; i < WalletDBKeys::SEK_ENCRYPTED_PAYLOAD_KEY_PREFIX_COUNT;
       ++i) {
    if (startsWith(key, WalletDBKeys::SEK_ENCRYPTED_PAYLOAD_KEY_PREFIXES[i])) {
      return true;
    }
  }

  return false;
}

DBReencryptor::NewSEK
DBReencryptor::beginDBReencrypt(const std::string &oldSEKHex) const {
  std::vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  std::vector<uint8_t> encryptedNewSEK(SEALED_SEK_BUF_SIZE, 0);
  uint64_t encryptedNewSEKLen = 0;

  // SEK is 16 bytes (SGX_AESGCM_KEY_SIZE) -> 32 hex chars + null = 33 bytes.
  // Must match EDL declaration: [out, count = 33].
  std::vector<char> newSEKHex(33, 0);

  sgx_status_t status = SGX_SUCCESS;

  status = trustedBeginDBReencrypt(eid, &errStatus, errMsg.data(),
                                   oldSEKHex.c_str(), encryptedNewSEK.data(),
                                   &encryptedNewSEKLen, newSEKHex.data());

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

  if (strnlen(newSEKHex.data(), 33) != 32) {
    throw SGXException(-1, "Invalid generated SEK length");
  }

  std::vector<char> sealedHex =
      carray2Hex(encryptedNewSEK.data(), encryptedNewSEKLen);

  NewSEK newSEK;
  newSEK.sealedHex = std::string(sealedHex.data());
  newSEK.plaintextHex = std::string(newSEKHex.data());
  return newSEK;
}

std::string DBReencryptor::reencryptEncryptedPayloadHex(
    const std::string &encryptedPayloadHex) const {
  std::vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  std::vector<uint8_t> encryptedPayload(DB_REENCRYPT_PAYLOAD_BUF_SIZE, 0);
  std::vector<uint8_t> reencryptedPayload(DB_REENCRYPT_PAYLOAD_BUF_SIZE, 0);
  uint64_t encryptedPayloadLen = 0;
  uint64_t reencryptedPayloadLen = 0;

  if (encryptedPayloadHex.empty() ||
      !hex2carray(encryptedPayloadHex.c_str(), &encryptedPayloadLen,
                  encryptedPayload.data(), DB_REENCRYPT_PAYLOAD_BUF_SIZE)) {
    throw SGXException(CORRUPT_DATABASE,
                       "Invalid encrypted wallet DB payload hex");
  }

  sgx_status_t status = SGX_SUCCESS;

  status = trustedReencryptDBPayload(
      eid, &errStatus, errMsg.data(), encryptedPayload.data(),
      encryptedPayloadLen, reencryptedPayload.data(), &reencryptedPayloadLen);

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

  std::vector<char> reencryptedHex =
      carray2Hex(reencryptedPayload.data(), reencryptedPayloadLen);

  return std::string(reencryptedHex.data());
}

void DBReencryptor::commitDBReencrypt() const {
  std::vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;

  sgx_status_t status = SGX_SUCCESS;

  status = trustedCommitDBReencrypt(eid, &errStatus, errMsg.data());

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());
}

void DBReencryptor::abortDBReencryptNoThrow() const {
  try {
    std::vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;

    sgx_status_t status = SGX_SUCCESS;

    status = trustedAbortDBReencrypt(eid, &errStatus, errMsg.data());

    if (status != SGX_SUCCESS || errStatus != 0) {
      spdlog::error("trustedAbortDBReencrypt failed");
    }
  } catch (...) {
    spdlog::error("Could not abort DB reencryption inside enclave");
  }
}

class DBReencryptor::ReencryptVisitor : public LevelDB::KeyValueVisitor {
  DBReencryptor &reencryptor;
  LevelDB &destinationDB;
  const std::string &newSealedSEKHex;
  MigrationStats &stats;

public:
  ReencryptVisitor(DBReencryptor &_reencryptor, LevelDB &_destinationDB,
                   const std::string &_newSealedSEKHex, MigrationStats &_stats)
      : reencryptor(_reencryptor), destinationDB(_destinationDB),
        newSealedSEKHex(_newSealedSEKHex), stats(_stats) {}

  void visitDBKeyValue(const std::string &key,
                       const std::string &rawValue) override {
    // special case - SEK key needs to be replaced with new SEK value
    if (std::string_view(key) == WalletDBKeys::SEK) {
      destinationDB.writeString(key, newSealedSEKHex);
      stats.sawSEK = true;
      stats.encrypted++;
      return;
    }

    // If value is encrypted with old SEK, reencrypt with new SEK.
    if (reencryptor.isKeyHoldingEncryptedValue(key)) {
      ParsedDBValue parsed = reencryptor.parseDBValue(rawValue);
      std::string reencryptedPayload =
          reencryptor.reencryptEncryptedPayloadHex(parsed.payload);
      destinationDB.writeRawString(
          key, reencryptor.encodeDBValue(parsed, reencryptedPayload));
      stats.encrypted++;
      stats.reencrypted++;

      if (std::string_view(key) == WalletDBKeys::TEST_KEY) {
        stats.sawTestKey = true;
      }

      return;
    }

    destinationDB.writeRawString(key, rawValue);
    stats.plaintextCopied++;
  }
};

DBReencryptor::MigrationStats
DBReencryptor::writeReencryptedWalletDB(const std::string &temporaryDBPath,
                                        const std::string &newSealedSEKHex) {
  MigrationStats stats;

  if (fs::exists(temporaryDBPath)) {
    throw SGXException(COULD_NOT_ACCESS_DATABASE,
                       "Temporary wallet DB path already exists");
  }

  {
    LevelDB destinationDB(temporaryDBPath);
    ReencryptVisitor visitor(*this, destinationDB, newSealedSEKHex, stats);

    // go over all keys
    LevelDB::getLevelDb()->visitKeyValues(&visitor,
                                          std::numeric_limits<uint64_t>::max());

    // if DB didnt have SEK for some reason, add it to DB.
    // Else, it was already updated at the time of the 1st check
    if (!stats.sawSEK) {
      destinationDB.writeString(WalletDBKeys::SEK, newSealedSEKHex);
      stats.sawSEK = true;
    }
  }

  if (!stats.sawTestKey) {
    throw SGXException(CORRUPT_DATABASE,
                       std::string("Could not find ") +
                           std::string(WalletDBKeys::TEST_KEY) +
                           " in wallet database");
  }

  return stats;
}

void DBReencryptor::swapWalletDB(DBSwapState &swapState) const {
  fs::rename(swapState.sourcePath, swapState.backupPath);
  swapState.sourceMoved = true;

  fs::rename(swapState.temporaryPath, swapState.sourcePath);
  swapState.temporaryMoved = true;
}

void DBReencryptor::rollbackWalletDBSwapNoThrow(DBSwapState &swapState) const {
  try {
    if (swapState.temporaryMoved && fs::exists(swapState.sourcePath)) {
      fs::rename(swapState.sourcePath, swapState.temporaryPath + ".failed");
      swapState.temporaryMoved = false;
    }

    if (swapState.sourceMoved && fs::exists(swapState.backupPath) &&
        !fs::exists(swapState.sourcePath)) {
      fs::rename(swapState.backupPath, swapState.sourcePath);
      swapState.sourceMoved = false;
    }
  } catch (...) {
    spdlog::error("Could not roll back wallet DB directory swap");
  }
}

void DBReencryptor::replaceBackupSEKFile(
    const std::string &backupKeyBackupPath) const {
  bool oldBackupMoved = false;

  try {
    // move old backup key to backup location
    fs::rename(SGXWALLET_BACKUP_KEY_PATH, backupKeyBackupPath);
    oldBackupMoved = true;

    // move new tmp backup to real backup location
    fs::rename(SGXWALLET_BACKUP_KEY_TMP_PATH, SGXWALLET_BACKUP_KEY_PATH);
  } catch (...) {

    // if we moved old backup key but failed to move new backup key to real
    // backup location - put old backup key back to real location again
    if (oldBackupMoved && !fs::exists(SGXWALLET_BACKUP_KEY_PATH) &&
        fs::exists(backupKeyBackupPath)) {
      try {
        fs::rename(backupKeyBackupPath, SGXWALLET_BACKUP_KEY_PATH);
      } catch (...) {
        spdlog::error("Could not restore old SEK backup file");
      }
    }
    throw;
  }
}
