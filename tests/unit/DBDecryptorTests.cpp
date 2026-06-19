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

#include "third_party/catch.hpp"

#include <ctime>
#include <experimental/filesystem>
#include <fstream>
#include <memory>
#include <regex>
#include <sstream>
#include <unistd.h>

#include <json/json.h>

#include "../../DBReencrypt.h"
#include "../../SGXException.h"
#include "../../WalletDBKeys.h"

namespace fs = std::experimental::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Access private methods via friendship declared in DBReencrypt.h
class DBReencryptorTests {
  DBReencryptor r;

public:
  std::string readBackupSEK(const std::string &path) {
    return r.readBackupSEK(path);
  }

  std::string migrationSuffix() { return r.migrationSuffix(); }

  void writeBackupSEKTmp(const std::string &sekHex, const std::string &path) {
    r.writeBackupSEKTmp(sekHex, path);
  }

  // Expose parseDBValue
  DBReencryptor::ParsedDBValue parseDBValue(const std::string &raw) {
    return r.parseDBValue(raw);
  }

  // Expose encodeDBValue
  std::string encodeDBValue(const DBReencryptor::ParsedDBValue &parsed,
                            const std::string &payload) {
    return r.encodeDBValue(parsed, payload);
  }

  // Expose isKeyHoldingEncryptedValue
  bool isKeyHoldingEncryptedValue(std::string_view key) {
    return r.isKeyHoldingEncryptedValue(key);
  }

  // Expose startsWith
  bool startsWith(std::string_view value, std::string_view prefix) {
    return r.startsWith(value, prefix);
  }

  void swapWalletDB(const std::string &sourcePath,
                    const std::string &temporaryPath,
                    const std::string &backupPath) {
    DBReencryptor::DBSwapState swapState{sourcePath, temporaryPath, backupPath};
    r.swapWalletDB(swapState);
  }

  void rollbackWalletDBSwapNoThrow(const std::string &sourcePath,
                                   const std::string &temporaryPath,
                                   const std::string &backupPath,
                                   bool sourceMoved, bool temporaryMoved) {
    DBReencryptor::DBSwapState swapState{sourcePath, temporaryPath, backupPath,
                                         sourceMoved, temporaryMoved};
    r.rollbackWalletDBSwapNoThrow(swapState);
  }
};

static std::string makeTempPath(const std::string &prefix) {
  std::ostringstream os;
  os << fs::temp_directory_path().string() << "/" << prefix << "." << getpid()
     << "." << std::to_string(std::time(nullptr));
  return os.str();
}

static Json::Value parseJson(const std::string &value) {
  Json::Value parsed;
  Json::CharReaderBuilder builder;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  std::string errors;
  REQUIRE(reader->parse(value.data(), value.data() + value.size(), &parsed,
                        &errors));
  return parsed;
}

// ---------------------------------------------------------------------------
// parseDBValue
// ---------------------------------------------------------------------------

TEST_CASE("parseDBValue - old style: plain payload is returned as-is",
          "[unit][DBReencryptor][parseDBValue]") {
  DBReencryptorTests t;
  auto parsed = t.parseDBValue("deadbeef0123456789abcdef");

  REQUIRE(parsed.newStyle == false);
  REQUIRE(parsed.payload == "deadbeef0123456789abcdef");
}

TEST_CASE("parseDBValue - new style: extracts value from JSON wrapper",
          "[unit][DBReencryptor][parseDBValue]") {
  DBReencryptorTests t;
  auto parsed = t.parseDBValue(
      R"({"value":"deadbeef0123456789abcdef","timestamp":"1746547200"})");

  REQUIRE(parsed.newStyle == true);
  REQUIRE(parsed.payload == "deadbeef0123456789abcdef");
}

TEST_CASE(
    "parseDBValue - new style: preserves full JSON object for re-encoding",
    "[unit][DBReencryptor][parseDBValue]") {
  DBReencryptorTests t;
  auto parsed =
      t.parseDBValue(R"({"value":"aabbcc","timestamp":"1746547200"})");

  REQUIRE(parsed.jsonValue.isMember("timestamp"));
  REQUIRE(parsed.jsonValue["timestamp"].asString() == "1746547200");
}

TEST_CASE("parseDBValue - empty string is treated as old style",
          "[unit][DBReencryptor][parseDBValue]") {
  DBReencryptorTests t;
  auto parsed = t.parseDBValue("");

  REQUIRE(parsed.newStyle == false);
  REQUIRE(parsed.payload == "");
}

TEST_CASE(
    "parseDBValue - malformed JSON starting with '{' throws CORRUPT_DATABASE",
    "[unit][DBReencryptor][parseDBValue]") {
  DBReencryptorTests t;
  REQUIRE_THROWS_AS(t.parseDBValue("{not valid json}"), SGXException);
}

TEST_CASE("parseDBValue - valid JSON but missing 'value' field throws "
          "CORRUPT_DATABASE",
          "[unit][DBReencryptor][parseDBValue]") {
  DBReencryptorTests t;
  REQUIRE_THROWS_AS(t.parseDBValue(R"({"timestamp":"123"})"), SGXException);
}

// ---------------------------------------------------------------------------
// encodeDBValue
// ---------------------------------------------------------------------------

TEST_CASE("encodeDBValue - old style: returns new payload directly",
          "[unit][DBReencryptor][encodeDBValue]") {
  DBReencryptorTests t;
  auto parsed = t.parseDBValue("old_payload");

  std::string encoded = t.encodeDBValue(parsed, "new_payload");
  REQUIRE(encoded == "new_payload");
}

TEST_CASE("encodeDBValue - new style: replaces value field, keeps other fields",
          "[unit][DBReencryptor][encodeDBValue]") {
  DBReencryptorTests t;
  auto parsed =
      t.parseDBValue(R"({"value":"old_payload","timestamp":"1746547200"})");

  std::string encoded = t.encodeDBValue(parsed, "new_payload");

  Json::Value encodedJson = parseJson(encoded);
  REQUIRE(encodedJson["value"].asString() == "new_payload");
  REQUIRE(encodedJson["timestamp"].asString() == "1746547200");
}

TEST_CASE("encodeDBValue - roundtrip: parse then re-encode with same payload",
          "[unit][DBReencryptor][encodeDBValue]") {
  DBReencryptorTests t;
  std::string original = R"({"value":"abc123","timestamp":"999"})";
  auto parsed = t.parseDBValue(original);
  std::string encoded = t.encodeDBValue(parsed, "abc123");
  Json::Value encodedJson = parseJson(encoded);
  REQUIRE(encodedJson["value"].asString() == "abc123");
  REQUIRE(encodedJson["timestamp"].asString() == "999");

  auto reparsed = t.parseDBValue(encoded);
  REQUIRE(reparsed.payload == "abc123");
}

// ---------------------------------------------------------------------------
// isKeyHoldingEncryptedValue
// ---------------------------------------------------------------------------

TEST_CASE("isKeyHoldingEncryptedValue - TEST_KEY is encrypted",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE(t.isKeyHoldingEncryptedValue(WalletDBKeys::TEST_KEY));
}

TEST_CASE("isKeyHoldingEncryptedValue - NEK: prefix matches",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE(t.isKeyHoldingEncryptedValue("NEK:0x1234abc"));
}

TEST_CASE("isKeyHoldingEncryptedValue - tmp_NEK prefix matches",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE(t.isKeyHoldingEncryptedValue("tmp_NEKsomesuffix"));
}

TEST_CASE("isKeyHoldingEncryptedValue - BLS_KEY: prefix matches",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE(t.isKeyHoldingEncryptedValue("BLS_KEY:node1:1:5:1:2"));
}

TEST_CASE("isKeyHoldingEncryptedValue - POLY: prefix matches",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE(t.isKeyHoldingEncryptedValue("POLY:xyz"));
}

TEST_CASE("isKeyHoldingEncryptedValue - DKG_DH_KEY_ prefix matches",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE(t.isKeyHoldingEncryptedValue("DKG_DH_KEY_abc"));
}

TEST_CASE(
    "isKeyHoldingEncryptedValue - SEK key is NOT an encrypted payload key",
    "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE_FALSE(t.isKeyHoldingEncryptedValue(WalletDBKeys::SEK));
}

TEST_CASE("isKeyHoldingEncryptedValue - unknown key is not encrypted",
          "[unit][DBReencryptor][isKeyHoldingEncryptedValue]") {
  DBReencryptorTests t;
  REQUIRE_FALSE(t.isKeyHoldingEncryptedValue("SOME_RANDOM_KEY"));
  REQUIRE_FALSE(t.isKeyHoldingEncryptedValue("CSR_abc"));
  REQUIRE_FALSE(t.isKeyHoldingEncryptedValue(""));
}

// ---------------------------------------------------------------------------
// migrationSuffix
// ---------------------------------------------------------------------------

TEST_CASE("migrationSuffix - has expected format .<timestamp>.<pid>",
          "[unit][DBReencryptor][migrationSuffix]") {
  DBReencryptorTests t;
  std::string suffix = t.migrationSuffix();

  REQUIRE(std::regex_match(suffix, std::regex("^\\.[0-9]+\\.[0-9]+$")));
  REQUIRE(suffix.rfind("." + std::to_string(getpid())) != std::string::npos);
}

// ---------------------------------------------------------------------------
// writeBackupSEKTmp / readBackupSEK
// ---------------------------------------------------------------------------

TEST_CASE("writeBackupSEKTmp - writes content and truncates existing file",
          "[unit][DBReencryptor][writeBackupSEKTmp]") {
  DBReencryptorTests t;
  const std::string tempPath = makeTempPath("dbreencrypt.backupsek.tmp");

  try {
    t.writeBackupSEKTmp("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", tempPath);
    t.writeBackupSEKTmp("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", tempPath);

    std::ifstream in(tempPath);
    REQUIRE(in.good());
    std::string content((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    REQUIRE(content == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  } catch (...) {
    if (fs::exists(tempPath)) {
      fs::remove(tempPath);
    }
    throw;
  }

  fs::remove(tempPath);
}

TEST_CASE("readBackupSEK - trims whitespace and validates hex",
          "[unit][DBReencryptor][readBackupSEK]") {
  DBReencryptorTests t;
  const std::string tempPath = makeTempPath("dbreencrypt.readsek.valid");

  try {
    std::ofstream out(tempPath, std::ios::trunc);
    out << "  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    out.close();

    std::string sek = t.readBackupSEK(tempPath);
    REQUIRE(sek == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  } catch (...) {
    if (fs::exists(tempPath)) {
      fs::remove(tempPath);
    }
    throw;
  }

  fs::remove(tempPath);
}

TEST_CASE("readBackupSEK - throws for missing file",
          "[unit][DBReencryptor][readBackupSEK]") {
  DBReencryptorTests t;
  const std::string missingPath = makeTempPath("dbreencrypt.readsek.missing");
  if (fs::exists(missingPath)) {
    fs::remove(missingPath);
  }

  REQUIRE_THROWS_AS(t.readBackupSEK(missingPath), SGXException);
}

TEST_CASE("readBackupSEK - throws for invalid SEK length",
          "[unit][DBReencryptor][readBackupSEK]") {
  DBReencryptorTests t;
  const std::string tempPath = makeTempPath("dbreencrypt.readsek.badlen");

  try {
    std::ofstream out(tempPath, std::ios::trunc);
    out << "abcdef";
    out.close();

    REQUIRE_THROWS_AS(t.readBackupSEK(tempPath), SGXException);
  } catch (...) {
    if (fs::exists(tempPath)) {
      fs::remove(tempPath);
    }
    throw;
  }

  fs::remove(tempPath);
}

TEST_CASE("readBackupSEK - throws for non-hex SEK",
          "[unit][DBReencryptor][readBackupSEK]") {
  DBReencryptorTests t;
  const std::string tempPath = makeTempPath("dbreencrypt.readsek.badhex");

  try {
    std::ofstream out(tempPath, std::ios::trunc);
    out << "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    out.close();

    REQUIRE_THROWS_AS(t.readBackupSEK(tempPath), SGXException);
  } catch (...) {
    if (fs::exists(tempPath)) {
      fs::remove(tempPath);
    }
    throw;
  }

  fs::remove(tempPath);
}

// ---------------------------------------------------------------------------
// swapWalletDB / rollbackWalletDBSwapNoThrow
// ---------------------------------------------------------------------------

TEST_CASE("swapWalletDB - swaps source and temporary DB paths",
          "[unit][DBReencryptor][swapWalletDB]") {
  DBReencryptorTests t;
  const std::string root = makeTempPath("dbreencrypt.swap");
  const std::string sourcePath = root + "/source.db";
  const std::string temporaryPath = root + "/temporary.db";
  const std::string backupPath = root + "/backup.db";

  try {
    fs::create_directories(sourcePath);
    fs::create_directories(temporaryPath);

    std::ofstream(sourcePath + "/marker.txt") << "old";
    std::ofstream(temporaryPath + "/marker.txt") << "new";

    t.swapWalletDB(sourcePath, temporaryPath, backupPath);

    REQUIRE(fs::exists(sourcePath));
    REQUIRE(fs::exists(backupPath));
    REQUIRE(!fs::exists(temporaryPath));

    std::ifstream activeMarker(sourcePath + "/marker.txt");
    std::ifstream backupMarker(backupPath + "/marker.txt");
    std::string activeContent;
    std::string backupContent;
    activeMarker >> activeContent;
    backupMarker >> backupContent;
    REQUIRE(activeContent == "new");
    REQUIRE(backupContent == "old");
  } catch (...) {
    if (fs::exists(root)) {
      fs::remove_all(root);
    }
    throw;
  }

  fs::remove_all(root);
}

TEST_CASE(
    "rollbackWalletDBSwapNoThrow - restores original DB and keeps failed DB",
    "[unit][DBReencryptor][rollbackWalletDBSwapNoThrow]") {
  DBReencryptorTests t;
  const std::string root = makeTempPath("dbreencrypt.rollback");
  const std::string sourcePath = root + "/source.db";
  const std::string temporaryPath = root + "/temporary.db";
  const std::string backupPath = root + "/backup.db";
  const std::string failedPath = temporaryPath + ".failed";

  try {
    fs::create_directories(sourcePath);
    fs::create_directories(backupPath);

    // simulate source has new DB, backup has old DB
    std::ofstream(sourcePath + "/marker.txt") << "new";
    std::ofstream(backupPath + "/marker.txt") << "old";

    t.rollbackWalletDBSwapNoThrow(sourcePath, temporaryPath, backupPath, true,
                                  true);

    // rollback should restore source from backup, and move failed new DB to
    // temporaryPath.failed
    REQUIRE(fs::exists(sourcePath));
    REQUIRE(fs::exists(failedPath));
    REQUIRE(!fs::exists(backupPath));

    std::ifstream activeMarker(sourcePath + "/marker.txt");
    std::ifstream failedMarker(failedPath + "/marker.txt");
    std::string activeContent;
    std::string failedContent;
    activeMarker >> activeContent;
    failedMarker >> failedContent;
    REQUIRE(activeContent == "old");
    REQUIRE(failedContent == "new");
  } catch (...) {
    if (fs::exists(root)) {
      fs::remove_all(root);
    }
    throw;
  }

  fs::remove_all(root);
}

// ---------------------------------------------------------------------------
// startsWith
// ---------------------------------------------------------------------------

TEST_CASE("startsWith - matches exact prefix", "[unit][DBReencryptor][startsWith]") {
  DBReencryptorTests t;
  REQUIRE(t.startsWith("NEK:foo", "NEK:"));
}

TEST_CASE("startsWith - empty prefix always matches",
          "[unit][DBReencryptor][startsWith]") {
  DBReencryptorTests t;
  REQUIRE(t.startsWith("anything", ""));
}

TEST_CASE("startsWith - no match when value is shorter than prefix",
          "[unit][DBReencryptor][startsWith]") {
  DBReencryptorTests t;
  REQUIRE_FALSE(t.startsWith("NE", "NEK:"));
}

TEST_CASE("startsWith - no match for wrong prefix",
          "[unit][DBReencryptor][startsWith]") {
  DBReencryptorTests t;
  REQUIRE_FALSE(t.startsWith("BLS_KEY:x", "NEK:"));
}
