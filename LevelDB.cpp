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
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file LevelDB.cpp
    @author Stan Kladko
    @date 2019
*/

#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include <jsonrpccpp/client.h>

#include "LevelDB.h"
#include "SGXException.h"
#include "WalletDBKeys.h"
#include "sgxwallet_common.h"

#include "ServerInit.h"

#include "common.h"
#include "third_party/spdlog/spdlog.h"

using namespace leveldb;

static WriteOptions writeOptions;
static ReadOptions readOptions;

shared_ptr<string> LevelDB::readNewStyleValue(const string &value) {
  Json::Value key_data;
  Json::Reader reader;
  reader.parse(value.c_str(), key_data);

  return std::make_shared<string>(key_data["value"].asString());
}

std::shared_ptr<string> LevelDB::readString(std::string_view _key) {

  auto result = std::make_shared<string>();

  CHECK_STATE(db)

  auto status =
      db->Get(readOptions, Slice(_key.data(), _key.size()), result.get());

  throwExceptionOnError(status);

  if (status.IsNotFound()) {
    return nullptr;
  }

  if (result->at(0) == '{') {
    return readNewStyleValue(*result);
  }

  return result;
}

void LevelDB::writeString(std::string_view _key, const string &_value) {
  Json::Value writerData;
  writerData["value"] = _value;
  writerData["timestamp"] = std::to_string(std::time(nullptr));

  Json::FastWriter fastWriter;
  std::string output = fastWriter.write(writerData);

  auto status =
      db->Put(writeOptions, Slice(_key.data(), _key.size()), Slice(output));

  throwExceptionOnError(status);
}

void LevelDB::writeRawString(std::string_view _key, const string &_value) {
  auto status =
      db->Put(writeOptions, Slice(_key.data(), _key.size()), Slice(_value));

  throwExceptionOnError(status);
}

void LevelDB::writeBatch(const vector<pair<string, string>> &puts,
                         const vector<string> &deletes,
                         bool requireNewPutKeys) {
  lock_guard<recursive_mutex> lock(mutex);

  // make sure no keys with same names existed before
  if (requireNewPutKeys) {
    for (const auto &it : puts) {
      if (readString(it.first) != nullptr) {
        throw SGXException(KEY_NAME_ALREADY_EXISTS, string(__FUNCTION__) +
                                                        ":Name already exists" +
                                                        it.first);
      }
    }
  }

  leveldb::WriteBatch batch;
  Json::FastWriter fastWriter;

  for (const auto &it : puts) {
    Json::Value writerData;
    writerData["value"] = it.second;
    writerData["timestamp"] = std::to_string(std::time(nullptr));
    std::string output = fastWriter.write(writerData);

    batch.Put(Slice(it.first), Slice(output));
  }

  for (const auto &key : deletes) {
    batch.Delete(Slice(key));
  }

  auto status = db->Write(writeOptions, &batch);
  throwExceptionOnError(status);
}

void LevelDB::deleteDHDKGKey(std::string_view _key) {

  string full_key = string(WalletDBKeys::DKG_DH_KEY_PREFIX) + string(_key);

  auto status = db->Delete(writeOptions, Slice(full_key));

  throwExceptionOnError(status);
}

void LevelDB::deleteTempNEK(std::string_view _key) {

  CHECK_STATE(_key.compare(0, WalletDBKeys::TEMP_ECDSA_KEY_PREFIX.size(),
                           WalletDBKeys::TEMP_ECDSA_KEY_PREFIX) == 0);

  auto status = db->Delete(writeOptions, Slice(_key.data(), _key.size()));

  throwExceptionOnError(status);
}

void LevelDB::deleteKey(std::string_view _key) {

  auto status = db->Delete(writeOptions, Slice(_key.data(), _key.size()));

  throwExceptionOnError(status);
}

void LevelDB::throwExceptionOnError(Status _status) {
  if (_status.IsNotFound())
    return;

  if (!_status.ok()) {
    throw SGXException(
        COULD_NOT_ACCESS_DATABASE,
        ("Could not access database database:" + _status.ToString()).c_str());
  }
}

uint64_t LevelDB::visitKeys(LevelDB::KeyVisitor *_visitor,
                            uint64_t _maxKeysToVisit) {

  CHECK_STATE(_visitor);

  uint64_t readCounter = 0;

  unique_ptr<leveldb::Iterator> it(db->NewIterator(readOptions));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    _visitor->visitDBKey(it->key().data());
    readCounter++;
    if (readCounter >= _maxKeysToVisit) {
      break;
    }
  }

  return readCounter;
}

uint64_t LevelDB::visitKeyValues(LevelDB::KeyValueVisitor *_visitor,
                                 uint64_t _maxKeysToVisit) {

  CHECK_STATE(_visitor);

  uint64_t readCounter = 0;

  unique_ptr<leveldb::Iterator> it(db->NewIterator(readOptions));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    _visitor->visitDBKeyValue(it->key().ToString(), it->value().ToString());
    readCounter++;
    if (readCounter >= _maxKeysToVisit) {
      break;
    }
  }

  throwExceptionOnError(it->status());

  return readCounter;
}

std::vector<string> LevelDB::writeKeysToVector1(uint64_t _maxKeysToVisit) {
  uint64_t readCounter = 0;
  std::vector<string> keys;

  unique_ptr<leveldb::Iterator> it(db->NewIterator(readOptions));
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    string cur_key(it->key().data(), it->key().size());
    keys.push_back(cur_key);
    readCounter++;
    if (readCounter >= _maxKeysToVisit) {
      break;
    }
  }

  return keys;
}

void LevelDB::writeDataUnique(std::string_view name, const string &value) {
  if (readString(name)) {
    spdlog::debug("Name {} already exists", string(name));
    throw SGXException(KEY_SHARE_ALREADY_EXISTS,
                       "Data with this name already exists");
  }

  writeString(name, value);
}

pair<stringstream, uint64_t> LevelDB::getAllKeys() {
  stringstream keysInfo;

  unique_ptr<leveldb::Iterator> it(db->NewIterator(readOptions));
  uint64_t counter = 0;
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    ++counter;
    string key = it->key().ToString();
    string value;
    if (it->value().ToString()[0] == '{') {
      // new style keys
      Json::Value key_data;
      Json::Reader reader;
      reader.parse(it->value().ToString().c_str(), key_data);

      string timestamp_to_date_command =
          "date -d @" + key_data["timestamp"].asString();
      value = " VALUE: " + key_data["value"].asString() +
              ", TIMESTAMP: " + exec(timestamp_to_date_command.c_str()) + '\n';
    } else {
      // old style keys
      value = " VALUE: " + it->value().ToString();
    }
    keysInfo << "KEY: " << key << ',' << value;
  }

  return {std::move(keysInfo), counter};
}

pair<string, uint64_t> LevelDB::getLatestCreatedKey() {
  unique_ptr<leveldb::Iterator> it(db->NewIterator(readOptions));

  int64_t latest_timestamp = 0;
  string latest_created_key_name = "";
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    if (it->value().ToString()[0] == '{') {
      // new style keys
      Json::Value key_data;
      Json::Reader reader;
      reader.parse(it->value().ToString().c_str(), key_data);

      if (std::stoi(key_data["timestamp"].asString()) > latest_timestamp) {
        latest_timestamp = std::stoi(key_data["timestamp"].asString());
        latest_created_key_name = it->key().ToString();
      }
    } else {
      // old style keys
      // assuming server has at least one new-style key created
      continue;
    }
  }

  return {latest_created_key_name, latest_timestamp};
}

LevelDB::LevelDB(const string &filename) {
  leveldb::Options options;
  options.create_if_missing = true;

  leveldb::DB *raw_db = nullptr;
  if (!leveldb::DB::Open(options, filename, &raw_db).ok()) {
    throw std::runtime_error("Unable to open levelDB database");
  }

  if (raw_db == nullptr) {
    throw std::runtime_error("Null levelDB object");
  }

  db = shared_ptr<leveldb::DB>(raw_db);
}

LevelDB::~LevelDB() {}

const std::shared_ptr<LevelDB> &LevelDB::getLevelDb() {
  CHECK_STATE(levelDb)
  return levelDb;
}

const std::shared_ptr<LevelDB> &LevelDB::getCsrDb() {
  CHECK_STATE(csrDb)
  return csrDb;
}

const std::shared_ptr<LevelDB> &LevelDB::getCsrStatusDb() {
  CHECK_STATE(csrStatusDb)
  return csrStatusDb;
}

std::shared_ptr<LevelDB> LevelDB::levelDb = nullptr;

std::shared_ptr<LevelDB> LevelDB::csrDb = nullptr;

std::shared_ptr<LevelDB> LevelDB::csrStatusDb = nullptr;

string LevelDB::sgx_data_folder;

bool LevelDB::isInited = false;

void LevelDB::initDataFolderAndDBs() {
  CHECK_STATE(!isInited)
  isInited = true;

  spdlog::info("Initing wallet database ... ");

  char cwd[PATH_MAX];

  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    spdlog::error("Could not get current working directory.");
    throw SGXException(COULD_NOT_GET_WORKING_DIRECTORY,
                       "Could not get current working directory.");
  }

  sgx_data_folder = string(cwd) + "/" + SGXDATA_FOLDER;

  struct stat info;
  if (stat(sgx_data_folder.c_str(), &info) != 0) {
    spdlog::info("sgx_data folder does not exist. Creating ...");

    if (system(("mkdir " + sgx_data_folder).c_str()) == 0) {
      spdlog::info("Successfully created sgx_data folder");
    } else {
      spdlog::error("Could not create sgx_data folder.");
      throw SGXException(ERROR_CREATING_SGX_DATA_FOLDER,
                         "Could not create sgx_data folder.");
    }
  }

  spdlog::info("Opening wallet databases");

  auto dbName = sgx_data_folder + WALLETDB_NAME;
  levelDb = make_shared<LevelDB>(dbName);

  auto csr_dbname = sgx_data_folder + "CSR_DB";
  csrDb = make_shared<LevelDB>(csr_dbname);

  auto csr_status_dbname = sgx_data_folder + "CSR_STATUS_DB";
  csrStatusDb = make_shared<LevelDB>(csr_status_dbname);

  spdlog::info("Successfully opened databases");
}

void LevelDB::closeDataFolderAndDBs() {
  csrStatusDb.reset();
  csrDb.reset();
  levelDb.reset();
  isInited = false;
}

const string &LevelDB::getSgxDataFolder() { return sgx_data_folder; }
