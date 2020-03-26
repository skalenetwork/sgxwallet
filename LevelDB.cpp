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


#include <stdexcept>
#include <memory>
#include <string>
#include <iostream>


#include "leveldb/db.h"

#include "sgxwallet_common.h"
#include "RPCException.h"
#include "LevelDB.h"

#include "ServerInit.h"

#include "spdlog/spdlog.h"
#include "common.h"


using namespace leveldb;



static WriteOptions writeOptions;
static ReadOptions readOptions;




std::shared_ptr<string> LevelDB::readString(const string &_key) {

    std::lock_guard<std::recursive_mutex> lock(mutex);

    auto result = std::make_shared<string>();

    if (db == nullptr) {
        throw RPCException(NULL_DATABASE, "Null db");
    }

    auto status = db->Get(readOptions, _key, &*result);


      spdlog::debug("key to read from db: {}",_key );
      //std::cerr << "key to read from db: " << _key << std::endl;


    throwExceptionOnError(status);

    if (status.IsNotFound())
        return nullptr;

    return result;
}

void LevelDB::writeString(const string &_key, const string &_value) {

    std::lock_guard<std::recursive_mutex> lock(mutex);

    auto status = db->Put(writeOptions, Slice(_key), Slice(_value));

    throwExceptionOnError(status);


        spdlog::debug("written key: {}",_key );
       // std::cerr << "written key " << _key  << std::endl;

}


void LevelDB::deleteDHDKGKey (const string &_key) {

    std::lock_guard<std::recursive_mutex> lock(mutex);

    string full_key = "DKG_DH_KEY_" + _key;

    auto status = db->Delete(writeOptions, Slice(_key));

    throwExceptionOnError(status);

      spdlog::debug("key deleted: {}",full_key );
      //std::cerr << "key deleted " << full_key << std::endl;

}

void LevelDB::deleteTempNEK(const string &_key){

    std::lock_guard<std::recursive_mutex> lock(mutex);

    string prefix = _key.substr(0,8);
    if (prefix != "tmp_NEK:") {
      return;
    }

    auto status = db->Delete(writeOptions, Slice(_key));

    throwExceptionOnError(status);

    std::cerr << "key deleted " << _key << std::endl;
}

void LevelDB::deleteKey(const string &_key){

    std::lock_guard<std::recursive_mutex> lock(mutex);

    auto status = db->Delete(writeOptions, Slice(_key));

    throwExceptionOnError(status);

      spdlog::debug("key deleted: {}",_key );
      // std::cerr << "key deleted " << _key << std::endl;

}



void LevelDB::writeByteArray(const char *_key, size_t _keyLen, const char *value,
                             size_t _valueLen) {

    std::lock_guard<std::recursive_mutex> lock(mutex);

    auto status = db->Put(writeOptions, Slice(_key, _keyLen), Slice(value, _valueLen));

    throwExceptionOnError(status);
}


void LevelDB::writeByteArray(string &_key, const char *value,
                             size_t _valueLen) {

    std::lock_guard<std::recursive_mutex> lock(mutex);

    auto status = db->Put(writeOptions, Slice(_key), Slice(value, _valueLen));

    throwExceptionOnError(status);
}

void LevelDB::throwExceptionOnError(Status _status) {

    if (_status.IsNotFound())
        return;

    if (!_status.ok()) {
        throw RPCException(COULD_NOT_ACCESS_DATABASE, ("Could not access database database:" + _status.ToString()).c_str());
    }

}

uint64_t LevelDB::visitKeys(LevelDB::KeyVisitor *_visitor, uint64_t _maxKeysToVisit) {

    uint64_t readCounter = 0;

    leveldb::Iterator *it = db->NewIterator(readOptions);
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        _visitor->visitDBKey(it->key().data());
        readCounter++;
        if (readCounter >= _maxKeysToVisit) {
            break;
        }
    }

    delete it;

    return readCounter;
}

std::vector<string> LevelDB::writeKeysToVector1(uint64_t _maxKeysToVisit){
  uint64_t readCounter = 0;
  std::vector<string> keys;

  leveldb::Iterator *it = db->NewIterator(readOptions);
  for (it->SeekToFirst(); it->Valid(); it->Next()) {
    string cur_key(it->key().data(), it->key().size());
    keys.push_back(cur_key);
   // keys.push_back(it->key().data());
    readCounter++;
    if (readCounter >= _maxKeysToVisit) {
      break;
    }
  }

  delete it;

  return keys;
}

void LevelDB::writeDataUnique(const string & Name, const string &value) {

  auto key = Name;

  if (readString(Name) != nullptr) {
    spdlog::debug("name {}",Name, " already exists");
     // std::cerr << "name " << Name << " already exists" << std::endl;
    throw RPCException(KEY_SHARE_ALREADY_EXISTS, "Data with this name already exists");
  }

  writeString(key, value);

      spdlog::debug("{}",Name, " is written to db");

}


LevelDB::LevelDB(string &filename) {


    leveldb::Options options;
    options.create_if_missing = true;

    if (!leveldb::DB::Open(options, filename, (leveldb::DB **) &db).ok()) {
        throw std::runtime_error("Unable to open levelDB database");
    }

    if (db == nullptr) {
        throw std::runtime_error("Null levelDB object");
    }

}

LevelDB::~LevelDB() {
}

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
        spdlog::error("could not get current workin directory");
        exit(-1);
    }

    sgx_data_folder = string(cwd) + "/" + SGXDATA_FOLDER;

    struct stat info;
    if (stat(sgx_data_folder.c_str(), &info) !=0 ){
        spdlog::info("sgx_data folder does not exist. Creating ...");

        if (system(("mkdir " + sgx_data_folder).c_str()) == 0){
            spdlog::info("Successfully created sgx_data folder");
        }
        else{
            spdlog::error("Couldnt create creating sgx_data folder");
            exit(-1);
        }
    }


    spdlog::info("Opening wallet databases");

    auto dbName = sgx_data_folder +  WALLETDB_NAME;
    levelDb = make_shared<LevelDB>(dbName);

    auto csr_dbname = sgx_data_folder + "CSR_DB";
    csrDb = make_shared<LevelDB>(csr_dbname);

    auto csr_status_dbname = sgx_data_folder + "CSR_STATUS_DB";
    csrStatusDb = make_shared<LevelDB>(csr_status_dbname);

    spdlog::info("Successfully opened databases");

}

const string &LevelDB::getSgxDataFolder() {
    return sgx_data_folder;
}
