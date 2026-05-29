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

    @file LevelDB.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_LEVELDB_H
#define SGXWALLET_LEVELDB_H

#include "common.h"
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace leveldb {
class DB;
class Status;
class Slice;
} // namespace leveldb

class LevelDB {

  recursive_mutex mutex;

  shared_ptr<leveldb::DB> db;

  static bool isInited;

  static shared_ptr<LevelDB> levelDb;

  static shared_ptr<LevelDB> csrDb;

  static shared_ptr<LevelDB> csrStatusDb;

  static string sgx_data_folder;

public:
  static void initDataFolderAndDBs();

  static void closeDataFolderAndDBs();

  static const shared_ptr<LevelDB> &getLevelDb();

  static const shared_ptr<LevelDB> &getCsrDb();

  static const shared_ptr<LevelDB> &getCsrStatusDb();

public:
  shared_ptr<string> readString(std::string_view _key);

  shared_ptr<string> readNewStyleValue(const string &value);

  pair<stringstream, uint64_t> getAllKeys();

  pair<string, uint64_t> getLatestCreatedKey();

  /**
   * @brief Writes the value to the DB, wrapped in JSON with timestamp.
   * This is the standard way of writing values to the DB, used everywhere
   * except for SEK reencrypt, where we want to keep exact same value and
   * timestamp for all keys except SEK.
   */
  void writeString(std::string_view key1, const string &value1);

  /**
   * @brief Writes the value as is to the DB.
   * This method is only used during reencryption DB to keep
   * exact same value (without JSON wrapper), keeping original
   * timestamp.
   */
  void writeRawString(std::string_view key1, const string &value1);

  void writeDataUnique(std::string_view Name, const string &value);

  void deleteDHDKGKey(std::string_view _key);

  void deleteTempNEK(std::string_view _key);

  void deleteKey(std::string_view _key);

public:
  void throwExceptionOnError(leveldb::Status result);

  LevelDB(const string &filename);

  class KeyVisitor {
  public:
    virtual void visitDBKey(const char *_data) = 0;
    virtual void writeDBKeysToVector(const char *_data,
                                     vector<const char *> &keys_vect) {}
  };

  uint64_t visitKeys(KeyVisitor *_visitor, uint64_t _maxKeysToVisit);

  class KeyValueVisitor {
  public:
    virtual void visitDBKeyValue(const string &_key, const string &_value) = 0;
  };

  uint64_t visitKeyValues(KeyValueVisitor *_visitor, uint64_t _maxKeysToVisit);

  vector<string> writeKeysToVector1(uint64_t _maxKeysToVisit);

  virtual ~LevelDB();

  static const string &getSgxDataFolder();
};

#endif
