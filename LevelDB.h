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

    @file LevelDB.h
    @author Stan Kladko
    @date 2019
*/


#ifndef SGXWALLET_LEVELDB_H
#define SGXWALLET_LEVELDB_H

#include <memory>
#include <string>
#include <mutex>
#include <vector>
#include "common.h"
namespace leveldb {
    class DB;
    class Status;
    class Slice;
}

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

    static const shared_ptr<LevelDB> &getLevelDb();

    static const shared_ptr<LevelDB> &getCsrDb();

    static const shared_ptr<LevelDB> &getCsrStatusDb();

public:


    shared_ptr<string> readString(const string& _key);


    void writeString(const string &key1, const string &value1);

    void writeDataUnique(const string & Name, const string &value);

    void writeByteArray(const char *_key, size_t _keyLen, const char *value,
                        size_t _valueLen);


    void writeByteArray(string& _key, const char *value,
                        size_t _valueLen);

    void deleteDHDKGKey (const string &_key);

    void deleteTempNEK (const string &_key);

    void deleteKey(const string &_key);

public:


    void throwExceptionOnError(leveldb::Status result);


    LevelDB(string& filename);




    class KeyVisitor {
    public:
        virtual void visitDBKey(const char* _data) = 0;
        virtual void writeDBKeysToVector(const char* _data, vector<const char*> & keys_vect) {}
    };

    uint64_t visitKeys(KeyVisitor* _visitor, uint64_t _maxKeysToVisit);

    vector<string> writeKeysToVector1(uint64_t _maxKeysToVisit);

    virtual ~LevelDB();

    static const string &getSgxDataFolder();


};




#endif