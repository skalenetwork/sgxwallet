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

namespace leveldb {
    class DB;
    class Status;
    class Slice;
}

class LevelDB {

    std::recursive_mutex mutex;

    leveldb::DB* db;

public:


    std::shared_ptr<std::string> readString(const std::string& _key);


    void writeString(const std::string &key1, const std::string &value1);

    void writeDataUnique(const std::string & Name, const std::string &value);

    void writeByteArray(const char *_key, size_t _keyLen, const char *value,
                        size_t _valueLen);


    void writeByteArray(std::string& _key, const char *value,
                        size_t _valueLen);

    void deleteDHDKGKey (const std::string &_key);

    void deleteOlegKey (const std::string &_key);

    void deleteTempNEK (const std::string &_key);

    void deleteKey(const std::string &_key);

public:


    void throwExceptionOnError(leveldb::Status result);


    LevelDB(std::string& filename);




    class KeyVisitor {
    public:
        virtual void visitDBKey(const char* _data) = 0;
        virtual void writeDBKeysToVector(const char* _data, std::vector<const char*> & keys_vect) {}
    };

    uint64_t visitKeys(KeyVisitor* _visitor, uint64_t _maxKeysToVisit);

    std::vector<std::string> writeKeysToVector1(uint64_t _maxKeysToVisit);

    virtual ~LevelDB();


};


extern LevelDB* levelDb;

extern LevelDB* csrDb;

extern LevelDB* csrStatusDb;

#endif