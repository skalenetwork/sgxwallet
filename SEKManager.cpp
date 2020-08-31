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

    @file SEKManager.cpp
    @author Stan Kladko
    @date 2020
*/

#include "SEKManager.h"
#include "SGXException.h"
#include "BLSCrypto.h"
#include "LevelDB.h"

#include <fstream>
#include <iostream>
#include <algorithm>

#include "sgxwallet_common.h"
#include "common.h"
#include "sgxwallet.h"

#include "ServerDataChecker.h"
#include "third_party/spdlog/spdlog.h"

using namespace std;

#define BACKUP_PATH "./sgx_data/sgxwallet_backup_key.txt"


bool case_insensitive_match(string s1, string s2) {
    //convert s1 and s2 into lower case strings
    transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
    transform(s2.begin(), s2.end(), s2.begin(), ::tolower);
    return s1.compare(s2);
}

void create_test_key() {
    int errStatus = 0;
    vector<char> errMsg(1024, 0);
    uint32_t enc_len;

    uint8_t encrypted_key[BUF_LEN];
    memset(encrypted_key, 0, BUF_LEN);

    string key = TEST_VALUE;

    status = trustedEncryptKeyAES(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key, &enc_len);
    if (status != SGX_SUCCESS) {
        cerr << "encrypt test key failed with status " << status << endl;
        throw SGXException(status, errMsg.data());
    }

    if (errStatus != 0) {
        cerr << "encrypt test key failed with status " << errStatus << endl;
        throw SGXException(errStatus, errMsg.data());
    }

    vector<char> hexEncrKey(2 * enc_len + 1, 0);

    carray2Hex(encrypted_key, enc_len, hexEncrKey.data());

    uint64_t test_len;
    vector <uint8_t> test_encr_key(1024, 0);
    if (!hex2carray(hexEncrKey.data(), &test_len, test_encr_key.data())) {
        cerr << "wrong encrypted test key" << endl;
    }

    LevelDB::getLevelDb()->writeDataUnique("TEST_KEY", hexEncrKey.data());
}


shared_ptr <vector<uint8_t>> check_and_set_SEK(const string &SEK) {
    shared_ptr <string> test_key_ptr = LevelDB::getLevelDb()->readString("TEST_KEY");
    vector <uint8_t> encr_test_key(BUF_LEN, 0);
    uint64_t len;
    if (!hex2carray(test_key_ptr->c_str(), &len, encr_test_key.data())) {
        spdlog::error("wrong test key");
        exit(-1);
    }

    vector<char> decr_key(1024, 0);
    vector<char> errMsg(1024, 0);
    int err_status = 0;

    auto encrypted_SEK = make_shared < vector < uint8_t >> (1024, 0);

    uint32_t l = len;

    status = trustedSetSEK_backup(eid, &err_status, errMsg.data(), encrypted_SEK->data(), &l, SEK.c_str());

    if (status != SGX_SUCCESS) {
        spdlog::error("trustedSetSEK_backup failed with error code {}", status);
        exit(-1);
    }

    if (err_status != 0) {
        spdlog::error("trustedSetSEK_backup failed with error status {}", status);
        exit(-1);
    }

    status = trustedDecryptKeyAES(eid, &err_status, errMsg.data(), encr_test_key.data(), len, decr_key.data());
    if (status != SGX_SUCCESS || err_status != 0) {
        spdlog::error("Failed to decrypt test key");
        spdlog::error(errMsg.data());
        exit(-1);
    }

    string test_key = TEST_VALUE;
    if (test_key.compare(decr_key.data()) != 0) {
        spdlog::error("Invalid SEK");
        exit(-1);
    }

    encrypted_SEK->resize(l);

    return encrypted_SEK;
}

void gen_SEK() {
    vector<char> errMsg(1024, 0);
    int err_status = 0;
    vector <uint8_t> encrypted_SEK(1024, 0);
    uint32_t enc_len = 0;

    char SEK[65];
    memset(SEK, 0, 65);

    spdlog::error("Generating backup key. Will be stored in backup_key.txt ... ");

    status = trustedGenerateSEK(eid, &err_status, errMsg.data(), encrypted_SEK.data(), &enc_len, SEK);

    if (status != SGX_SUCCESS) {
        throw SGXException(status, errMsg.data());
    }

    if (err_status != 0) {
        throw SGXException(err_status, errMsg.data());
    }

    if (strnlen(SEK, 33) != 32) {
        throw SGXException(-1, "strnlen(SEK,33) != 32");
    }

    vector<char> hexEncrKey(2 * enc_len + 1, 0);

    carray2Hex(encrypted_SEK.data(), enc_len, hexEncrKey.data());

    ofstream sek_file(BACKUP_PATH);
    sek_file.clear();

    sek_file << SEK;


    cout << "ATTENTION! YOUR BACKUP KEY HAS BEEN WRITTEN INTO sgx_data/backup_key.txt \n" <<
         "PLEASE COPY IT TO THE SAFE PLACE AND THEN DELETE THE FILE MANUALLY BY RUNNING THE FOLLOWING COMMAND:\n" <<
         "apt-get install secure-delete && srm -vz sgx_data/backup_key.txt" << endl;


    if (!autoconfirm) {
        string confirm_str = "I confirm";
        string buffer;
        do {
            cout << " DO YOU CONFIRM THAT YOU COPIED THE KEY? (if you confirm type - I confirm)"
                 << endl;
            getline(cin, buffer);
        } while (case_insensitive_match(confirm_str, buffer));
    }


    LevelDB::getLevelDb()->writeDataUnique("SEK", hexEncrKey.data());

    create_test_key();
}

void trustedSetSEK(shared_ptr <string> hex_encrypted_SEK) {
    vector<char> errMsg(1024, 0);
    int err_status = 0;

    uint8_t encrypted_SEK[BUF_LEN];
    memset(encrypted_SEK, 0, BUF_LEN);

    uint64_t len;

    if (!hex2carray(hex_encrypted_SEK->c_str(), &len, encrypted_SEK)) {
        throw SGXException(INVALID_HEX, "Invalid encrypted SEK Hex");
    }

    status = trustedSetSEK(eid, &err_status, errMsg.data(), encrypted_SEK);
    if (status != SGX_SUCCESS) {
        cerr << "RPCException thrown" << endl;
        throw SGXException(status, errMsg.data());
    }

    if (err_status != 0) {
        cerr << "RPCException thrown" << endl;
        throw SGXException(err_status, errMsg.data());
    }
}

#include "experimental/filesystem"

#include <boost/algorithm/string.hpp>

void enter_SEK() {
    vector<char> errMsg(BUF_LEN, 0);


    shared_ptr <string> test_key_ptr = LevelDB::getLevelDb()->readString("TEST_KEY");
    if (test_key_ptr == nullptr) {
        spdlog::error("Error: corrupt or empty LevelDB database");
        exit(-1);
    }


    if (!experimental::filesystem::is_regular_file(BACKUP_PATH)) {
        spdlog::error("File does not exist: "  BACKUP_PATH);
        exit(-1);
    }

    ifstream sek_file(BACKUP_PATH);

    spdlog::info("Reading backup key from file ...");

    string sek((istreambuf_iterator<char>(sek_file)),
               istreambuf_iterator<char>());

    boost::trim(sek);

    spdlog::info("Setting backup key ...");

    while (!checkHex(sek, 16)) {
        spdlog::error("Invalid hex in key");
        exit(-1);
    }

    auto encrypted_SEK = check_and_set_SEK(sek);

    vector<char> hexEncrKey(BUF_LEN, 0);

    carray2Hex(encrypted_SEK->data(), encrypted_SEK->size(), hexEncrKey.data());

    spdlog::info("Got sealed storage encryption key.");

    LevelDB::getLevelDb()->deleteKey("SEK");

    spdlog::info("Storing sealed storage encryption key in LevelDB ...");

    LevelDB::getLevelDb()->writeDataUnique("SEK", hexEncrKey.data());

    spdlog::info("Stored storage encryption key in LevelDB.");

}

void initSEK() {
    shared_ptr <string> encrypted_SEK_ptr = LevelDB::getLevelDb()->readString("SEK");
    if (enterBackupKey) {
        enter_SEK();
    } else {
        if (encrypted_SEK_ptr == nullptr) {
            spdlog::warn("SEK was not created yet. Going to create SEK");
            gen_SEK();
        } else {
            trustedSetSEK(encrypted_SEK_ptr);
        }
    }
}

//a002e7ca685d46a32771d16fe2518e58
