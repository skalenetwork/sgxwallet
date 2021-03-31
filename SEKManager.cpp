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


#include <fstream>
#include <iostream>
#include <algorithm>

#include "third_party/spdlog/spdlog.h"


#include "sgxwallet_common.h"
#include "common.h"
#include "sgxwallet.h"

#include "ExitHandler.h"
#include "SGXException.h"
#include "BLSCrypto.h"
#include "LevelDB.h"

#include "ServerDataChecker.h"
#include "ServerInit.h"
#include "SEKManager.h"

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
    uint64_t enc_len;

    SAFE_UINT8_BUF(encrypted_key, BUF_LEN);

    string key = TEST_VALUE;

    sgx_status_t status =  SGX_SUCCESS;

    {
        READ_LOCK(sgxInitMutex);
        status = trustedEncryptKey(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key, &enc_len);
    }

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    vector<char> hexEncrKey = carray2Hex(encrypted_key, enc_len);

    LevelDB::getLevelDb()->writeDataUnique("TEST_KEY", hexEncrKey.data());
}


void validate_SEK() {

    shared_ptr <string> test_key_ptr = LevelDB::getLevelDb()->readString("TEST_KEY");
    vector <uint8_t> encr_test_key(BUF_LEN, 0);
    vector<char> decr_key(BUF_LEN, 0);
    uint64_t len = 0;
    vector<char> errMsg(BUF_LEN, 0);

    int err_status = 0;

    if (!hex2carray(test_key_ptr->c_str(), &len, encr_test_key.data(),
                    BUF_LEN)) {
        spdlog::error("Corrupt test key is LevelDB");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-4);
    }

    sgx_status_t status = SGX_SUCCESS;

    {
        READ_LOCK(sgxInitMutex);
        status = trustedDecryptKey(eid, &err_status, errMsg.data(), encr_test_key.data(), len, decr_key.data());
    }

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());

    string test_key = TEST_VALUE;

    if (test_key.compare(decr_key.data()) != 0) {
        spdlog::error("Invalid storage key. You need to recover using backup key");
        spdlog::error("Set the correct backup key into sgx_datasgxwallet_backup_key.txt");
        spdlog::error("Then run sgxwallet using backup flag");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-5);
    }
}


shared_ptr <vector<uint8_t>> check_and_set_SEK(const string &SEK) {

    vector<char> decr_key(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);
    int err_status = 0;

    auto encrypted_SEK = make_shared < vector < uint8_t >> (BUF_LEN, 0);

    uint64_t l = 0;

    sgx_status_t status = SGX_SUCCESS;

    {
        READ_LOCK(sgxInitMutex);
        status = trustedSetSEKBackup(eid, &err_status, errMsg.data(), encrypted_SEK->data(), &l,
                             SEK.c_str());
    }


    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());

    encrypted_SEK->resize(l);

    validate_SEK();

    return encrypted_SEK;
}

void gen_SEK() {
    vector<char> errMsg(1024, 0);
    int err_status = 0;
    vector <uint8_t> encrypted_SEK(1024, 0);
    uint64_t enc_len = 0;

    SAFE_CHAR_BUF(SEK, 65);

    spdlog::info("Generating backup key. Will be stored in backup_key.txt ... ");


    sgx_status_t status = SGX_SUCCESS;
    {

        status = trustedGenerateSEK(eid, &err_status, errMsg.data(), encrypted_SEK.data(), &enc_len, SEK);
    }

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());


    if (strnlen(SEK, 33) != 32) {
        throw SGXException(-1, "strnlen(SEK,33) != 32");
    }

    vector<char> hexEncrKey = carray2Hex(encrypted_SEK.data(), enc_len);

    spdlog::info(string("Encrypted storage encryption key:") + hexEncrKey.data());

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

    validate_SEK();

    shared_ptr <string> encrypted_SEK_ptr = LevelDB::getLevelDb()->readString("SEK");

    setSEK(encrypted_SEK_ptr);

    validate_SEK();

}


//static std::atomic<int> isSgxWalletExiting(0);

//void safeExit() {

//    // this is to make sure exit is only called once if called from multiple threads

//    auto previousValue = isSgxWalletExiting.exchange(1);

//    if (previousValue != 1)
//        exit(-6);
//}

void setSEK(shared_ptr <string> hex_encrypted_SEK) {

    CHECK_STATE(hex_encrypted_SEK);

    vector<char> errMsg(1024, 0);
    int err_status = 0;

    SAFE_UINT8_BUF(encrypted_SEK, BUF_LEN);

    uint64_t len = 0;

    if (!hex2carray(hex_encrypted_SEK->c_str(), &len, encrypted_SEK,
                    BUF_LEN)) {
        throw SGXException(SET_SEK_INVALID_SEK_HEX, "Invalid encrypted SEK Hex");
    }

    sgx_status_t status = SGX_SUCCESS;
    {
        status = trustedSetSEK(eid, &err_status, errMsg.data(), encrypted_SEK);
    }

    HANDLE_TRUSTED_FUNCTION_ERROR(status, err_status, errMsg.data());


    validate_SEK();


}

#include "experimental/filesystem"

#include <boost/algorithm/string.hpp>

void enter_SEK() {

    shared_ptr <string> test_key_ptr = LevelDB::getLevelDb()->readString("TEST_KEY");
    if (test_key_ptr == nullptr) {
        spdlog::error("Error: corrupt or empty LevelDB database");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-7);
    }


    if (!experimental::filesystem::is_regular_file(BACKUP_PATH)) {
        spdlog::error("File does not exist: "  BACKUP_PATH);
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-8);
    }

    ifstream sek_file(BACKUP_PATH);

    spdlog::info("Reading backup key from file ...");

    string sek((istreambuf_iterator<char>(sek_file)),
               istreambuf_iterator<char>());

    boost::trim(sek);

    spdlog::info("Setting backup key ...");

    while (!checkHex(sek, 16)) {
        spdlog::error("Invalid hex in key");
        ExitHandler::exitHandler(SIGTERM, ExitHandler::ec_failure);
        exit(-9);
    }

    auto encrypted_SEK = check_and_set_SEK(sek);

    vector<char> hexEncrKey = carray2Hex(encrypted_SEK->data(), encrypted_SEK->size());

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
            setSEK(encrypted_SEK_ptr);
        }
    }
}

//a002e7ca685d46a32771d16fe2518e58
