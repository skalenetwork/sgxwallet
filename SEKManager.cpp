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
#include "RPCException.h"
#include "BLSCrypto.h"
#include "LevelDB.h"

#include <iostream>
#include <algorithm>

#include "sgxwallet_common.h"
#include "common.h"
#include "sgxwallet.h"

#include "ServerDataChecker.h"
#include "spdlog/spdlog.h"

bool case_insensitive_match(string s1, string s2) {
  //convert s1 and s2 into lower case strings
  transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
  transform(s2.begin(), s2.end(), s2.begin(), ::tolower);
  return s1.compare(s2);
}

void create_test_key(){
  int errStatus =  0;
  vector<char> errMsg(1024,0);
  uint32_t enc_len;

  uint8_t encrypted_key[BUF_LEN];
  memset(encrypted_key, 0, BUF_LEN);

  std::string key = TEST_VALUE;

  status = encrypt_key_aes(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key, &enc_len);
  if ( status != 0){
    std::cerr << "encrypt test key failed with status " << status << std::endl;
    throw RPCException(status, errMsg.data()) ;
  }

  //std::cerr << "enc len is " << enc_len << std::endl;

  vector<char> hexEncrKey(2 * enc_len + 1, 0);

  carray2Hex(encrypted_key, enc_len, hexEncrKey.data());

  uint64_t test_len;
  vector<uint8_t>test_encr_key(1024, 0);
  if (!hex2carray(hexEncrKey.data(), &test_len, test_encr_key.data())){
    std::cerr << "wrong encrypted test key" << std::endl;
  }


  LevelDB::getLevelDb() -> writeDataUnique("TEST_KEY", hexEncrKey.data());
}

bool check_SEK(std::string SEK){
   std::shared_ptr <std::string> test_key_ptr = LevelDB::getLevelDb() -> readString("TEST_KEY");
//  if (test_key_ptr == nullptr){
//    spdlog::error("empty db" );
//    exit(-1);
//  }
//  else{
    vector<uint8_t> encr_test_key(BUF_LEN, 0);
    uint64_t len;
    if ( !hex2carray(test_key_ptr->c_str(), &len, encr_test_key.data())){
      spdlog::error("wrong test key" );
      exit(-1);
    }

    vector<char> decr_key(1024,0);
    vector<char> errMsg(1024,0);
    int err_status = 0;

    vector<uint8_t> encr_SEK(1024,0);

    uint32_t l = len;
    std::cerr << " l is " << l << std::endl;

    status = set_SEK_backup(eid, &err_status, errMsg.data(), encr_SEK.data(), &l, SEK.c_str() );
    if (status != SGX_SUCCESS){
      cerr << "RPCException thrown with status " << status << endl;
      throw RPCException(status, errMsg.data());
    }

    status = decrypt_key_aes(eid, &err_status, errMsg.data(), encr_test_key.data(), len, decr_key.data());
    if (status != SGX_SUCCESS || err_status != 0){
      spdlog::error("failed to decrypt test key" );
      spdlog::error(errMsg.data());
      exit(-1);
    }


    std::string test_key = TEST_VALUE;
    if (test_key.compare(decr_key.data())!= 0){
      std::cerr << "decrypted key is " << decr_key.data() << std::endl;
      spdlog::error("Invalid SEK" );
      return false;
    }
    return true;
 // }
}

void gen_SEK(){

  vector<char> errMsg(1024,0);
  int err_status = 0;
  vector<uint8_t> encr_SEK(1024, 0);
  uint32_t enc_len = 0;

  //vector<char> SEK(65, 0);
  char SEK[65];
  memset(SEK, 0, 65);

  status = generate_SEK(eid, &err_status, errMsg.data(), encr_SEK.data(), &enc_len, SEK);
  if (status != SGX_SUCCESS ||  err_status != 0  ){
    throw RPCException(status, errMsg.data()) ;
  }

  vector<char> hexEncrKey(2 * enc_len + 1, 0);

  carray2Hex(encr_SEK.data(), enc_len, hexEncrKey.data());

  cout << "ATTENTION! THIS IS YOUR KEY FOR BACK UP. PLEASE COPY IT TO THE SAFE PLACE" << endl;
  cout << "key is " << SEK << endl;

  if (!autoconfirm) {
    std::string confirm_str = "I confirm";
    std::string buffer;
    do {
      std::cout << " DO YOU CONFIRM THAT YOU COPIED THE KEY? (if you confirm type - I confirm)"
                << std::endl;
      std::getline(std::cin, buffer);
    } while (case_insensitive_match(confirm_str, buffer)); //(strcmp(confirm_str.c_str(), buffer.c_str()) != 0);
  }

  if (system("reset") != 0) {
      cerr << "Could not execute reset" << endl;
  }

  LevelDB::getLevelDb()->writeDataUnique("SEK", hexEncrKey.data());

  create_test_key();
}

void set_SEK(std::shared_ptr<std::string> hex_encr_SEK){
  vector<char> errMsg(1024,0);
  int err_status = 0;
  //vector<uint8_t> encr_SEK(1024, 0);

  uint8_t encr_SEK[BUF_LEN];
  memset(encr_SEK, 0, BUF_LEN);

  uint64_t len;

  if (!hex2carray(hex_encr_SEK->c_str(), &len, encr_SEK)){
    throw RPCException(INVALID_HEX, "Invalid encrypted SEK Hex");
  }

  status = set_SEK(eid, &err_status, errMsg.data(), encr_SEK, len );
  if ( status != SGX_SUCCESS || err_status != 0 ){
    cerr << "RPCException thrown" << endl;
    throw RPCException(status, errMsg.data()) ;
  }

}

void enter_SEK(){
  vector<char> errMsg(1024,0);
  int err_status = 0;
  vector<uint8_t> encr_SEK(BUF_LEN, 0);
  uint32_t enc_len;

  std::shared_ptr <std::string> test_key_ptr = LevelDB::getLevelDb() -> readString("TEST_KEY");
  if (test_key_ptr == nullptr){
    spdlog::error("empty db" );
    exit(-1);
  }

  std::string SEK;
  std::cout << "ENTER BACKUP KEY" << std::endl;
  std::cin >> SEK;
  while (!checkHex(SEK, 16) || !check_SEK(SEK)){
    std::cout << "KEY IS INVALID.TRY ONCE MORE" << std::endl;
    SEK = "";
    std::cin >> SEK;
  }
//  if (DEBUG_PRINT)
//   std::cerr << "your key is " << SEK << std::endl;


  status = set_SEK_backup(eid, &err_status, errMsg.data(), encr_SEK.data(), &enc_len, SEK.c_str() );
  if (status != SGX_SUCCESS){
    cerr << "RPCException thrown with status " << status << endl;
    throw RPCException(status, errMsg.data());
  }

  vector<char> hexEncrKey(2 * enc_len + 1, 0);

  carray2Hex(encr_SEK.data(), enc_len, hexEncrKey.data());

  LevelDB::getLevelDb() -> deleteKey("SEK");
  LevelDB::getLevelDb() -> writeDataUnique("SEK", hexEncrKey.data());
}

void init_SEK(){
  std::shared_ptr<std::string> encr_SEK_ptr = LevelDB::getLevelDb()->readString("SEK");
  if (encr_SEK_ptr == nullptr){
    spdlog::info("SEK was not created yet. Going to create SEK");
    gen_SEK();
  }
  else{
    if (printDebugInfo)
      spdlog::info("going to set SEK from db" );
    set_SEK(encr_SEK_ptr);
  }
}

//a002e7ca685d46a32771d16fe2518e58