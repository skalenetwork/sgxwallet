/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#include "tests/integration/IntegrationTestSupport.h"

#include "secure_enclave_u.h"
#include "tests/TestConstants.h"
#include "third_party/catch.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#define PRINT_SRC_LINE cerr << "Executing line " << to_string(__LINE__) << endl;

using namespace std;

TEST_CASE_METHOD(TestFixture, "AES encrypt/decrypt",
                 "[integration][keys][aes-encrypt-decrypt]") {
  int errStatus = 0;
  vector<char> errMsg(BUF_LEN, 0);
  uint64_t encLen;
  string key = SAMPLE_AES_KEY;
  vector<uint8_t> encrypted_key(BUF_LEN, 0);

  PRINT_SRC_LINE
  auto status = trustedEncryptKey(eid, &errStatus, errMsg.data(), key.c_str(),
                                  encrypted_key.data(), &encLen);

  REQUIRE(status == 0);
  REQUIRE(errStatus == 0);

  vector<char> decr_key(BUF_LEN, 0);
  PRINT_SRC_LINE
  status = trustedDecryptKey(eid, &errStatus, errMsg.data(),
                             encrypted_key.data(), encLen, decr_key.data());

  REQUIRE(status == 0);
  REQUIRE(key.compare(decr_key.data()) == 0);
  REQUIRE(errStatus == 0);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Exportable / non-exportable keys",
                 "[integration][keys][exportable-nonexportable-keys]") {
  int errStatus = 0;
  vector<char> errMsg(BUF_LEN, 0);
  vector<uint8_t> encPrivKey(BUF_LEN, 0);
  vector<char> pubKeyX(BUF_LEN, 0);
  vector<char> pubKeyY(BUF_LEN, 0);

  uint64_t encLen = 0;
  int exportable = 0;

  auto status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(),
                                        &exportable, encPrivKey.data(), &encLen,
                                        pubKeyX.data(), pubKeyY.data());

  vector<char> decrypted_key(BUF_LEN, 0);
  status = trustedDecryptKey(eid, &errStatus, errMsg.data(), encPrivKey.data(),
                             encLen, decrypted_key.data());
  REQUIRE(errStatus == -11);

  exportable = 1;

  encPrivKey.clear();
  errMsg.clear();
  pubKeyX.clear();
  pubKeyY.clear();

  status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), &exportable,
                                   encPrivKey.data(), &encLen, pubKeyX.data(),
                                   pubKeyY.data());

  decrypted_key.clear();
  status = trustedDecryptKey(eid, &errStatus, errMsg.data(), encPrivKey.data(),
                             encLen, decrypted_key.data());
  REQUIRE(errStatus == 0);
  REQUIRE(status == SGX_SUCCESS);

  string key = SAMPLE_AES_KEY;
  vector<uint8_t> encrypted_key(BUF_LEN, 0);

  status = trustedEncryptKey(eid, &errStatus, errMsg.data(), key.c_str(),
                             encrypted_key.data(), &encLen);

  REQUIRE(status == 0);
  REQUIRE(errStatus == 0);

  vector<char> decr_key(BUF_LEN, 0);
  PRINT_SRC_LINE
  status = trustedDecryptKey(eid, &errStatus, errMsg.data(),
                             encrypted_key.data(), encLen, decr_key.data());

  REQUIRE(status == 0);
  REQUIRE(key.compare(decr_key.data()) == 0);
  REQUIRE(errStatus == 0);
  sleep(3);
}
