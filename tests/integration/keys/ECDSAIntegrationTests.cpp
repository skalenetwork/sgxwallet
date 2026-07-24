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

#include "common.h"
#include "sgxwallet.h"
#include "tests/TestConstants.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <algorithm>
#include <cstdint>
#include <json/value.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/common/exception.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace jsonrpc;
using namespace std;

class TestFixtureZMQSign {
public:
  TestFixtureZMQSign() {
    resetTestDB();
    initConfig config = makeTestInitConfig(false, false, true, true, false);

    initAll(config);
  }

  ~TestFixtureZMQSign() { destroyTestEnclave(); }
};

TEST_CASE_METHOD(TestFixture, "ECDSA AES keygen and signature test",
                 "[integration][ecdsa][ecdsa-aes-key-sig-gen]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  vector<uint8_t> encrPrivKey(BUF_LEN, 0);
  vector<char> pubKeyX(BUF_LEN, 0);
  vector<char> pubKeyY(BUF_LEN, 0);

  uint64_t encLen = 0;
  int exportable = 0;
  auto status = trustedGenerateEcdsaKey(
      eid, &errStatus, errMsg.data(), &exportable, encrPrivKey.data(), &encLen,
      pubKeyX.data(), pubKeyY.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  string hex = SAMPLE_HEX_HASH;
  vector<char> signatureR(BUF_LEN, 0);
  vector<char> signatureS(BUF_LEN, 0);
  uint8_t signatureV = 0;

  for (int i = 0; i < 50; i++) {
    status = trustedEcdsaSign(
        eid, &errStatus, errMsg.data(), encrPrivKey.data(), encLen, hex.data(),
        signatureR.data(), signatureS.data(), &signatureV, 16);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
  }
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES key gen",
                 "[integration][ecdsa][ecdsa-aes-key-gen]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  vector<uint8_t> encrPrivKey(BUF_LEN, 0);
  vector<char> pubKeyX(BUF_LEN, 0);
  vector<char> pubKeyY(BUF_LEN, 0);
  uint64_t encLen = 0;
  int exportable = 0;
  auto status = trustedGenerateEcdsaKey(
      eid, &errStatus, errMsg.data(), &exportable, encrPrivKey.data(), &encLen,
      pubKeyX.data(), pubKeyY.data());

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES get public key",
                 "[integration][ecdsa][ecdsa-aes-get-pub-key]") {
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

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> receivedPubKeyX(BUF_LEN, 0);
  vector<char> receivedPubKeyY(BUF_LEN, 0);

  status = trustedGetPublicEcdsaKey(
      eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen,
      receivedPubKeyX.data(), receivedPubKeyY.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA key gen API",
                 "[integration][ecdsa][ecdsa-key-gen-api]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  for (int i = 0; i <= 20; i++) {
    try {
      auto keyName = genECDSAKeyAPI(c);
      Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
      REQUIRE(sig["status"].asInt() == 0);
      Json::Value getPubKey = c.getPublicECDSAKey(keyName);
      REQUIRE(getPubKey["status"].asInt() == 0);
    } catch (JsonRpcException &e) {
      cerr << e.what() << endl;
      throw;
    }
  }

  auto keyName = genECDSAKeyAPI(c);

  Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);

  for (int i = 0; i <= 20; i++) {
    try {
      auto keyName = genECDSAKeyAPI(c);
      Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);
      REQUIRE(sig["status"].asInt() == 0);
      Json::Value getPubKey = c.getPublicECDSAKey(keyName);
      REQUIRE(getPubKey["status"].asInt() == 0);
    } catch (JsonRpcException &e) {
      cerr << e.what() << endl;
      throw;
    }
  }
}

TEST_CASE_METHOD(TestFixture, "Import ECDSA Key",
                 "[integration][ecdsa][import-ecdsa-key]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string name = "NEK:abcdef";
  auto response = c.importECDSAKey("6507625568967977077291849236396320012317305"
                                   "261598035438182864059942098934847",
                                   name);
  REQUIRE(response["status"] != 0);

  string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  response = c.importECDSAKey(key_str, name);
  REQUIRE(response["status"] == 0);

  REQUIRE(c.ecdsaSignMessageHash(16, name, SAMPLE_HASH)["status"] == 0);
}

TEST_CASE_METHOD(TestFixture, "Import ECDSA Key Zmq",
                 "[integration][ecdsa][import-ecdsa-key-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string name = "NEK:abcdef";
  REQUIRE_THROWS(
      client->importECDSAKey("6507625568967977077291849236396320012317305261598"
                             "035438182864059942098934847",
                             name));

  string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  string response = client->importECDSAKey(key_str, name);
  REQUIRE(response == client->getECDSAPublicKey(name));

  REQUIRE_NOTHROW(client->ecdsaSignMessageHash(16, name, SAMPLE_HASH));
}

TEST_CASE_METHOD(TestFixtureZMQSign, "ZMQ-ecdsa",
                 "[integration][ecdsa][zmq-ecdsa]") {
  HttpClient htp(RPC_ENDPOINT);
  StubClient c(htp, JSONRPC_CLIENT_V2);

  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  string keyName = genECDSAKeyAPI(c);
  int end = 10000000;
  string sh = string(SAMPLE_HASH);

  std::vector<std::thread> workers;

  for (int j = 0; j < 2; j++) {
    workers.push_back(std::thread([client, sh, keyName, end, j]() {
      CHECK_STATE(client);
      for (int i = (j * 2000); i < (j * 2000) + 1000; i++) {

        auto hash = sh.substr(0, sh.size() - 8) + to_string(end + i);

        auto sig = client->ecdsaSignMessageHash(16, keyName, hash);
        REQUIRE(sig.size() > 10);
      }
    }));
  };

  std::for_each(workers.begin(), workers.end(),
                [](std::thread &t) { t.join(); });
}
