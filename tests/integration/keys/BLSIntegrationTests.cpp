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

#include "BLSCrypto.h"
#include "BLSSigShare.h"
#include "common.h"
#include "sgxwallet.h"
#include "tests/TestConstants.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <cstdint>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

using namespace jsonrpc;
using namespace std;

TEST_CASE_METHOD(TestFixture, "BLS key encrypt",
                 "[integration][bls][bls-key-encrypt]") {
  auto key = encryptTestKey();
  REQUIRE(key);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Delete Bls Key",
                 "[integration][bls][delete-bls-key]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC);
  std::string key_str = key.toString(libBLS::algebra::Base::DEC);
  auto response = c.importBLSKeyShare(key_str, name);
  REQUIRE(response["status"] != 0);

  key_str = "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  response = c.importBLSKeyShare(key_str, name);
  REQUIRE(response["status"] == 0);

  REQUIRE(c.blsSignMessageHash(name, SAMPLE_HASH, 1, 1)["status"] == 0);

  REQUIRE(c.deleteBlsKey(name)["deleted"] == true);
}

TEST_CASE_METHOD(TestFixture, "Delete Bls Key Zmq",
                 "[integration][bls][delete-bls-key-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC);
  std::string key_str = key.toString(libBLS::algebra::Base::DEC);
  REQUIRE(!client->importBLSKeyShare(key_str, name));

  key_str = "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  REQUIRE(client->importBLSKeyShare(key_str, name));

  REQUIRE_NOTHROW(client->blsSignMessageHash(name, SAMPLE_HASH, 1, 1));

  REQUIRE(client->deleteBLSKey(name));
}

TEST_CASE_METHOD(TestFixture, "Test generated bls key decrypt",
                 "[integration][bls][bls-aggregated-key-decrypt]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;

  int exportable = 1;

  uint64_t encBlsLen = 0;

  sgx_status_t status = SGX_SUCCESS;

  SAFE_UINT8_BUF(encrBlsKey, BUF_LEN)

  status = trustedGenerateBLSKey(eid, &errStatus, errMsg.data(), &exportable,
                                 encrBlsKey, &encBlsLen);

  REQUIRE(status == 0);
  REQUIRE(errStatus == 0);

  vector<char> decrKey(BUF_LEN, 0);
  status = trustedDecryptKey(eid, &errStatus, errMsg.data(), encrBlsKey,
                             encBlsLen, decrKey.data());

  REQUIRE(status == 0);
  REQUIRE(errStatus == 0);

  libBLS::algebra::FrScalar blsKey = libBLS::algebra::FrScalar::fromString(
      decrKey.data(), libBLS::algebra::Base::HEXA);

  REQUIRE(blsKey != libBLS::algebra::FrScalar::zero());

  SAFE_UINT8_BUF(encrBlsKeySecond, BUF_LEN)

  status = trustedGenerateBLSKey(eid, &errStatus, errMsg.data(), &exportable,
                                 encrBlsKeySecond, &encBlsLen);

  vector<char> decrKeySecond(BUF_LEN, 0);
  status = trustedDecryptKey(eid, &errStatus, errMsg.data(), encrBlsKeySecond,
                             encBlsLen, decrKeySecond.data());

  libBLS::algebra::FrScalar blsKeySecond =
      libBLS::algebra::FrScalar::fromString(decrKeySecond.data(),
                                            libBLS::algebra::Base::HEXA);

  REQUIRE(blsKey != blsKeySecond);
}

TEST_CASE_METHOD(TestFixture,
                 "Test key generation for bls aggregated signatures scheme",
                 "[integration][bls][bls-aggregated-key-generation]") {
  HttpClient htp(RPC_ENDPOINT);
  StubClient c(htp, JSONRPC_CLIENT_V2);

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  auto response = c.generateBLSPrivateKey(name);

  REQUIRE(response["status"] == 0);
}

TEST_CASE_METHOD(
    TestFixture,
    "Test key generation for bls aggregated signatures scheme via zmq",
    "[integration][bls][bls-aggregated-key-generation-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";

  REQUIRE(client->generateBLSPrivateKey(name));
}

TEST_CASE_METHOD(TestFixture,
                 "Test message signing for bls aggregated signatures scheme",
                 "[integration][bls][bls-aggregated-signing]") {
  HttpClient htp(RPC_ENDPOINT);
  StubClient c(htp, JSONRPC_CLIENT_V2);

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  auto response = c.generateBLSPrivateKey(name);
  REQUIRE(response["status"] == 0);

  string hash = SAMPLE_HASH;
  response = c.blsSignMessageHash(name, hash, 1, 1);
  REQUIRE(response["status"] == 0);
}

TEST_CASE_METHOD(
    TestFixture,
    "Test message signing for bls aggregated signatures scheme via zmq",
    "[integration][bls][bls-aggregated-signing-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  REQUIRE(client->generateBLSPrivateKey(name));

  string hash = SAMPLE_HASH;
  string signature = client->blsSignMessageHash(name, hash, 1, 1);
  REQUIRE(!signature.empty());
}

TEST_CASE_METHOD(TestFixture,
                 "Test pop prove for bls aggregated signatures scheme",
                 "[integration][bls][bls-aggregated-pop-prove]") {
  HttpClient htp(RPC_ENDPOINT);
  StubClient c(htp, JSONRPC_CLIENT_V2);

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";

  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::random();

  std::string keyStr = key.toString(libBLS::algebra::Base::HEXA);
  auto response = c.importBLSKeyShare(keyStr, name);
  REQUIRE(response["status"] == 0);

  libBLS::algebra::G1Point popProveLocal = libBLS::Bls::PopProve(key);

  response = c.popProve(name);
  REQUIRE(response["status"] == 0);
  string sigShare = response["popProve"].asString();
  libBLS::BLSSigShare sig(sigShare, 1, 1, 1);
  libBLS::algebra::G1Point popProveEnclave = sig.getSigShare();

  REQUIRE(popProveLocal == popProveEnclave);
}

TEST_CASE_METHOD(TestFixture,
                 "Test pop prove for bls aggregated signatures scheme via zmq",
                 "[integration][bls][bls-aggregated-pop-prove-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";

  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::random();

  std::string keyStr = key.toString(libBLS::algebra::Base::HEXA);
  auto response = client->importBLSKeyShare(keyStr, name);
  REQUIRE(response);

  libBLS::algebra::G1Point popProveLocal = libBLS::Bls::PopProve(key);

  std::string pop_prove_response = client->popProve(name);
  libBLS::BLSSigShare sig(pop_prove_response, 1, 1, 1);
  libBLS::algebra::G1Point popProveEnclave = sig.getSigShare();

  REQUIRE(popProveLocal == popProveEnclave);
}
