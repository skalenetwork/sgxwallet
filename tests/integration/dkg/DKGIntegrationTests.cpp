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
*/


#include "tests/TestSupport.h"
#include "tests/integration/IntegrationTestSupport.h"
#include "tests/integration/dkg/DKGIntegrationTestSupport.h"

#include "BLSCrypto.h"
#include "BLSPublicKey.h"
#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "CryptoTools.h"
#include "DKGCrypto.h"
#include "libBLS/dkg/dkg.h"
#include "SGXException.h"
#include "common.h"
#include "secure_enclave/DHDkg.h"
#include "secure_enclave/TEUtils.h"
#include "secure_enclave_u.h"
#include "sgxwallet.h"
#include "tests/TestConstants.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#define PRINT_SRC_LINE cerr << "Executing line " << to_string(__LINE__) << endl;

using namespace jsonrpc;
using namespace std;

class TestFixtureDKGV3Api {
public:
  static constexpr int DKG_V3_API_N = 2;
  static constexpr int DKG_V3_API_T = 2;

  TestFixtureDKGV3Api() {
    static std::once_flag initOnce;

    std::call_once(initOnce, [] {
      resetTestDB();

      initConfig config = makeTestInitConfig(false, false, false, true, true);

      initAll(config);
    });
  }
};

#ifdef SGX_ENABLE_TEST_ECALLS

TEST_CASE_METHOD(TestFixture, "DKG AES gen test", "[integration][dkg][dkg-aes-gen]") {
  vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
  vector<char> errMsg(BUF_LEN, 0);

  int errStatus = 0;
  uint64_t encLen = 0;

  PRINT_SRC_LINE
  auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(),
                                    encryptedDKGSecret.data(), &encLen, 32);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> secret(BUF_LEN, 0);
  vector<char> errMsg1(BUF_LEN, 0);

  status = trustedDecryptDkgSecret(eid, &errStatus, errMsg1.data(),
                                   encryptedDKGSecret.data(), encLen,
                                   (uint8_t *)secret.data());

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "DKG AES public shares test",
                 "[integration][dkg][dkg-aes-pub-shares]") {
  vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
  vector<char> errMsg(BUF_LEN, 0);

  int errStatus = 0;
  uint64_t encLen = 0;

  unsigned t = 32, n = 32;
  PRINT_SRC_LINE
  auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(),
                                    encryptedDKGSecret.data(), &encLen, n);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> errMsg1(BUF_LEN, 0);

  char colon = ':';
  vector<char> pubShares(10000, 0);
  PRINT_SRC_LINE
  status = trustedGetPublicShares(eid, &errStatus, errMsg1.data(),
                                  encryptedDKGSecret.data(), encLen,
                                  pubShares.data(), t);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<string> g2Strings = splitString(pubShares.data(), ',');
  vector<libBLS::algebra::G2Point> pubSharesG2;
  for (u_int64_t i = 0; i < g2Strings.size(); i++) {
    vector<string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');

    pubSharesG2.push_back(TestSupport::vectStringToG2(coeffStr));
  }

  vector<char> secret(BUF_LEN, 0);
  PRINT_SRC_LINE
  status = trustedDecryptDkgSecret(eid, &errStatus, errMsg1.data(),
                                   encryptedDKGSecret.data(), encLen,
                                   (uint8_t *)secret.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  libBLS::Dkg dkgObj(t, n);

  vector<libBLS::algebra::FrScalar> poly =
      TestSupport::splitStringToFr(secret.data(), colon);
  vector<libBLS::algebra::G2Point> pubSharesDkg =
      dkgObj.VerificationVector(poly);
  REQUIRE(pubSharesG2 == pubSharesDkg);
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares test",
                 "[integration][dkg][dkg-aes-encr-sshares]") {
  vector<char> errMsg(BUF_LEN, 0);
  vector<char> result(BUF_LEN, 0);

  int errStatus = 0;
  uint64_t encLen = 0;

  vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
  PRINT_SRC_LINE
  auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(),
                                    encryptedDKGSecret.data(), &encLen, 2);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<uint8_t> encrPRDHKey(BUF_LEN, 0);

  string pub_keyB = SAMPLE_PUBLIC_KEY_B;

  vector<char> s_shareG2(BUF_LEN, 0);
  PRINT_SRC_LINE
  status = trustedGetEncryptedSecretShare(
      eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), encLen,
      encrPRDHKey.data(), &encLen, result.data(), s_shareG2.data(),
      (char *)pub_keyB.data(), 2, 2, 1);

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares version 2 test",
                 "[integration][dkg][dkg-aes-encr-sshares-v2]") {
  vector<char> errMsg(BUF_LEN, 0);
  vector<char> result(BUF_LEN, 0);

  int errStatus = 0;
  uint64_t encLen = 0;

  vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
  PRINT_SRC_LINE
  auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(),
                                    encryptedDKGSecret.data(), &encLen, 2);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<uint8_t> encrPRDHKey(BUF_LEN, 0);

  string pub_keyB = SAMPLE_PUBLIC_KEY_B;

  vector<char> s_shareG2(BUF_LEN, 0);
  PRINT_SRC_LINE
  status = trustedGetEncryptedSecretShareV2(
      eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), encLen,
      encrPRDHKey.data(), &encLen, result.data(), s_shareG2.data(),
      (char *)pub_keyB.data(), 2, 2, 1);

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "DKG AES V3 gen uses previous BLS key",
                 "[integration][dkg][dkg-aes-gen-v3]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;

  int exportable = 1;
  vector<uint8_t> encryptedBlsKey(BUF_LEN, 0);
  uint64_t encryptedBlsKeyLen = 0;

  // generate previous BLS key to be used in DKG V3 generation
  auto status =
      trustedGenerateBLSKey(eid, &errStatus, errMsg.data(), &exportable,
                            encryptedBlsKey.data(), &encryptedBlsKeyLen);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> previousBlsKey(BUF_LEN, 0);
  status =
      trustedDecryptKey(eid, &errStatus, errMsg.data(), encryptedBlsKey.data(),
                        encryptedBlsKeyLen, previousBlsKey.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  // generate DKG V3 using previous BLS key
  vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
  uint64_t encryptedDKGSecretLen = 0;

  status = trustedGenDkgSecretV3(
      eid, &errStatus, errMsg.data(), encryptedBlsKey.data(),
      encryptedBlsKeyLen, encryptedDKGSecret.data(), &encryptedDKGSecretLen, 2);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> decryptedDKGSecret(BUF_LEN, 0);
  status = trustedDecryptDkgSecret(
      eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(),
      encryptedDKGSecretLen, (uint8_t *)decryptedDKGSecret.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  // make sure the first coefficient of the polynomial is the same as the
  // previous BLS key
  vector<libBLS::algebra::FrScalar> poly =
      TestSupport::splitStringToFr(decryptedDKGSecret.data(), ':');
  REQUIRE(poly.size() == 2);

  auto previousBlsKeyFr = libBLS::algebra::FrScalar::fromString(
      previousBlsKey.data(), libBLS::algebra::Base::HEXA);
  REQUIRE(poly.at(0) == previousBlsKeyFr);

  // make sure the public key generated from the DKG for index 0 matches the
  // public key generated from the previous BLS key
  vector<char> expectedBlsPubKey(BUF_LEN, 0);
  status = trustedGetBlsPubKey(eid, &errStatus, errMsg.data(),
                               encryptedBlsKey.data(), encryptedBlsKeyLen,
                               expectedBlsPubKey.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> publicShares(10000, 0);
  status = trustedGetPublicShares(
      eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(),
      encryptedDKGSecretLen, publicShares.data(), 2);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<string> publicShareStrings = splitString(publicShares.data(), ',');
  REQUIRE(publicShareStrings.size() == 2);
  REQUIRE(publicShareStrings.at(0) == string(expectedBlsPubKey.data()));
}

#endif

TEST_CASE_METHOD(TestFixture, "DKG AES V3 create BLS key",
                 "[integration][dkg][dkg-aes-create-bls-v3]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;

  int exportable = 1;
  vector<uint8_t> encryptedPreviousBlsKey(BUF_LEN, 0);
  uint64_t encryptedPreviousBlsKeyLen = 0;

  // generate previous BLS
  auto status = trustedGenerateBLSKey(
      eid, &errStatus, errMsg.data(), &exportable,
      encryptedPreviousBlsKey.data(), &encryptedPreviousBlsKeyLen);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  // generate DKG V3 using previous BLS key
  vector<uint8_t> encryptedDKGSecret(BUF_LEN, 0);
  uint64_t encryptedDKGSecretLen = 0;
  status = trustedGenDkgSecretV3(
      eid, &errStatus, errMsg.data(), encryptedPreviousBlsKey.data(),
      encryptedPreviousBlsKeyLen, encryptedDKGSecret.data(),
      &encryptedDKGSecretLen, 2);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  // Generate a recipient ECDSA keypair: only the holder of recipient_sk can
  // decrypt the secret share (via ECDH with the sender's ephemeral pubkey).
  vector<uint8_t> encryptedRecipientKey(BUF_LEN, 0);
  uint64_t encryptedRecipientKeyLen = 0;
  vector<char> recipientPubKeyX(BUF_LEN, 0);
  vector<char> recipientPubKeyY(BUF_LEN, 0);
  int recipientExportable = 0;

  status = trustedGenerateEcdsaKey(
      eid, &errStatus, errMsg.data(), &recipientExportable,
      encryptedRecipientKey.data(), &encryptedRecipientKeyLen,
      recipientPubKeyX.data(), recipientPubKeyY.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  // Construct recipient public key in the 128-char (64X+64Y) format expected
  // by trustedGetEncryptedSecretShareV2.
  string recipientPublicKey =
      string(recipientPubKeyX.data()) + string(recipientPubKeyY.data());

  vector<char> encryptedSecretShare(193, 0);
  vector<char> secretShareG2(320, 0);
  vector<uint8_t> encryptedSenderKey(BUF_LEN, 0);
  uint64_t encryptedSenderKeyLen = 0;

  status = trustedGetEncryptedSecretShareV2(
      eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(),
      encryptedDKGSecretLen, encryptedSenderKey.data(), &encryptedSenderKeyLen,
      encryptedSecretShare.data(), secretShareG2.data(),
      (char *)recipientPublicKey.data(), 2, 2, 1);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<uint8_t> contributorIndices = {0};
  vector<uint8_t> encryptedBlsKey(BUF_LEN, 0);
  uint64_t encryptedBlsKeyLen = 0;

  // Decrypt using the recipient's private key: ECDH(recipient_sk, sender_pk)
  // recovers the same session key as ECDH(sender_sk, recipient_pk) used during
  // encryption.
  status = trustedCreateBlsKeyV3(
      eid, &errStatus, errMsg.data(), encryptedSecretShare.data(),
      contributorIndices.data(), contributorIndices.size(),
      encryptedRecipientKey.data(), encryptedRecipientKeyLen,
      encryptedBlsKey.data(), &encryptedBlsKeyLen);
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> blsPubKey(320, 0);
  status = trustedGetBlsPubKey(eid, &errStatus, errMsg.data(),
                               encryptedBlsKey.data(), encryptedBlsKeyLen,
                               blsPubKey.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  REQUIRE(string(blsPubKey.data()) == string(secretShareG2.data()));
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS test", "[integration][dkg][dkg-bls]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  vector<string> ecdsaKeyNames;
  vector<string> blsKeyNames;

  int schainID = TestSupport::randGen();
  int dkgID = TestSupport::randGen();

  PRINT_SRC_LINE
  DKGIntegrationTestSupport::doDKG(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

  REQUIRE(blsKeyNames.size() == 4);

  schainID = TestSupport::randGen();
  dkgID = TestSupport::randGen();

  DKGIntegrationTestSupport::doDKG(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 test", "[integration][dkg][dkg-bls-v2]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  vector<string> ecdsaKeyNames;
  vector<string> blsKeyNames;

  int schainID = TestSupport::randGen();
  int dkgID = TestSupport::randGen();

  PRINT_SRC_LINE
  DKGIntegrationTestSupport::doDKGV2(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

  REQUIRE(blsKeyNames.size() == 4);

  schainID = TestSupport::randGen();
  dkgID = TestSupport::randGen();

  DKGIntegrationTestSupport::doDKGV2(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 to V3 rotation correctness",
                 "[integration][dkg][dkg-bls-v2-v3-rotation]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int schainID = TestSupport::randGen();
  int dkgV2ID = TestSupport::randGen();
  int dkgV3ID = dkgV2ID + 1;

  PRINT_SRC_LINE
  DKGIntegrationTestSupport::doDKGV3Rotation(c, 5, 3, schainID, dkgV2ID, dkgV3ID, 50, 3);

  schainID = TestSupport::randGen();
  dkgV2ID = TestSupport::randGen();
  dkgV3ID = dkgV2ID + 1;

  DKGIntegrationTestSupport::doDKGV3Rotation(c, 16, 5, schainID, dkgV2ID, dkgV3ID, 1, 1);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 to V3 rotation with joining nodes",
                 "[integration][dkg][dkg-bls-v2-v3-rotation-new-nodes]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int schainID = TestSupport::randGen();
  int dkgV2ID = TestSupport::randGen();
  int dkgV3ID = dkgV2ID + 1;

  PRINT_SRC_LINE
  DKGIntegrationTestSupport::doDKGV3RotationWithNewNodes(c, 4, 4, 3, 1, schainID, dkgV2ID,
                                         dkgV3ID, 1);

  schainID = TestSupport::randGen();
  dkgV2ID = TestSupport::randGen();
  dkgV3ID = dkgV2ID + 1;

  DKGIntegrationTestSupport::doDKGV3RotationWithNewNodes(c, 10, 10, 7, 6, schainID, dkgV2ID,
                                         dkgV3ID, 1);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 to V3 rotation security",
                 "[integration][dkg][dkg-bls-v2-v3-rotation-security]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int schainID = TestSupport::randGen();
  int dkgV2ID = TestSupport::randGen();
  int dkgV3ID = dkgV2ID + 1;

  PRINT_SRC_LINE

  // Case 1: Rotate a threshold of nodes - the nodes rotated out should be able
  // to decrypt together
  DKGIntegrationTestSupport::doDKGV3UnsafeRotatedNodesCanDecrypt(c, 10, 7, 7, schainID, dkgV2ID,
                                                 dkgV3ID);

  schainID = TestSupport::randGen();
  dkgV2ID = TestSupport::randGen();
  dkgV3ID = dkgV2ID + 1;
  int dkgV4ID = dkgV2ID + 2;

  // Case 2: Do 2 successive rotations, each rotating out number of nodes < t
  // If all nodes join such that number of nodes > t, they should still not be
  // able to decrypt
  DKGIntegrationTestSupport::doDKGV3CrossEpochRetiredNodesCannotCollude(
      c, 10, 7, 4, 4, schainID, dkgV2ID, dkgV3ID, dkgV4ID);

  // Case 3: Test boundary conditions varying number of faulty nodes.
  auto runScenario = [&](int n, int t, int rotatedCount, int nonRespondingCount,
                         bool shouldDecrypt) {
    int schainID = TestSupport::randGen();
    int dkgV2ID = TestSupport::randGen();
    int dkgV3ID = dkgV2ID + 1;

    DKGIntegrationTestSupport::doDKGV3RotationWithNonRespondingNodes(
        c, n, t, rotatedCount, nonRespondingCount, shouldDecrypt, schainID,
        dkgV2ID, dkgV3ID);
  };

  // should work - 4 nodes, 1 rotated, 1 faulty
  runScenario(4, 3, 1, 1, true);
  // should not work - 4 nodes, 1 rotated, 2 faulty
  runScenario(4, 3, 1, 2, false);
  // should work - 10 nodes, 1 rotated, 3 faulty
  runScenario(10, 7, 1, 3, true);
  // should work - 10 nodes, 6 rotated, 3 faulty (unsafe in practice since
  // rotated > n - t)
  runScenario(10, 7, 6, 3, true);
  // should not work - 10 nodes, 1 rotated, 4 faulty
  runScenario(10, 7, 1, 4, false);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS ZMQ test", "[integration][dkg][dkg-bls-zmq]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  string empty = "";
  auto zmqClient = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  vector<string> ecdsaKeyNames;
  vector<string> blsKeyNames;

  int schainID = TestSupport::randGen();
  int dkgID = TestSupport::randGen();

  PRINT_SRC_LINE
  DKGIntegrationTestSupport::doZMQBLS(zmqClient, c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID,
                      dkgID);
  REQUIRE(blsKeyNames.size() == 4);
  schainID = TestSupport::randGen();
  dkgID = TestSupport::randGen();
  DKGIntegrationTestSupport::doZMQBLS(zmqClient, c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID,
                      dkgID);
}

TEST_CASE_METHOD(TestFixture, "DKG API V2 test", "[integration][dkg][dkg-api-v2]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  string polyName = SAMPLE_POLY_NAME;

  PRINT_SRC_LINE
  Json::Value genPoly = c.generateDKGPoly(polyName, 2);
  REQUIRE(genPoly["status"].asInt() == 0);

  Json::Value publicKeys;
  publicKeys.append(SAMPLE_DKG_PUB_KEY_1);
  publicKeys.append(SAMPLE_DKG_PUB_KEY_2);

  // wrongName
  Json::Value genPolyWrongName = c.generateDKGPoly("poly", 2);
  REQUIRE(genPolyWrongName["status"].asInt() != 0);

  Json::Value verifVectWrongName = c.getVerificationVector("poly", 2);
  REQUIRE(verifVectWrongName["status"].asInt() != 0);

  Json::Value secretSharesWrongName =
      c.getSecretShareV2("poly", publicKeys, 2, 2);
  REQUIRE(secretSharesWrongName["status"].asInt() != 0);

  // wrong_t
  Json::Value genPolyWrong_t = c.generateDKGPoly(polyName, 33);
  REQUIRE(genPolyWrong_t["status"].asInt() != 0);

  Json::Value verifVectWrong_t = c.getVerificationVector(polyName, 1);
  REQUIRE(verifVectWrong_t["status"].asInt() != 0);

  Json::Value secretSharesWrong_t =
      c.getSecretShareV2(polyName, publicKeys, 3, 3);
  REQUIRE(secretSharesWrong_t["status"].asInt() != 0);

  Json::Value publicKeys1;
  publicKeys1.append(SAMPLE_DKG_PUB_KEY_1);
  Json::Value secretSharesWrong_n =
      c.getSecretShareV2(polyName, publicKeys1, 2, 1);
  REQUIRE(secretSharesWrong_n["status"].asInt() != 0);

  // wrong number of publicKeys
  Json::Value secretSharesWrongPkeys =
      c.getSecretShareV2(polyName, publicKeys, 2, 3);
  REQUIRE(secretSharesWrongPkeys["status"].asInt() != 0);

  // wrong verif
  Json::Value Skeys = c.getSecretShareV2(polyName, publicKeys, 2, 2);
  REQUIRE_NOTHROW(c.getSecretShare(polyName, publicKeys, 2, 2));
  REQUIRE(Skeys == c.getSecretShare(polyName, publicKeys, 2, 2));

  Json::Value verifVect = c.getVerificationVector(polyName, 2);
  REQUIRE_NOTHROW(c.getVerificationVector(polyName, 2));
  REQUIRE(verifVect == c.getVerificationVector(polyName, 2));

  Json::Value verificationWrongSkeys = c.dkgVerificationV2("", "", "", 2, 2, 1);
  REQUIRE(verificationWrongSkeys["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixture, "DKG API V2 ZMQ test", "[integration][dkg][dkg-api-v2-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  string polyName = SAMPLE_POLY_NAME;

  PRINT_SRC_LINE
  REQUIRE(client->generateDKGPoly(polyName, 2));

  Json::Value publicKeys;
  publicKeys.append(SAMPLE_DKG_PUB_KEY_1);
  publicKeys.append(SAMPLE_DKG_PUB_KEY_2);

  // wrongName
  REQUIRE(!client->generateDKGPoly("poly", 2));

  REQUIRE_THROWS(client->getVerificationVector("poly", 2));

  REQUIRE_THROWS(client->getSecretShare("poly", publicKeys, 2, 2));

  // wrong_t
  REQUIRE(!client->generateDKGPoly(polyName, 33));

  REQUIRE_THROWS(client->getVerificationVector(polyName, 0));

  REQUIRE_THROWS(client->getSecretShare(polyName, publicKeys, 3, 3));

  Json::Value publicKeys1;
  publicKeys1.append(SAMPLE_DKG_PUB_KEY_1);
  REQUIRE_THROWS(client->getSecretShare(polyName, publicKeys1, 2, 1));

  // wrong number of publicKeys
  REQUIRE_THROWS(client->getSecretShare(polyName, publicKeys, 2, 3));

  // wrong verif
  string Skeys = client->getSecretShare(polyName, publicKeys, 2, 2);
  REQUIRE_NOTHROW(client->getSecretShare(polyName, publicKeys, 2, 2));
  REQUIRE(Skeys == client->getSecretShare(polyName, publicKeys, 2, 2));

  Json::Value verifVect = client->getVerificationVector(polyName, 2);
  REQUIRE_NOTHROW(client->getVerificationVector(polyName, 2));
  REQUIRE(verifVect == client->getVerificationVector(polyName, 2));

  REQUIRE_THROWS(client->dkgVerification("", "", "", 2, 2, 1));
}

TEST_CASE_METHOD(TestFixtureDKGV3Api,
                 "DKG V3 JSONRPC API generates DKG polynomial",
                 "[integration][dkg][dkg-api-v3-generate-poly]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  const int schainID = TestSupport::randGen();
  const int dkgV2ID = TestSupport::randGen();
  const int dkgV3ID = TestSupport::randGen();

  const string previousBlsKeyName =
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 0, dkgV2ID);
  Json::Value previousBlsKey = c.generateBLSPrivateKey(previousBlsKeyName);
  REQUIRE(previousBlsKey["status"].asInt() == 0);

  const string polyName = DKGIntegrationTestSupport::makeDKGPolyName(schainID, 0, dkgV3ID);
  Json::Value genPoly =
      c.generateDKGPolyV3(polyName, previousBlsKeyName, DKG_V3_API_T);
  REQUIRE(genPoly["status"].asInt() == 0);

  Json::Value verificationVector =
      c.getVerificationVector(polyName, DKG_V3_API_T);
  REQUIRE(verificationVector["status"].asInt() == 0);
  REQUIRE(!DKGIntegrationTestSupport::publicSharesFromVerificationVector(verificationVector,
                                                         DKG_V3_API_T)
               .empty());

  Json::Value genPolyWrongName =
      c.generateDKGPolyV3("poly", previousBlsKeyName, DKG_V3_API_T);
  REQUIRE(genPolyWrongName["status"].asInt() != 0);

  Json::Value genPolyWrongPreviousBls = c.generateDKGPolyV3(
      DKGIntegrationTestSupport::makeDKGPolyName(schainID, 1, dkgV3ID), "bls", DKG_V3_API_T);
  REQUIRE(genPolyWrongPreviousBls["status"].asInt() != 0);

  Json::Value genPolyWrongT = c.generateDKGPolyV3(
      DKGIntegrationTestSupport::makeDKGPolyName(schainID, 2, dkgV3ID), previousBlsKeyName, 33);
  REQUIRE(genPolyWrongT["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixtureDKGV3Api, "DKG V3 JSONRPC API creates BLS key",
                 "[integration][dkg][dkg-api-v3-create-bls]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  const int schainID = TestSupport::randGen();
  const int dkgV2ID = TestSupport::randGen();
  const int dkgV3ID = TestSupport::randGen();

  vector<string> ecdsaKeyNames(DKG_V3_API_N);
  Json::Value publicEcdsaKeys(Json::arrayValue);
  vector<string> previousBlsKeyNames(DKG_V3_API_N);
  vector<string> polyNames(DKG_V3_API_N);
  vector<string> publicShares(DKG_V3_API_N);
  vector<string> dealerSecretShares(DKG_V3_API_N);

  for (int i = 0; i < DKG_V3_API_N; ++i) {
    Json::Value ecdsaKey = c.generateECDSAKey();
    REQUIRE(ecdsaKey["status"].asInt() == 0);
    ecdsaKeyNames[i] = ecdsaKey["keyName"].asString();
    publicEcdsaKeys.append(ecdsaKey["publicKey"]);

    previousBlsKeyNames[i] = DKGIntegrationTestSupport::makeBLSKeyName(schainID, i, dkgV2ID);
    Json::Value previousBlsKey =
        c.generateBLSPrivateKey(previousBlsKeyNames[i]);
    REQUIRE(previousBlsKey["status"].asInt() == 0);

    polyNames[i] = DKGIntegrationTestSupport::makeDKGPolyName(schainID, i, dkgV3ID);
    Json::Value genPoly =
        c.generateDKGPolyV3(polyNames[i], previousBlsKeyNames[i], DKG_V3_API_T);
    REQUIRE(genPoly["status"].asInt() == 0);

    Json::Value verificationVector =
        c.getVerificationVector(polyNames[i], DKG_V3_API_T);
    REQUIRE(verificationVector["status"].asInt() == 0);
    publicShares[i] = DKGIntegrationTestSupport::publicSharesFromVerificationVector(
        verificationVector, DKG_V3_API_T);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    Json::Value secretShares = c.getSecretShareV2(
        polyNames[contributor], publicEcdsaKeys, DKG_V3_API_T, DKG_V3_API_N);
    REQUIRE(secretShares["status"].asInt() == 0);
    dealerSecretShares[contributor] = secretShares["secretShare"].asString();
    REQUIRE(dealerSecretShares[contributor].length() ==
            static_cast<size_t>(DKG_V3_API_N) *
                DKGIntegrationTestSupport::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    for (int recipient = 0; recipient < DKG_V3_API_N; ++recipient) {
      const string contribution =
          DKGIntegrationTestSupport::encryptedDkgSecretContributionForRecipient(
              dealerSecretShares[contributor], recipient);
      Json::Value verification = c.dkgVerificationV2(
          publicShares[contributor], ecdsaKeyNames[recipient], contribution,
          DKG_V3_API_T, DKG_V3_API_N, recipient);
      REQUIRE(verification["status"].asInt() == 0);
      REQUIRE(verification["result"].asBool());
    }
  }

  Json::Value firstRecipientContributions =
      DKGIntegrationTestSupport::dkgV3SecretContributionsForRecipient(dealerSecretShares, 0);
  const string firstBlsKeyName =
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 0, dkgV3ID);
  Json::Value createFirst = c.createBLSPrivateKeyV3(
      firstBlsKeyName, ecdsaKeyNames[0], polyNames[0],
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createFirst["status"].asInt() == 0);

  Json::Value firstPublicKey = c.getBLSPublicKeyShare(firstBlsKeyName);
  REQUIRE(firstPublicKey["status"].asInt() == 0);
  REQUIRE(firstPublicKey["blsPublicKeyShare"].isArray());

  Json::Value secondRecipientContributions =
      DKGIntegrationTestSupport::dkgV3SecretContributionsForRecipient(dealerSecretShares, 1);
  const string secondBlsKeyName =
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 1, dkgV3ID);
  Json::Value createSecond = c.createBLSPrivateKeyV3(
      secondBlsKeyName, ecdsaKeyNames[1], "", secondRecipientContributions,
      DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createSecond["status"].asInt() == 0);

  Json::Value secondPublicKey = c.getBLSPublicKeyShare(secondBlsKeyName);
  REQUIRE(secondPublicKey["status"].asInt() == 0);
  REQUIRE(secondPublicKey["blsPublicKeyShare"].isArray());

  Json::Value createWrongBlsName = c.createBLSPrivateKeyV3(
      "bls", ecdsaKeyNames[0], "", firstRecipientContributions, DKG_V3_API_T,
      DKG_V3_API_N);
  REQUIRE(createWrongBlsName["status"].asInt() != 0);

  Json::Value createWrongEcdsaName = c.createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 2, dkgV3ID), "eth", "",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createWrongEcdsaName["status"].asInt() != 0);

  Json::Value createWrongPolyName = c.createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 3, dkgV3ID), ecdsaKeyNames[0], "poly",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createWrongPolyName["status"].asInt() != 0);

  Json::Value malformedContributions(Json::objectValue);
  Json::Value createMalformedContributions = c.createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 4, dkgV3ID), ecdsaKeyNames[0], "",
      malformedContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createMalformedContributions["status"].asInt() != 0);

  Json::Value tooFewContributions(Json::arrayValue);
  tooFewContributions.append(firstRecipientContributions[0]);
  Json::Value createTooFewContributions = c.createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 5, dkgV3ID), ecdsaKeyNames[0], "",
      tooFewContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createTooFewContributions["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixtureDKGV3Api, "DKG V3 ZMQ API generates DKG polynomial",
                 "[integration][dkg][dkg-api-v3-zmq-generate-poly]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  const int schainID = TestSupport::randGen();
  const int dkgV2ID = TestSupport::randGen();
  const int dkgV3ID = TestSupport::randGen();

  const string previousBlsKeyName =
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 0, dkgV2ID);
  REQUIRE(client->generateBLSPrivateKey(previousBlsKeyName));

  const string polyName = DKGIntegrationTestSupport::makeDKGPolyName(schainID, 0, dkgV3ID);
  REQUIRE(
      client->generateDKGPolyV3(polyName, previousBlsKeyName, DKG_V3_API_T));

  Json::Value verificationVector =
      client->getVerificationVector(polyName, DKG_V3_API_T);
  REQUIRE(!DKGIntegrationTestSupport::publicSharesFromVerificationVector(verificationVector,
                                                         DKG_V3_API_T)
               .empty());

  REQUIRE(!client->generateDKGPolyV3("poly", previousBlsKeyName, DKG_V3_API_T));
  REQUIRE_THROWS(client->generateDKGPolyV3(
      DKGIntegrationTestSupport::makeDKGPolyName(schainID, 1, dkgV3ID), "bls", DKG_V3_API_T));
  REQUIRE(!client->generateDKGPolyV3(
      DKGIntegrationTestSupport::makeDKGPolyName(schainID, 2, dkgV3ID), previousBlsKeyName,
      33));
}

TEST_CASE_METHOD(TestFixtureDKGV3Api, "DKG V3 ZMQ API creates BLS key",
                 "[integration][dkg][dkg-api-v3-zmq-create-bls]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  const int schainID = TestSupport::randGen();
  const int dkgV2ID = TestSupport::randGen();
  const int dkgV3ID = TestSupport::randGen();

  vector<string> ecdsaKeyNames(DKG_V3_API_N);
  Json::Value publicEcdsaKeys(Json::arrayValue);
  vector<string> previousBlsKeyNames(DKG_V3_API_N);
  vector<string> polyNames(DKG_V3_API_N);
  vector<string> publicShares(DKG_V3_API_N);
  vector<string> dealerSecretShares(DKG_V3_API_N);

  // generate some BLSkeys and polys to simulate DKG process
  for (int i = 0; i < DKG_V3_API_N; ++i) {
    auto ecdsaKey = client->generateECDSAKey();
    publicEcdsaKeys.append(ecdsaKey.first);
    ecdsaKeyNames[i] = ecdsaKey.second;

    // generate some BLS key (simulate previous DKG keys)
    previousBlsKeyNames[i] = DKGIntegrationTestSupport::makeBLSKeyName(schainID, i, dkgV2ID);
    REQUIRE(client->generateBLSPrivateKey(previousBlsKeyNames[i]));

    // generate poly using previous DKG key
    polyNames[i] = DKGIntegrationTestSupport::makeDKGPolyName(schainID, i, dkgV3ID);
    REQUIRE(client->generateDKGPolyV3(polyNames[i], previousBlsKeyNames[i],
                                      DKG_V3_API_T));

    Json::Value verificationVector =
        client->getVerificationVector(polyNames[i], DKG_V3_API_T);
    publicShares[i] = DKGIntegrationTestSupport::publicSharesFromVerificationVector(
        verificationVector, DKG_V3_API_T);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    dealerSecretShares[contributor] = client->getSecretShare(
        polyNames[contributor], publicEcdsaKeys, DKG_V3_API_T, DKG_V3_API_N);
    REQUIRE(dealerSecretShares[contributor].length() ==
            static_cast<size_t>(DKG_V3_API_N) *
                DKGIntegrationTestSupport::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    for (int recipient = 0; recipient < DKG_V3_API_N; ++recipient) {
      const string contribution =
          DKGIntegrationTestSupport::encryptedDkgSecretContributionForRecipient(
              dealerSecretShares[contributor], recipient);
      REQUIRE(client->dkgVerification(publicShares[contributor],
                                      ecdsaKeyNames[recipient], contribution,
                                      DKG_V3_API_T, DKG_V3_API_N, recipient));
    }
  }

  Json::Value firstRecipientContributions =
      DKGIntegrationTestSupport::dkgV3SecretContributionsForRecipient(dealerSecretShares, 0);
  const string firstBlsKeyName =
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 0, dkgV3ID);
  REQUIRE(client->createBLSPrivateKeyV3(
      firstBlsKeyName, ecdsaKeyNames[0], polyNames[0],
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N));

  Json::Value firstPublicKey = client->getBLSPublicKey(firstBlsKeyName);
  REQUIRE(firstPublicKey.isArray());

  Json::Value secondRecipientContributions =
      DKGIntegrationTestSupport::dkgV3SecretContributionsForRecipient(dealerSecretShares, 1);
  const string secondBlsKeyName =
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 1, dkgV3ID);
  REQUIRE(client->createBLSPrivateKeyV3(secondBlsKeyName, ecdsaKeyNames[1], "",
                                        secondRecipientContributions,
                                        DKG_V3_API_T, DKG_V3_API_N));

  Json::Value secondPublicKey = client->getBLSPublicKey(secondBlsKeyName);
  REQUIRE(secondPublicKey.isArray());

  REQUIRE(!client->createBLSPrivateKeyV3("bls", ecdsaKeyNames[0], "",
                                         firstRecipientContributions,
                                         DKG_V3_API_T, DKG_V3_API_N));

  REQUIRE_THROWS(client->createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 2, dkgV3ID), "eth", "",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N));

  REQUIRE_THROWS(client->createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 3, dkgV3ID), ecdsaKeyNames[0], "poly",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N));

  Json::Value malformedContributions(Json::objectValue);
  REQUIRE(!client->createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 4, dkgV3ID), ecdsaKeyNames[0], "",
      malformedContributions, DKG_V3_API_T, DKG_V3_API_N));

  Json::Value tooFewContributions(Json::arrayValue);
  tooFewContributions.append(firstRecipientContributions[0]);
  REQUIRE(!client->createBLSPrivateKeyV3(
      DKGIntegrationTestSupport::makeBLSKeyName(schainID, 5, dkgV3ID), ecdsaKeyNames[0], "",
      tooFewContributions, DKG_V3_API_T, DKG_V3_API_N));
}

TEST_CASE_METHOD(TestFixture, "PolyExists test", "[integration][dkg][dkg-poly-exists]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  string polyName = SAMPLE_POLY_NAME;
  PRINT_SRC_LINE
  Json::Value genPoly = c.generateDKGPoly(polyName, 2);
  REQUIRE(genPoly["status"] == 0);

  PRINT_SRC_LINE
  Json::Value polyExists = c.isPolyExists(polyName);
  REQUIRE(polyExists["status"] == 0);
  REQUIRE(polyExists["IsExist"].asBool());

  PRINT_SRC_LINE
  Json::Value polyDoesNotExist = c.isPolyExists("Vasya");
  REQUIRE(!polyDoesNotExist["IsExist"].asBool());
}

TEST_CASE_METHOD(TestFixture, "PolyExistsZmq test", "[integration][dkg][dkg-poly-exists-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  string polyName = SAMPLE_POLY_NAME;
  REQUIRE_NOTHROW(client->generateDKGPoly(polyName, 2));

  bool polyExists = client->isPolyExists(polyName);
  REQUIRE(polyExists);

  bool polyDoesNotExist = client->isPolyExists("Vasya");
  REQUIRE(!polyDoesNotExist);
}

TEST_CASE_METHOD(TestFixture, "AES_DKG V2 test", "[integration][dkg][aes-dkg-v2]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int n = 2, t = 2;
  Json::Value ethKeys[n];
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  Json::Value secretShares[n];
  Json::Value pubBLSKeys[n];
  Json::Value blsSigShares[n];
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  int schainID = TestSupport::randGen();
  int dkgID = TestSupport::randGen();
  for (uint8_t i = 0; i < n; i++) {
    PRINT_SRC_LINE
    ethKeys[i] = c.generateECDSAKey();
    REQUIRE(ethKeys[i]["status"] == 0);
    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);
    REQUIRE(ethKeys[i]["status"] == 0);
    auto response = c.generateDKGPoly(polyName, t);
    REQUIRE(response["status"] == 0);

    polyNames[i] = polyName;
    PRINT_SRC_LINE
    verifVects[i] = c.getVerificationVector(polyName, t);
    REQUIRE(verifVects[i]["status"] == 0);

    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    PRINT_SRC_LINE
    secretShares[i] = c.getSecretShareV2(polyNames[i], pubEthKeys, t, n);
    REQUIRE(secretShares[i]["status"] == 0);

    for (uint8_t k = 0; k < t; k++)
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        pubShares[i] += TestSupport::convertDecToHex(pubShare);
      }
  }

  int k = 0;
  vector<string> secShares(n);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      PRINT_SRC_LINE
      Json::Value verif = c.dkgVerificationV2(
          pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
      REQUIRE(verif["status"] == 0);
      bool res = verif["result"].asBool();
      k++;
      REQUIRE(res);
    }

  Json::Value complaintResponse = c.complaintResponse(polyNames[1], t, n, 0);
  REQUIRE(complaintResponse["status"] == 0);

  string dhKey = complaintResponse["dhKey"].asString();
  string shareG2 = complaintResponse["share*G2"].asString();
  string secretShare = secretShares[1]["secretShare"].asString().substr(0, 192);

  vector<char> message(65, 0);

  SAFE_CHAR_BUF(encr_sshare, BUF_LEN)
  strncpy(encr_sshare, pubEthKeys[0].asString().c_str(), 128);

  SAFE_CHAR_BUF(common_key, BUF_LEN);
  REQUIRE(DKGIntegrationTestSupport::sessionKeyRecoverDH(dhKey.c_str(), encr_sshare, common_key) == 0);

  uint8_t key_to_hash[33];
  uint64_t len;
  REQUIRE(hex2carray(common_key, &len, key_to_hash, 64));

  auto hashed_key =
      cryptlite::sha256::hash_hex(string((char *)key_to_hash, 32));

  SAFE_CHAR_BUF(derived_key, 33)

  uint64_t key_length;
  REQUIRE(hex2carray(&hashed_key[0], &key_length, (uint8_t *)derived_key, 33));

  SAFE_CHAR_BUF(encr_sshare_check, BUF_LEN)
  strncpy(encr_sshare_check, secretShare.c_str(), ECDSA_SKEY_LEN - 1);

  REQUIRE(DKGIntegrationTestSupport::xorDecryptDHV2(derived_key, encr_sshare_check, message) == 0);

  libBLS::algebra::FrScalar share = libBLS::algebra::FrScalar::fromString(
      string(message.data()), libBLS::algebra::Base::HEXA);
  libBLS::algebra::G2Point decrypted_share_G2 =
      share * libBLS::algebra::G2Point::generator();

  REQUIRE(decrypted_share_G2.toString(libBLS::algebra::Base::DEC) == shareG2);

  Json::Value verificationVectorMult =
      complaintResponse["verificationVectorMult"];

  libBLS::algebra::G2Point verificationValue =
      libBLS::algebra::G2Point::identity();
  for (int i = 0; i < t; ++i) {
    std::vector<std::string> vvMultVec = {
        verificationVectorMult[i][0].asString(),
        verificationVectorMult[i][1].asString(),
        verificationVectorMult[i][2].asString(),
        verificationVectorMult[i][3].asString()};
    libBLS::algebra::G2Point value = libBLS::algebra::G2Point::fromString(
        vvMultVec, libBLS::algebra::Base::DEC);
    verificationValue = verificationValue + value;
  }
  REQUIRE(verificationValue == decrypted_share_G2);

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  array<uint8_t, 32> hash_arr;

  uint64_t binLen;

  if (!hex2carray(hash.c_str(), &binLen, hash_arr.data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, libBLS::BLSPublicKeyShare> coeffs_pkeys_map;

  for (int i = 0; i < t; i++) {
    string endName = polyNames[i].substr(4);
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    auto response =
        c.createBLSPrivateKeyV2(blsName, ethKeys[i]["keyName"].asString(),
                                polyNames[i], secShares[i], t, n);
    REQUIRE(response["status"] == 0);

    PRINT_SRC_LINE
    pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
    REQUIRE(pubBLSKeys[i]["status"] == 0);

    string hash = SAMPLE_HASH;
    blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
    REQUIRE(blsSigShares[i]["status"] == 0);

    string sig_share = blsSigShares[i]["signatureShare"].asString();
    libBLS::BLSSigShare sig(sig_share, i + 1, t, n);
    sigShareSet.addSigShare(sig);

    vector<string> pubKey_vect;
    for (uint8_t j = 0; j < 4; j++) {
      pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
    }
    libBLS::BLSPublicKeyShare pubKey(pubKey_vect, t, n);
    PRINT_SRC_LINE
    REQUIRE(pubKey.VerifySigWithHelper(hash_arr, sig, t, n));

    coeffs_pkeys_map.insert(std::make_pair(i + 1, pubKey));
  }

  libBLS::BLSSignature commonSig = sigShareSet.merge();
  libBLS::BLSPublicKey common_public(coeffs_pkeys_map, t, n);
  REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig));
}

TEST_CASE_METHOD(TestFixture, "AES_DKG V2 ZMQ test", "[integration][dkg][aes-dkg-v2-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  int n = 2, t = 2;
  vector<string> ethKeys(n);
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  vector<string> secretShares(n);
  Json::Value pubBLSKeys[n];
  vector<string> blsSigShares(n);
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  int schainID = TestSupport::randGen();
  int dkgID = TestSupport::randGen();
  for (uint8_t i = 0; i < n; i++) {
    auto generatedKey = client->generateECDSAKey();
    ethKeys[i] = generatedKey.second;
    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);
    CHECK_STATE(client->generateDKGPoly(polyName, t));
    polyNames[i] = polyName;
    verifVects[i] = client->getVerificationVector(polyName, t);

    pubEthKeys.append(generatedKey.first);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = client->getSecretShare(polyNames[i], pubEthKeys, t, n);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i][k][j].asString();
        pubShares[i] += TestSupport::convertDecToHex(pubShare);
      }
    }
  }

  int k = 0;
  vector<string> secShares(n);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare = secretShares[i].substr(192 * j, 192);
      secShares[i] += secretShares[j].substr(192 * i, 192);
      REQUIRE(client->dkgVerification(pubShares[i], ethKeys[j], secretShare, t,
                                      n, j));
      k++;
    }

  auto complaintResponse = client->complaintResponse(polyNames[1], t, n, 0);

  string dhKey = std::get<0>(complaintResponse);
  string shareG2 = std::get<1>(complaintResponse);
  string secretShare = secretShares[1].substr(0, 192);

  vector<char> message(65, 0);

  SAFE_CHAR_BUF(encr_sshare, BUF_LEN)
  strncpy(encr_sshare, pubEthKeys[0].asString().c_str(), 128);

  SAFE_CHAR_BUF(common_key, BUF_LEN);
  REQUIRE(DKGIntegrationTestSupport::sessionKeyRecoverDH(dhKey.c_str(), encr_sshare, common_key) == 0);

  uint8_t key_to_hash[33];
  uint64_t len;
  REQUIRE(hex2carray(common_key, &len, key_to_hash, 64));

  auto hashed_key =
      cryptlite::sha256::hash_hex(string((char *)key_to_hash, 32));

  SAFE_CHAR_BUF(derived_key, 33)

  uint64_t key_length;
  REQUIRE(hex2carray(&hashed_key[0], &key_length, (uint8_t *)derived_key, 33));

  SAFE_CHAR_BUF(encr_sshare_check, BUF_LEN)
  strncpy(encr_sshare_check, secretShare.c_str(), ECDSA_SKEY_LEN - 1);

  REQUIRE(DKGIntegrationTestSupport::xorDecryptDHV2(derived_key, encr_sshare_check, message) == 0);

  libBLS::algebra::FrScalar share = libBLS::algebra::FrScalar::fromString(
      string(message.data()), libBLS::algebra::Base::HEXA);
  libBLS::algebra::G2Point decrypted_share_G2 =
      share * libBLS::algebra::G2Point::generator();

  REQUIRE(decrypted_share_G2.toString(libBLS::algebra::Base::DEC) == shareG2);

  Json::Value verificationVectorMult = std::get<2>(complaintResponse);

  libBLS::algebra::G2Point verificationValue =
      libBLS::algebra::G2Point::identity();
  for (int i = 0; i < t; ++i) {
    std::vector<std::string> vvMultVec = {
        verificationVectorMult[i][0].asString(),
        verificationVectorMult[i][1].asString(),
        verificationVectorMult[i][2].asString(),
        verificationVectorMult[i][3].asString()};
    libBLS::algebra::G2Point value = libBLS::algebra::G2Point::fromString(
        vvMultVec, libBLS::algebra::Base::DEC);
    verificationValue = verificationValue + value;
  }
  REQUIRE(verificationValue == decrypted_share_G2);

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  array<uint8_t, 32> hash_arr;

  uint64_t binLen;

  if (!hex2carray(hash.c_str(), &binLen, hash_arr.data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, libBLS::BLSPublicKeyShare> coeffs_pkeys_map;

  for (int i = 0; i < t; i++) {
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    REQUIRE(client->createBLSPrivateKey(blsName, ethKeys[i], polyNames[i],
                                        secShares[i], t, n));

    pubBLSKeys[i] = client->getBLSPublicKey(blsName);

    string hash = SAMPLE_HASH;
    blsSigShares[i] = client->blsSignMessageHash(blsName, hash, t, n);
    REQUIRE(blsSigShares[i].length() > 0);

    libBLS::BLSSigShare sig(blsSigShares[i], i + 1, t, n);
    sigShareSet.addSigShare(sig);

    vector<string> pubKey_vect;
    for (uint8_t j = 0; j < 4; j++) {
      pubKey_vect.push_back(pubBLSKeys[i][j].asString());
    }
    libBLS::BLSPublicKeyShare pubKey(pubKey_vect, t, n);
    REQUIRE(pubKey.VerifySigWithHelper(hash_arr, sig, t, n));

    coeffs_pkeys_map.insert(std::make_pair(i + 1, pubKey));
  }

  libBLS::BLSSignature commonSig = sigShareSet.merge();
  libBLS::BLSPublicKey common_public(coeffs_pkeys_map, t, n);
  REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig));
}

TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg v2 bls",
                 "[integration][dkg][many-threads-crypto-v2]") {
  vector<thread> threads;
  int num_threads = 4;
  for (int i = 0; i < num_threads; i++) {
    threads.push_back(thread(DKGIntegrationTestSupport::sendRPCRequestV2));
  }

  for (auto &thread : threads) {
    thread.join();
  }
}

TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg v2 bls zmq",
                 "[integration][dkg][many-threads-crypto-v2-zmq]") {
  vector<thread> threads;
  int num_threads = 4;
  for (int i = 0; i < num_threads; i++) {
    threads.push_back(thread(DKGIntegrationTestSupport::sendRPCRequestZMQ));
  }

  for (auto &thread : threads) {
    thread.join();
  }
}
