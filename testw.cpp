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

    @file testw.cpp
    @author Stan Kladko
    @date 2020
*/

#include "secure_enclave/DHDkg.h"
#include "secure_enclave_u.h"
#include "sgxwallet_common.h"
#include "third_party/intel/create_enclave.h"
#include "third_party/intel/sgx_detect.h"
#include <dkg/dkg.h>
#include <gmp.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <sgx_tcrypto.h>
#include <sgx_urts.h>
#include <stdio.h>

#include "BLSCrypto.h"
#include "CryptoTools.h"
#include "DKGCrypto.h"
#include "LevelDB.h"
#include "SGXException.h"
#include "SGXWalletServer.hpp"
#include "ServerInit.h"

#define CATCH_CONFIG_MAIN

#include "BLSPublicKey.h"
#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "SEKManager.h"
#include "common.h"
#include "stubclient.h"
#include "third_party/catch.hpp"
#include <thread>

#include "SGXRegistrationServer.h"
#include "SGXWalletServer.h"
#include "TestUtils.h"
#include "secure_enclave/TEUtils.h"
#include "sgxwallet.h"
#include "testw.h"
#include "zmq_src/ZMQClient.h"
#include "zmq_src/ZMQServer.h"
#include <condition_variable>
#include <mutex>

#define PRINT_SRC_LINE cerr << "Executing line " << to_string(__LINE__) << endl;

using namespace jsonrpc;
using namespace std;

/**
 * @brief Sends a curl request with the provided jsonData to the specified url
 * If keyPath and certPath are provided, they are used for the request
 * @return the response as a string
 * @note Needed since current `HttpClient` class does not allow to use
 * self-signed certificates
 */
std::string httpsRequest(const std::string &url, const std::string &jsonData,
                         bool expectedError, const std::string &keyPath = "",
                         const std::string &certPath = "") {
  std::ostringstream command;
  command << "curl -X POST --data '" << jsonData << "' "
          << "-H 'content-type:application/json;' -v ";

  // If keyPath and certPath are provided, add them to the command
  if (!keyPath.empty() && !certPath.empty()) {
    command << "--key " << keyPath << " "
            << "--key " << keyPath << " --cert " << certPath << " ";
  }

  command << url << " -k ";
  if (expectedError) {
    //            vv--redirect stderr to stdout
    command << "2>&1";
  }

  // Open a pipe to read the command's standard output.
  FILE *fp = popen(command.str().c_str(), "r");
  if (fp == nullptr) {
    std::cerr << "Error opening pipe for curl command." << std::endl;
    return "";
  }

  // Read the output of the curl command in chunks.
  constexpr size_t bufferSize = 128;
  char buffer[bufferSize];
  std::string response;
  while (fgets(buffer, bufferSize, fp) != nullptr) {
    response += buffer;
  }

  // Close the pipe.
  pclose(fp);
  return response;
}

/**
 * @brief Check if a string ends with a given suffix
 */
bool endsWith(const std::string &str, const std::string &suffix) {
  if (suffix.size() > str.size())
    return false;
  return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

initConfig makeTestInitConfig(bool useHTTPS, bool checkCert, bool checkZMQSig,
                              bool autoSign, bool checkKeyOwnership,
                              bool enterBackupKey = false) {
  initConfig config;
  config.logLevel = L_INFO;
  config.enclaveLogLevel = L_INFO;
  config.useHTTPS = useHTTPS;
  config.autoconfirm = true;
  config.enterBackupKey = enterBackupKey;
  config.checkCert = checkCert;
  config.checkZMQSig = checkZMQSig;
  config.autoSign = autoSign;
  config.generateTestKeys = false;
  config.checkKeyOwnership = checkKeyOwnership;
  config.threadPoolSize = SGXWalletServer::DEFAULT_NUM_THREADS_SGX;
  return config;
}

// Test Fixtures

class TestFixture {
public:
  TestFixture() {
    TestUtils::resetDB();
    initConfig config = makeTestInitConfig(false, false, false, true, true);

    initAll(config);
  }

  ~TestFixture() { TestUtils::destroyEnclave(); }
};

// initAll is process-static; this fixture keeps the enclave alive across the
// split V3 API tests so grouped tags can run more than one test case.
class TestFixtureDKGV3Api {
public:
  static constexpr int DKG_V3_API_N = 2;
  static constexpr int DKG_V3_API_T = 2;

  TestFixtureDKGV3Api() {
    static once_flag initOnce;

    call_once(initOnce, [] {
      TestUtils::resetDB();

      initConfig config{.logLevel = L_INFO,
                        .autoconfirm = true,
                        .checkCert = false,
                        .checkZMQSig = false,
                        .autoSign = true,
                        .generateTestKeys = false,
                        .checkKeyOwnership = true,
                        .threadPoolSize =
                            SGXWalletServer::DEFAULT_NUM_THREADS_SGX};

      initAll(config);
    });
  }
};

class TestFixtureHTTPS {
public:
  TestFixtureHTTPS() {
    TestUtils::resetDB();
    initConfig config = makeTestInitConfig(true, true, true, true, true);

    initAll(config);
  }

  ~TestFixtureHTTPS() { TestUtils::destroyEnclave(); }

  // Used for all HTTPS requests - simplest request possible
  // Any request would do - this is only used for heatlhchecks &
  // checking for errors on malformed https requests
  static constexpr const char *REQUEST_DATA =
      "{\"jsonrpc\":\"2.0\",\"method\":\"getServerVersion\",\"params\":[],"
      "\"id\":1}";
};

class TestFixtureZMQSign {
public:
  TestFixtureZMQSign() {
    TestUtils::resetDB();
    initConfig config = makeTestInitConfig(false, false, true, true, false);

    initAll(config);
  }

  ~TestFixtureZMQSign() { TestUtils::destroyEnclave(); }
};

class TestFixtureNoResetFromBackup {
public:
  TestFixtureNoResetFromBackup() {
    initConfig config =
        makeTestInitConfig(false, false, false, true, true, true);

    initAll(config);
  }

  ~TestFixtureNoResetFromBackup() {
    sleep(3);
    TestUtils::destroyEnclave();
  }
};

class TestFixtureNoReset {
public:
  TestFixtureNoReset() {
    initConfig config = makeTestInitConfig(false, false, false, true, true);

    initAll(config);
  }

  ~TestFixtureNoReset() { TestUtils::destroyEnclave(); }
};

TEST_CASE_METHOD(TestFixture, "HTTP Healthcheck", "[http-healthcheck]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  REQUIRE(c.getServerVersion()["version"] == SGXWalletServer::getVersion());
  sleep(3);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS Healthcheck", "[https-healthcheck]") {
  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

  string keyFile = "insecure-samples/yourdomain.key";
  string csrFile = "insecure-samples/yourdomain.csr";
  string certFile = "insecure-samples/yourdomain.crt";

  ifstream infile(csrFile);
  infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ostringstream ss;
  ss << infile.rdbuf();
  infile.close();

  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());
  std::string hash = result["hash"].asString();

  result = SGXRegistrationServer::getServer()->GetCertificate(hash);
  std::string cert = result["cert"].asString();

  // Write certificate to file
  std::ofstream out(certFile);
  if (!out) {
    throw std::runtime_error("Failed to open file for writing certificate");
  }
  out << cert;
  out.close();

  // make the request
  bool expectedError = false;
  std::string resp =
      httpsRequest(RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA,
                   expectedError, keyFile, certFile);

  Json::Value json;
  Json::CharReaderBuilder reader;
  std::istringstream iss(resp);
  std::string errs;
  if (!Json::parseFromStream(reader, iss, &json, &errs)) {
    std::cerr << "Failed to parse JSON: " << errs << std::endl;
    throw std::runtime_error("Failed to parse JSON response");
  }

  REQUIRE(json.isObject());
  REQUIRE(json["jsonrpc"] == "2.0");
  REQUIRE(json["id"] == 1);
  REQUIRE(json["result"].isObject());
  REQUIRE(json["result"]["version"].asString() ==
          SGXWalletServer::getVersion());
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS wrong certificate",
                 "[https-wrong-ssl-certificate]") {
  string keyFile = "insecure-samples/yourdomain.key";
  string csrFile = "insecure-samples/yourdomain.csr";
  string certFile = "insecure-samples/yourdomain.crt";

  // signed with wrong key
  std::ostringstream selfSign;
  selfSign << "openssl x509 -req -in " << csrFile << " -signkey " << keyFile
           << " -out " << certFile;
  REQUIRE(system(selfSign.str().c_str()) == 0);

  bool expectedError = true;
  std::string resp =
      httpsRequest(RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA,
                   expectedError, keyFile, certFile);

  REQUIRE(resp.find("curl: (") != std::string::npos);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS without certificate",
                 "[https-without-certificate]") {
  // request with no certificate / key
  bool expectedError = true;
  std::string resp = httpsRequest(
      RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA, expectedError);
  REQUIRE(resp.find("curl: (") != std::string::npos);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "HTTPS certificate not in database",
                 "[https-certificate-not-in-db]") {
  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

  string keyFile = "insecure-samples/yourdomain.key";
  string csrFile = "insecure-samples/yourdomain.csr";
  string certFile = "insecure-samples/yourdomain.crt";

  // sign certificate
  ifstream infile(csrFile);
  infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ostringstream ss;
  ss << infile.rdbuf();
  infile.close();

  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());
  std::string hash = result["hash"].asString();

  result = SGXRegistrationServer::getServer()->GetCertificate(hash);
  std::string cert = result["cert"].asString();

  // Write certificate to file
  std::ofstream out(certFile);
  if (!out) {
    throw std::runtime_error("Failed to open file for writing certificate");
  }
  out << cert;
  out.close();

  // kill enclave
  TestUtils::destroyEnclave();

  // reset db & init enclave again
  TestUtils::resetDB();
  initConfig config = makeTestInitConfig(true, true, true, true, true);

  initAll(config);

  // make the request
  bool expectedError = true;
  std::string resp =
      httpsRequest(RPC_ENDPOINT_HTTPS, TestFixtureHTTPS::REQUEST_DATA,
                   expectedError, keyFile, certFile);
  REQUIRE(resp.find("curl: (") != std::string::npos);
}

/// Functionality tests

TEST_CASE_METHOD(TestFixture, "ECDSA AES keygen and signature test",
                 "[ecdsa-aes-key-sig-gen]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  vector<uint8_t> encrPrivKey(BUF_LEN, 0);
  vector<char> pubKeyX(BUF_LEN, 0);
  vector<char> pubKeyY(BUF_LEN, 0);

  uint64_t encLen = 0;
  int exportable = 0;
  PRINT_SRC_LINE
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
    PRINT_SRC_LINE
    status = trustedEcdsaSign(
        eid, &errStatus, errMsg.data(), encrPrivKey.data(), encLen, hex.data(),
        signatureR.data(), signatureS.data(), &signatureV, 16);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
  }
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES key gen", "[ecdsa-aes-key-gen]") {
  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;
  vector<uint8_t> encrPrivKey(BUF_LEN, 0);
  vector<char> pubKeyX(BUF_LEN, 0);
  vector<char> pubKeyY(BUF_LEN, 0);
  uint64_t encLen = 0;
  int exportable = 0;
  PRINT_SRC_LINE
  auto status = trustedGenerateEcdsaKey(
      eid, &errStatus, errMsg.data(), &exportable, encrPrivKey.data(), &encLen,
      pubKeyX.data(), pubKeyY.data());

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES get public key",
                 "[ecdsa-aes-get-pub-key]") {
  int errStatus = 0;
  vector<char> errMsg(BUF_LEN, 0);
  vector<uint8_t> encPrivKey(BUF_LEN, 0);
  vector<char> pubKeyX(BUF_LEN, 0);
  vector<char> pubKeyY(BUF_LEN, 0);

  uint64_t encLen = 0;
  int exportable = 0;

  PRINT_SRC_LINE
  auto status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(),
                                        &exportable, encPrivKey.data(), &encLen,
                                        pubKeyX.data(), pubKeyY.data());

  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);

  vector<char> receivedPubKeyX(BUF_LEN, 0);
  vector<char> receivedPubKeyY(BUF_LEN, 0);

  PRINT_SRC_LINE
  status = trustedGetPublicEcdsaKey(
      eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen,
      receivedPubKeyX.data(), receivedPubKeyY.data());
  REQUIRE(status == SGX_SUCCESS);
  REQUIRE(errStatus == SGX_SUCCESS);
}

/* Do later
TEST_CASE_METHOD("BLS key encrypt/decrypt", "[bls-key-encrypt-decrypt]") {
    resetDB();
    initConfig config = makeTestInitConfig(false, false, false, true, true);
    initAll(config);

    //init_enclave();

    int errStatus = -1;

    vector<char> errMsg(BUF_LEN, 0);

    char *encryptedKey = TestUtils::encryptTestKey();
    REQUIRE(encryptedKey != nullptr);
    char *plaintextKey = decryptBLSKeyShareFromHex(&errStatus, errMsg.data(),
encryptedKey); free(encryptedKey);

    REQUIRE(errStatus == 0);
    REQUIRE(strcmp(plaintextKey, TEST_BLS_KEY_SHARE) == 0);

    printf("Decrypt key completed with status: %d %s \n", errStatus,
errMsg.data()); printf("Decrypted key len %d\n", (int) strlen(plaintextKey));
    printf("Decrypted key: %s\n", plaintextKey);
    free(plaintextKey);
}
*/

string genECDSAKeyAPI(StubClient &_c) {
  Json::Value genKey = _c.generateECDSAKey();
  CHECK_STATE(genKey["status"].asInt() == 0);
  auto keyName = genKey["keyName"].asString();
  CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);
  return keyName;
}

TEST_CASE_METHOD(TestFixture, "ECDSA key gen API", "[ecdsa-key-gen-api]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  for (int i = 0; i <= 20; i++) {
    try {
      PRINT_SRC_LINE
      auto keyName = genECDSAKeyAPI(c);
      PRINT_SRC_LINE
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
      PRINT_SRC_LINE
      auto keyName = genECDSAKeyAPI(c);
      PRINT_SRC_LINE
      Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);
      REQUIRE(sig["status"].asInt() == 0);
      PRINT_SRC_LINE
      Json::Value getPubKey = c.getPublicECDSAKey(keyName);
      REQUIRE(getPubKey["status"].asInt() == 0);
    } catch (JsonRpcException &e) {
      cerr << e.what() << endl;
      throw;
    }
  }
}

TEST_CASE_METHOD(TestFixture, "BLS key encrypt", "[bls-key-encrypt]") {
  auto key = TestUtils::encryptTestKey();
  REQUIRE(key);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "DKG AES gen test", "[dkg-aes-gen]") {
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
                 "[dkg-aes-pub-shares]") {
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

    pubSharesG2.push_back(TestUtils::vectStringToG2(coeffStr));
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
      TestUtils::splitStringToFr(secret.data(), colon);
  vector<libBLS::algebra::G2Point> pubSharesDkg =
      dkgObj.VerificationVector(poly);
  REQUIRE(pubSharesG2 == pubSharesDkg);
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares test",
                 "[dkg-aes-encr-sshares]") {
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
                 "[dkg-aes-encr-sshares-v2]") {
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
                 "[dkg-aes-gen-v3]") {
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
      TestUtils::splitStringToFr(decryptedDKGSecret.data(), ':');
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

TEST_CASE_METHOD(TestFixture, "DKG AES V3 create BLS key",
                 "[dkg-aes-create-bls-v3]") {
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

TEST_CASE_METHOD(TestFixture, "DKG_BLS test", "[dkg-bls]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  vector<string> ecdsaKeyNames;
  vector<string> blsKeyNames;

  int schainID = TestUtils::randGen();
  int dkgID = TestUtils::randGen();

  PRINT_SRC_LINE
  TestUtils::doDKG(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

  REQUIRE(blsKeyNames.size() == 4);

  schainID = TestUtils::randGen();
  dkgID = TestUtils::randGen();

  TestUtils::doDKG(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 test", "[dkg-bls-v2]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  vector<string> ecdsaKeyNames;
  vector<string> blsKeyNames;

  int schainID = TestUtils::randGen();
  int dkgID = TestUtils::randGen();

  PRINT_SRC_LINE
  TestUtils::doDKGV2(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

  REQUIRE(blsKeyNames.size() == 4);

  schainID = TestUtils::randGen();
  dkgID = TestUtils::randGen();

  TestUtils::doDKGV2(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 to V3 rotation correctness",
                 "[dkg-bls-v2-v3-rotation]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int schainID = TestUtils::randGen();
  int dkgV2ID = TestUtils::randGen();
  int dkgV3ID = dkgV2ID + 1;

  PRINT_SRC_LINE
  TestUtils::doDKGV3Rotation(c, 5, 3, schainID, dkgV2ID, dkgV3ID, 50, 3);

  schainID = TestUtils::randGen();
  dkgV2ID = TestUtils::randGen();
  dkgV3ID = dkgV2ID + 1;

  TestUtils::doDKGV3Rotation(c, 16, 5, schainID, dkgV2ID, dkgV3ID, 1, 1);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 to V3 rotation with joining nodes",
                 "[dkg-bls-v2-v3-rotation-new-nodes]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int schainID = TestUtils::randGen();
  int dkgV2ID = TestUtils::randGen();
  int dkgV3ID = dkgV2ID + 1;

  PRINT_SRC_LINE
  TestUtils::doDKGV3RotationWithNewNodes(c, 4, 4, 3, 1, schainID, dkgV2ID,
                                         dkgV3ID, 1);

  schainID = TestUtils::randGen();
  dkgV2ID = TestUtils::randGen();
  dkgV3ID = dkgV2ID + 1;

  TestUtils::doDKGV3RotationWithNewNodes(c, 10, 10, 7, 6, schainID, dkgV2ID,
                                         dkgV3ID, 1);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 to V3 rotation security",
                 "[dkg-bls-v2-v3-rotation-security]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int schainID = TestUtils::randGen();
  int dkgV2ID = TestUtils::randGen();
  int dkgV3ID = dkgV2ID + 1;

  PRINT_SRC_LINE

  // Case 1: Rotate a threshold of nodes - the nodes rotated out should be able
  // to decrypt together
  TestUtils::doDKGV3UnsafeRotatedNodesCanDecrypt(c, 10, 7, 7, schainID, dkgV2ID,
                                                 dkgV3ID);

  schainID = TestUtils::randGen();
  dkgV2ID = TestUtils::randGen();
  dkgV3ID = dkgV2ID + 1;
  int dkgV4ID = dkgV2ID + 2;

  // Case 2: Do 2 successive rotations, each rotating out number of nodes < t
  // If all nodes join such that number of nodes > t, they should still not be
  // able to decrypt
  TestUtils::doDKGV3CrossEpochRetiredNodesCannotCollude(
      c, 10, 7, 4, 4, schainID, dkgV2ID, dkgV3ID, dkgV4ID);

  // Case 3: Test boundary conditions varying number of faulty nodes.
  auto runScenario = [&](int n, int t, int rotatedCount, int nonRespondingCount,
                         bool shouldDecrypt) {
    int schainID = TestUtils::randGen();
    int dkgV2ID = TestUtils::randGen();
    int dkgV3ID = dkgV2ID + 1;

    TestUtils::doDKGV3RotationWithNonRespondingNodes(
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

TEST_CASE_METHOD(TestFixture, "DKG_BLS ZMQ test", "[dkgblszmq]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  string ip = ZMQ_IP;

  string empty = "";
  auto zmqClient = make_shared<ZMQClient>(ip, ZMQ_PORT, false, empty, empty);

  vector<string> ecdsaKeyNames;
  vector<string> blsKeyNames;

  int schainID = TestUtils::randGen();
  int dkgID = TestUtils::randGen();

  PRINT_SRC_LINE
  TestUtils::doZMQBLS(zmqClient, c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID,
                      dkgID);
  REQUIRE(blsKeyNames.size() == 4);
  schainID = TestUtils::randGen();
  dkgID = TestUtils::randGen();
  TestUtils::doZMQBLS(zmqClient, c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID,
                      dkgID);
}

TEST_CASE_METHOD(TestFixture, "Delete Bls Key", "[delete-bls-key]") {
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

TEST_CASE_METHOD(TestFixture, "Delete Bls Key Zmq", "[delete-bls-key-zmq]") {
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

TEST_CASE_METHOD(TestFixture, "Import ECDSA Key", "[import-ecdsa-key]") {
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
                 "[import-ecdsa-key-zmq]") {
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

TEST_CASE_METHOD(TestFixture, "Backup Key", "[backup-key]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  std::ifstream sek_file("sgx_data/sgxwallet_backup_key.txt");
  REQUIRE(sek_file.good());

  std::string sek;
  sek_file >> sek;

  REQUIRE(sek.size() == 32);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerStatus", "[get-server-status]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  REQUIRE(c.getServerStatus()["status"] == 0);
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerStatusZmq",
                 "[get-server-status-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");
  REQUIRE_NOTHROW(client->getServerStatus());
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerVersion", "[get-server-version]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  REQUIRE(c.getServerVersion()["version"] == SGXWalletServer::getVersion());
  sleep(3);
}

TEST_CASE_METHOD(TestFixture, "Get ServerVersionZmq",
                 "[get-server-version-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");
  REQUIRE(client->getServerVersion() == SGXWalletServer::getVersion());
  sleep(3);
}

TEST_CASE_METHOD(TestFixtureHTTPS, "Cert request sign", "[cert-sign]") {

  PRINT_SRC_LINE

  REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

  PRINT_SRC_LINE

  string csrFile = "insecure-samples/yourdomain.csr";

  ifstream infile(csrFile);
  infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
  ostringstream ss;
  ss << infile.rdbuf();
  infile.close();

  PRINT_SRC_LINE

  auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());

  REQUIRE(result["status"] == 0);

  PRINT_SRC_LINE
  result = SGXRegistrationServer::getServer()->SignCertificate("Haha");

  REQUIRE(result["status"] != 0);
}

TEST_CASE_METHOD(TestFixture, "DKG API V2 test", "[dkg-api-v2]") {
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

TEST_CASE_METHOD(TestFixture, "DKG API V2 ZMQ test", "[dkg-api-v2-zmq]") {
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
                 "[dkg-api-v3][dkg-api-v3-generate-poly]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  const int schainID = TestUtils::randGen();
  const int dkgV2ID = TestUtils::randGen();
  const int dkgV3ID = TestUtils::randGen();

  const string previousBlsKeyName =
      TestUtils::makeBLSKeyName(schainID, 0, dkgV2ID);
  Json::Value previousBlsKey = c.generateBLSPrivateKey(previousBlsKeyName);
  REQUIRE(previousBlsKey["status"].asInt() == 0);

  const string polyName = TestUtils::makeDKGPolyName(schainID, 0, dkgV3ID);
  Json::Value genPoly =
      c.generateDKGPolyV3(polyName, previousBlsKeyName, DKG_V3_API_T);
  REQUIRE(genPoly["status"].asInt() == 0);

  Json::Value verificationVector =
      c.getVerificationVector(polyName, DKG_V3_API_T);
  REQUIRE(verificationVector["status"].asInt() == 0);
  REQUIRE(!TestUtils::publicSharesFromVerificationVector(verificationVector,
                                                         DKG_V3_API_T)
               .empty());

  Json::Value genPolyWrongName =
      c.generateDKGPolyV3("poly", previousBlsKeyName, DKG_V3_API_T);
  REQUIRE(genPolyWrongName["status"].asInt() != 0);

  Json::Value genPolyWrongPreviousBls = c.generateDKGPolyV3(
      TestUtils::makeDKGPolyName(schainID, 1, dkgV3ID), "bls", DKG_V3_API_T);
  REQUIRE(genPolyWrongPreviousBls["status"].asInt() != 0);

  Json::Value genPolyWrongT = c.generateDKGPolyV3(
      TestUtils::makeDKGPolyName(schainID, 2, dkgV3ID), previousBlsKeyName, 33);
  REQUIRE(genPolyWrongT["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixtureDKGV3Api, "DKG V3 JSONRPC API creates BLS key",
                 "[dkg-api-v3][dkg-api-v3-create-bls]") {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  const int schainID = TestUtils::randGen();
  const int dkgV2ID = TestUtils::randGen();
  const int dkgV3ID = TestUtils::randGen();

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

    previousBlsKeyNames[i] = TestUtils::makeBLSKeyName(schainID, i, dkgV2ID);
    Json::Value previousBlsKey =
        c.generateBLSPrivateKey(previousBlsKeyNames[i]);
    REQUIRE(previousBlsKey["status"].asInt() == 0);

    polyNames[i] = TestUtils::makeDKGPolyName(schainID, i, dkgV3ID);
    Json::Value genPoly =
        c.generateDKGPolyV3(polyNames[i], previousBlsKeyNames[i], DKG_V3_API_T);
    REQUIRE(genPoly["status"].asInt() == 0);

    Json::Value verificationVector =
        c.getVerificationVector(polyNames[i], DKG_V3_API_T);
    REQUIRE(verificationVector["status"].asInt() == 0);
    publicShares[i] = TestUtils::publicSharesFromVerificationVector(
        verificationVector, DKG_V3_API_T);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    Json::Value secretShares = c.getSecretShareV2(
        polyNames[contributor], publicEcdsaKeys, DKG_V3_API_T, DKG_V3_API_N);
    REQUIRE(secretShares["status"].asInt() == 0);
    dealerSecretShares[contributor] = secretShares["secretShare"].asString();
    REQUIRE(dealerSecretShares[contributor].length() ==
            static_cast<size_t>(DKG_V3_API_N) *
                TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    for (int recipient = 0; recipient < DKG_V3_API_N; ++recipient) {
      const string contribution =
          TestUtils::encryptedDkgSecretContributionForRecipient(
              dealerSecretShares[contributor], recipient);
      Json::Value verification = c.dkgVerificationV2(
          publicShares[contributor], ecdsaKeyNames[recipient], contribution,
          DKG_V3_API_T, DKG_V3_API_N, recipient);
      REQUIRE(verification["status"].asInt() == 0);
      REQUIRE(verification["result"].asBool());
    }
  }

  Json::Value firstRecipientContributions =
      TestUtils::dkgV3SecretContributionsForRecipient(dealerSecretShares, 0);
  const string firstBlsKeyName =
      TestUtils::makeBLSKeyName(schainID, 0, dkgV3ID);
  Json::Value createFirst = c.createBLSPrivateKeyV3(
      firstBlsKeyName, ecdsaKeyNames[0], polyNames[0],
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createFirst["status"].asInt() == 0);

  Json::Value firstPublicKey = c.getBLSPublicKeyShare(firstBlsKeyName);
  REQUIRE(firstPublicKey["status"].asInt() == 0);
  REQUIRE(firstPublicKey["blsPublicKeyShare"].isArray());

  Json::Value secondRecipientContributions =
      TestUtils::dkgV3SecretContributionsForRecipient(dealerSecretShares, 1);
  const string secondBlsKeyName =
      TestUtils::makeBLSKeyName(schainID, 1, dkgV3ID);
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
      TestUtils::makeBLSKeyName(schainID, 2, dkgV3ID), "eth", "",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createWrongEcdsaName["status"].asInt() != 0);

  Json::Value createWrongPolyName = c.createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 3, dkgV3ID), ecdsaKeyNames[0], "poly",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createWrongPolyName["status"].asInt() != 0);

  Json::Value malformedContributions(Json::objectValue);
  Json::Value createMalformedContributions = c.createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 4, dkgV3ID), ecdsaKeyNames[0], "",
      malformedContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createMalformedContributions["status"].asInt() != 0);

  Json::Value tooFewContributions(Json::arrayValue);
  tooFewContributions.append(firstRecipientContributions[0]);
  Json::Value createTooFewContributions = c.createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 5, dkgV3ID), ecdsaKeyNames[0], "",
      tooFewContributions, DKG_V3_API_T, DKG_V3_API_N);
  REQUIRE(createTooFewContributions["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixtureDKGV3Api, "DKG V3 ZMQ API generates DKG polynomial",
                 "[dkg-api-v3-zmq][dkg-api-v3-zmq-generate-poly]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  const int schainID = TestUtils::randGen();
  const int dkgV2ID = TestUtils::randGen();
  const int dkgV3ID = TestUtils::randGen();

  const string previousBlsKeyName =
      TestUtils::makeBLSKeyName(schainID, 0, dkgV2ID);
  REQUIRE(client->generateBLSPrivateKey(previousBlsKeyName));

  const string polyName = TestUtils::makeDKGPolyName(schainID, 0, dkgV3ID);
  REQUIRE(
      client->generateDKGPolyV3(polyName, previousBlsKeyName, DKG_V3_API_T));

  Json::Value verificationVector =
      client->getVerificationVector(polyName, DKG_V3_API_T);
  REQUIRE(!TestUtils::publicSharesFromVerificationVector(verificationVector,
                                                         DKG_V3_API_T)
               .empty());

  REQUIRE(!client->generateDKGPolyV3("poly", previousBlsKeyName, DKG_V3_API_T));
  REQUIRE_THROWS(client->generateDKGPolyV3(
      TestUtils::makeDKGPolyName(schainID, 1, dkgV3ID), "bls", DKG_V3_API_T));
  REQUIRE(!client->generateDKGPolyV3(
      TestUtils::makeDKGPolyName(schainID, 2, dkgV3ID), previousBlsKeyName,
      33));
}

TEST_CASE_METHOD(TestFixtureDKGV3Api, "DKG V3 ZMQ API creates BLS key",
                 "[dkg-api-v3-zmq][dkg-api-v3-zmq-create-bls]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  const int schainID = TestUtils::randGen();
  const int dkgV2ID = TestUtils::randGen();
  const int dkgV3ID = TestUtils::randGen();

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
    previousBlsKeyNames[i] = TestUtils::makeBLSKeyName(schainID, i, dkgV2ID);
    REQUIRE(client->generateBLSPrivateKey(previousBlsKeyNames[i]));

    // generate poly using previous DKG key
    polyNames[i] = TestUtils::makeDKGPolyName(schainID, i, dkgV3ID);
    REQUIRE(client->generateDKGPolyV3(polyNames[i], previousBlsKeyNames[i],
                                      DKG_V3_API_T));

    Json::Value verificationVector =
        client->getVerificationVector(polyNames[i], DKG_V3_API_T);
    publicShares[i] = TestUtils::publicSharesFromVerificationVector(
        verificationVector, DKG_V3_API_T);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    dealerSecretShares[contributor] = client->getSecretShare(
        polyNames[contributor], publicEcdsaKeys, DKG_V3_API_T, DKG_V3_API_N);
    REQUIRE(dealerSecretShares[contributor].length() ==
            static_cast<size_t>(DKG_V3_API_N) *
                TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);
  }

  for (int contributor = 0; contributor < DKG_V3_API_N; ++contributor) {
    for (int recipient = 0; recipient < DKG_V3_API_N; ++recipient) {
      const string contribution =
          TestUtils::encryptedDkgSecretContributionForRecipient(
              dealerSecretShares[contributor], recipient);
      REQUIRE(client->dkgVerification(publicShares[contributor],
                                      ecdsaKeyNames[recipient], contribution,
                                      DKG_V3_API_T, DKG_V3_API_N, recipient));
    }
  }

  Json::Value firstRecipientContributions =
      TestUtils::dkgV3SecretContributionsForRecipient(dealerSecretShares, 0);
  const string firstBlsKeyName =
      TestUtils::makeBLSKeyName(schainID, 0, dkgV3ID);
  REQUIRE(client->createBLSPrivateKeyV3(
      firstBlsKeyName, ecdsaKeyNames[0], polyNames[0],
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N));

  Json::Value firstPublicKey = client->getBLSPublicKey(firstBlsKeyName);
  REQUIRE(firstPublicKey.isArray());

  Json::Value secondRecipientContributions =
      TestUtils::dkgV3SecretContributionsForRecipient(dealerSecretShares, 1);
  const string secondBlsKeyName =
      TestUtils::makeBLSKeyName(schainID, 1, dkgV3ID);
  REQUIRE(client->createBLSPrivateKeyV3(secondBlsKeyName, ecdsaKeyNames[1], "",
                                        secondRecipientContributions,
                                        DKG_V3_API_T, DKG_V3_API_N));

  Json::Value secondPublicKey = client->getBLSPublicKey(secondBlsKeyName);
  REQUIRE(secondPublicKey.isArray());

  REQUIRE(!client->createBLSPrivateKeyV3("bls", ecdsaKeyNames[0], "",
                                         firstRecipientContributions,
                                         DKG_V3_API_T, DKG_V3_API_N));

  REQUIRE_THROWS(client->createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 2, dkgV3ID), "eth", "",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N));

  REQUIRE_THROWS(client->createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 3, dkgV3ID), ecdsaKeyNames[0], "poly",
      firstRecipientContributions, DKG_V3_API_T, DKG_V3_API_N));

  Json::Value malformedContributions(Json::objectValue);
  REQUIRE(!client->createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 4, dkgV3ID), ecdsaKeyNames[0], "",
      malformedContributions, DKG_V3_API_T, DKG_V3_API_N));

  Json::Value tooFewContributions(Json::arrayValue);
  tooFewContributions.append(firstRecipientContributions[0]);
  REQUIRE(!client->createBLSPrivateKeyV3(
      TestUtils::makeBLSKeyName(schainID, 5, dkgV3ID), ecdsaKeyNames[0], "",
      tooFewContributions, DKG_V3_API_T, DKG_V3_API_N));
}

TEST_CASE_METHOD(TestFixture, "PolyExists test", "[dkg-poly-exists]") {
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

TEST_CASE_METHOD(TestFixture, "PolyExistsZmq test", "[dkg-poly-exists-zmq]") {
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

TEST_CASE_METHOD(TestFixture, "AES_DKG V2 test", "[aes-dkg-v2]") {
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

  int schainID = TestUtils::randGen();
  int dkgID = TestUtils::randGen();
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
        pubShares[i] += TestUtils::convertDecToHex(pubShare);
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
  REQUIRE(sessionKeyRecoverDH(dhKey.c_str(), encr_sshare, common_key) == 0);

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

  REQUIRE(xorDecryptDHV2(derived_key, encr_sshare_check, message) == 0);

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

TEST_CASE_METHOD(TestFixture, "AES_DKG V2 ZMQ test", "[aes-dkg-v2-zmq]") {
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

  int schainID = TestUtils::randGen();
  int dkgID = TestUtils::randGen();
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
        pubShares[i] += TestUtils::convertDecToHex(pubShare);
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
  REQUIRE(sessionKeyRecoverDH(dhKey.c_str(), encr_sshare, common_key) == 0);

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

  REQUIRE(xorDecryptDHV2(derived_key, encr_sshare_check, message) == 0);

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

TEST_CASE_METHOD(TestFixture, "AES encrypt/decrypt", "[aes-encrypt-decrypt]") {
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
                 "[exportable-nonexportable-keys]") {
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

TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg v2 bls",
                 "[many-threads-crypto-v2]") {
  vector<thread> threads;
  int num_threads = 4;
  for (int i = 0; i < num_threads; i++) {
    threads.push_back(thread(TestUtils::sendRPCRequestV2));
  }

  for (auto &thread : threads) {
    thread.join();
  }
}

TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg v2 bls zmq",
                 "[many-threads-crypto-v2-zmq]") {
  vector<thread> threads;
  int num_threads = 4;
  for (int i = 0; i < num_threads; i++) {
    threads.push_back(thread(TestUtils::sendRPCRequestZMQ));
  }

  for (auto &thread : threads) {
    thread.join();
  }
}

TEST_CASE_METHOD(TestFixture, "First run", "[first-run]") {

  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  try {
    PRINT_SRC_LINE
    auto keyName = genECDSAKeyAPI(c);
    ofstream namefile("/tmp/keyname");
    namefile << keyName;

    PRINT_SRC_LINE
  } catch (JsonRpcException &e) {
    cerr << e.what() << endl;
    throw;
  }

  sleep(3);
}

TEST_CASE_METHOD(TestFixtureNoReset, "Second run", "[second-run]") {

  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);
  try {
    PRINT_SRC_LINE
    string keyName;
    ifstream namefile("/tmp/keyname");
    getline(namefile, keyName);

    Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
    REQUIRE(sig["status"].asInt() == 0);
    Json::Value getPubKey = c.getPublicECDSAKey(keyName);
    REQUIRE(getPubKey["status"].asInt() == 0);
  } catch (JsonRpcException &e) {
    cerr << e.what() << endl;
    throw;
  }
}

const std::vector<int> BATCH_TEST_VALUES = {
    1,
    ENCLAVE_MAX_CIPHERTEXT_BATCH / 2,
    ENCLAVE_MAX_CIPHERTEXT_BATCH - 1,
    ENCLAVE_MAX_CIPHERTEXT_BATCH,
    ENCLAVE_MAX_CIPHERTEXT_BATCH + 1,
    ENCLAVE_MAX_CIPHERTEXT_BATCH + ENCLAVE_MAX_CIPHERTEXT_BATCH / 2,
    2 * ENCLAVE_MAX_CIPHERTEXT_BATCH,
    3 * ENCLAVE_MAX_CIPHERTEXT_BATCH};

TEST_CASE_METHOD(TestFixture,
                 "Test decryption share for empty threshold encryption",
                 "[te-empty-decryption-share]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"] = Json::arrayValue;
  auto decryptionShares = c.getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  REQUIRE(decryptionShares["decryptionShares"].empty());
}

TEST_CASE_METHOD(TestFixture, "Test decryption share for threshold encryption",
                 "[te-decryption-share]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  // the same key writtn in decimal
  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC);

  for (int num_requests : BATCH_TEST_VALUES) {
    Json::Value publicDecryptionValues;

    std::vector<libBLS::algebra::G2Point> decryption_values;
    for (int i = 0; i < num_requests; i++) {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      decryption_values.push_back(decryption_value);
      auto decrytion_value_str =
          decryption_value.toString(libBLS::algebra::Base::HEXA);
      publicDecryptionValues["publicDecryptionValues"][i] = decrytion_value_str;
    }

    auto decryptionShares = c.getDecryptionShares(name, publicDecryptionValues);

    REQUIRE(decryptionShares.isObject());
    // should have no failed requests
    REQUIRE(!decryptionShares.isMember("failedRequests"));

    for (int i = 0; i < num_requests; i++) {
      auto decryption_share =
          decryptionShares["decryptionShares"][i].asString();
      libBLS::algebra::G2Point share = libBLS::algebra::G2Point::fromString(
          decryption_share, libBLS::algebra::Base::HEXA);
      REQUIRE(share == key * decryption_values[i]);
    }
  }
}

TEST_CASE_METHOD(TestFixture, "Test decryption share for faulty shares",
                 "[te-decryption-share-error]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"][0] =
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000";
  auto decryptionShares = c.getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  // response should also be all 0's
  REQUIRE(decryptionShares["decryptionShares"][0] ==
          publicDecryptionValues["publicDecryptionValues"][0]);

  // check for failed requests status code
  REQUIRE(decryptionShares.isMember("failedRequests"));
  REQUIRE(decryptionShares["failedRequests"].isObject());
  REQUIRE(decryptionShares["failedRequests"].isMember("0"));
  REQUIRE(decryptionShares["failedRequests"]["0"].isInt());
  REQUIRE(decryptionShares["failedRequests"]["0"].asInt() ==
          STATUS_G2_NOT_WELL_FORMED);
}

TEST_CASE_METHOD(TestFixture,
                 "Test decryption share for empty threshold encryption via zmq",
                 "[te-empty-decryption-share-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  client->importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues(Json::objectValue);
  publicDecryptionValues["publicDecryptionValues"] = Json::arrayValue;
  Json::Value decryptionShares =
      client->getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  REQUIRE(decryptionShares["decryptionShares"].empty());
}

TEST_CASE_METHOD(TestFixture, "Test decryption share for faulty shares via zmq",
                 "[te-decryption-share-error-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  client->importBLSKeyShare(key_str, name);

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"][0] =
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000";
  auto decryptionShares =
      client->getDecryptionShares(name, publicDecryptionValues);

  REQUIRE(decryptionShares.isObject());
  REQUIRE(decryptionShares.isMember("decryptionShares"));
  REQUIRE(decryptionShares["decryptionShares"].isArray());
  // response should also be all 0's
  REQUIRE(decryptionShares["decryptionShares"][0] ==
          publicDecryptionValues["publicDecryptionValues"][0]);

  // check for failed requests status code
  REQUIRE(decryptionShares.isMember("failedRequests"));
  REQUIRE(decryptionShares["failedRequests"].isObject());
  REQUIRE(decryptionShares["failedRequests"].isMember("0"));
  REQUIRE(decryptionShares["failedRequests"]["0"].isInt());
  REQUIRE(decryptionShares["failedRequests"]["0"].asInt() ==
          STATUS_G2_NOT_WELL_FORMED);
}

TEST_CASE_METHOD(TestFixture,
                 "Test decryption share for threshold encryption via zmq",
                 "[te-decryption-share-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  client->importBLSKeyShare(key_str, name);

  // the same key writtn in decimal
  libBLS::algebra::FrScalar key = libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC);

  for (int num_requests : BATCH_TEST_VALUES) {
    Json::Value publicDecryptionValues;

    std::vector<libBLS::algebra::G2Point> decryption_values;
    for (int i = 0; i < num_requests; i++) {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      decryption_values.push_back(decryption_value);
      decryption_value.toAffineCoordinates();
      auto decrytion_value_str =
          decryption_value.toString(libBLS::algebra::Base::HEXA);
      publicDecryptionValues["publicDecryptionValues"][i] = decrytion_value_str;
    }

    auto decryptionShares =
        client->getDecryptionShares(name, publicDecryptionValues);

    REQUIRE(decryptionShares.isObject());
    // should have no failed requests
    REQUIRE(!decryptionShares.isMember("failedRequests"));

    for (int i = 0; i < num_requests; i++) {
      auto decryption_share =
          decryptionShares["decryptionShares"][i].asString();
      libBLS::algebra::G2Point share = libBLS::algebra::G2Point::fromString(
          decryption_share, libBLS::algebra::Base::HEXA);
      REQUIRE(share == key * decryption_values[i]);
    }
  }
}

TEST_CASE_METHOD(TestFixture,
                 "Test 15 concurrent decryption share calls via zmq",
                 "[te-load-test-decryption-share-zmq]") {
  // Root client for key import (server-side state); do this once.
  auto rootClient = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, /*verify=*/true,
                                           "./sgx_data/cert_data/rootCA.pem",
                                           "./sgx_data/cert_data/rootCA.key");

  const std::string key_hex =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  const std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  rootClient->importBLSKeyShare(key_hex, name);

  // Same key in decimal (G2 * Fr verification)
  const libBLS::algebra::FrScalar key(libBLS::algebra::FrScalar::fromString(
      "6507625568967977077291849236396320012317305261598035"
      "438182864059942098934847",
      libBLS::algebra::Base::DEC));

  // For each configured batch size, launch 15 concurrent requests
  for (int num_requests : BATCH_TEST_VALUES) {
    // Ensure small-ish test to keep it lightweight; adjust or remove if
    // unneeded.
    REQUIRE(num_requests > 0);

    constexpr int kNumThreads = 22;
    TestUtils::start_barrier start_gate(kNumThreads);
    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    std::mutex first_exc_m;
    std::exception_ptr first_exc = nullptr;

    for (int t = 0; t < kNumThreads; ++t) {
      threads.emplace_back([&, t]() {
        try {
          // Per-thread client (ZMQ socket/thread safety)
          auto client =
              std::make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, /*verify=*/true,
                                          "./sgx_data/cert_data/rootCA.pem",
                                          "./sgx_data/cert_data/rootCA.key");

          // Build thread-local inputs
          Json::Value publicDecryptionValues;
          std::vector<libBLS::algebra::G2Point> decryption_values;
          decryption_values.reserve(num_requests);

          for (int i = 0; i < num_requests; ++i) {
            libBLS::algebra::G2Point g = libBLS::algebra::G2Point::random();
            decryption_values.push_back(g);
            auto g_str = g.toString(libBLS::algebra::Base::HEXA);
            publicDecryptionValues["publicDecryptionValues"][i] = g_str;
          }

          // Synchronize start so all 22 hit the server together
          start_gate.wait();
          // Request + validate
          auto decryptionShares =
              client->getDecryptionShares(name, publicDecryptionValues);

          // Basic shape checks
          REQUIRE(decryptionShares.isObject());
          REQUIRE(!decryptionShares.isMember("failedRequests"));
          REQUIRE(decryptionShares.isMember("decryptionShares"));
          REQUIRE(decryptionShares["decryptionShares"].isArray());
          REQUIRE(
              static_cast<int>(decryptionShares["decryptionShares"].size()) ==
              num_requests);

          // Verify each share: share == key * G2_i
          for (int i = 0; i < num_requests; ++i) {
            const auto share_hex =
                decryptionShares["decryptionShares"][i].asString();
            libBLS::algebra::G2Point share =
                libBLS::algebra::G2Point::fromString(
                    share_hex, libBLS::algebra::Base::HEXA);
            REQUIRE(share == key * decryption_values[i]);
          }
        } catch (...) {
          // Capture first exception for clean failure after joins
          std::lock_guard<std::mutex> lk(first_exc_m);
          if (!first_exc)
            first_exc = std::current_exception();
        }
      });
    }

    // Join all workers
    for (auto &th : threads)
      th.join();

    // Surface any error observed in threads
    if (first_exc)
      std::rethrow_exception(first_exc);
  }
}

// create random 64-character hexadecimal string
std::string generateHexString(size_t length) {
  const char hexChars[] = "0123456789ABCDEF";
  std::string hexString;
  hexString.reserve(64);

  std::srand(std::time(nullptr));

  for (size_t i = 0; i < length; ++i) {
    hexString += hexChars[std::rand() % 16];
  }

  return hexString;
}

TEST_CASE_METHOD(TestFixture, "Test decryption share with wrong ciphertext",
                 "[te-decryption-share-wrong-inputs]") {
  HttpClient client(RPC_ENDPOINT);
  client.SetTimeout(5000);
  StubClient c(client, JSONRPC_CLIENT_V2);

  std::string key_str =
      "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  c.importBLSKeyShare(key_str, name);

  // Invalid bls key name
  Json::Value publicDecryptionValues;
  REQUIRE_THROWS(c.getDecryptionShares(
      "BLS_KY:SCHAI_ID:123456789:NOD_ID:0:DG_I:0", publicDecryptionValues));

  // invalid decryption shares format
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  publicDecryptionValues[0] = "invalid";
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  // share has wrong size
  publicDecryptionValues.clear();

  publicDecryptionValues[0] =
      generateHexString(CIPHERTEXT_CHARACTER_LENGTH - 1);
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  publicDecryptionValues[0] =
      generateHexString(CIPHERTEXT_CHARACTER_LENGTH + 1);
  REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));

  // share is not in hexadecimal format
  for (int i = 0; i < CIPHERTEXT_CHARACTER_LENGTH; i++) {
    std::string value = generateHexString(CIPHERTEXT_CHARACTER_LENGTH);
    value[i] = 'G';
    publicDecryptionValues[0] = value;
    REQUIRE_THROWS(c.getDecryptionShares(name, publicDecryptionValues));
  }

  // share is not well formed
  std::string zeroG2String =
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000";
  libBLS::algebra::G2Point invalid_g2;
  invalid_g2.setZC0(libBLS::algebra::FqElement::zero());
  invalid_g2.setZC1(libBLS::algebra::FqElement::zero());
  invalid_g2.setXC0(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.setXC1(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.setYC0(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.setYC1(
      libBLS::algebra::FqElement::fromString("1", libBLS::algebra::Base::DEC));
  invalid_g2.toAffineCoordinates();

  Json::Value decriptionValues;
  std::string value;
  std::vector<int> corruptedIdx;

  // tamper random requests at random indices
  for (int i = 0; i < 50; i++) {
    int random = rand() % 3 + 1;
    if (i % random == 1) {
      // corrupted
      value = invalid_g2.toString(libBLS::algebra::Base::HEXA);
      corruptedIdx.push_back(i);
    } else {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      value = decryption_value.toString(libBLS::algebra::Base::HEXA);
    }
    decriptionValues["publicDecryptionValues"][i] = value;
  }

  Json::Value resp = c.getDecryptionShares(name, decriptionValues);

  REQUIRE(resp["failedRequests"].size() == corruptedIdx.size());

  for (size_t i = 0; i < corruptedIdx.size(); i++) {
    std::string decryptionShares =
        resp["decryptionShares"][corruptedIdx[i]].asString();
    REQUIRE(decryptionShares == zeroG2String);
    int idx = corruptedIdx[i];
    std::string corruptedIdxStr = std::to_string(idx);
    REQUIRE(resp["failedRequests"][corruptedIdxStr] ==
            STATUS_G2_NOT_WELL_FORMED);
  }

  // share is zero
  invalid_g2 = libBLS::algebra::G2Point::identity();
  invalid_g2.toAffineCoordinates();

  // clear from previous test
  corruptedIdx.clear();
  decriptionValues.clear();

  // tamper random requests at random indices
  for (int i = 0; i < 50; i++) {
    int random = rand() % 3 + 1;
    if (i % random == 1) {
      // corrupted
      value = invalid_g2.toString(libBLS::algebra::Base::HEXA);
      corruptedIdx.push_back(i);
    } else {
      libBLS::algebra::G2Point decryption_value =
          libBLS::algebra::G2Point::random();
      value = decryption_value.toString(libBLS::algebra::Base::HEXA);
    }
    decriptionValues["publicDecryptionValues"][i] = value;
  }

  resp = c.getDecryptionShares(name, decriptionValues);

  REQUIRE(resp["failedRequests"].size() == corruptedIdx.size());

  for (size_t i = 0; i < corruptedIdx.size(); i++) {
    std::string decryptionShares =
        resp["decryptionShares"][corruptedIdx[i]].asString();
    REQUIRE(decryptionShares == zeroG2String);
    int idx = corruptedIdx[i];
    std::string corruptedIdxStr = std::to_string(idx);
    REQUIRE(resp["failedRequests"][corruptedIdxStr] ==
            STATUS_G2_NOT_WELL_FORMED);
  }
}

TEST_CASE_METHOD(TestFixture, "Test generated bls key decrypt",
                 "[bls-aggregated-key-decrypt]") {
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
                 "[bls-aggregated-key-generation]") {
  HttpClient htp(RPC_ENDPOINT);
  StubClient c(htp, JSONRPC_CLIENT_V2);

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
  auto response = c.generateBLSPrivateKey(name);

  REQUIRE(response["status"] == 0);
}

TEST_CASE_METHOD(
    TestFixture,
    "Test key generation for bls aggregated signatures scheme via zmq",
    "[bls-aggregated-key-generation-zmq]") {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";

  REQUIRE(client->generateBLSPrivateKey(name));
}

TEST_CASE_METHOD(TestFixture,
                 "Test message signing for bls aggregated signatures scheme",
                 "[bls-aggregated-signing]") {
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
    "[bls-aggregated-signing-zmq]") {
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
                 "[bls-aggregated-pop-prove]") {
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
                 "[bls-aggregated-pop-prove-zmq]") {
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

TEST_CASE_METHOD(TestFixtureZMQSign, "ZMQ-ecdsa", "[zmq-ecdsa]") {
  HttpClient htp(RPC_ENDPOINT);
  StubClient c(htp, JSONRPC_CLIENT_V2);

  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  string keyName = "";

  PRINT_SRC_LINE
  keyName = genECDSAKeyAPI(c);
  int end = 10000000;
  string sh = string(SAMPLE_HASH);

  std::vector<std::thread> workers;

  PRINT_SRC_LINE

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
  PRINT_SRC_LINE
}

TEST_CASE_METHOD(TestFixtureNoResetFromBackup, "Backup restore",
                 "[backup-restore]") {}
