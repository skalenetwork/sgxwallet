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

#include "LevelDB.h"
#include "SGXRegistrationServer.h"
#include "SGXWalletServer.hpp"
#include "WalletDBKeys.h"
#include "tests/TestConstants.h"
#include "tests/TestSupport.h"
#include "tests/integration/dkg/DKGIntegrationTestSupport.h"
#include "third_party/catch.hpp"
#include "zmq_src/ZMQClient.h"

#include <atomic>
#include <chrono>
#include <fstream>
#include <future>
#include <json/json.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

using namespace jsonrpc;
using namespace std;

namespace {

const string rootCACert = "./sgx_data/cert_data/rootCA.pem";
const string rootCAKey = "./sgx_data/cert_data/rootCA.key";
const string otherKey = "insecure-samples/yourdomain.key";
const string keyHex =
    "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";

string readFile(const string &_path) {
  ifstream in(_path);
  REQUIRE(in.good());
  stringstream contents;
  contents << in.rdbuf();
  return contents.str();
}

shared_ptr<EVP_PKEY> readKey(const string &_path) {
  const unique_ptr<BIO, decltype(&BIO_free)> bio(
      BIO_new_file(_path.c_str(), "r"), BIO_free);
  REQUIRE(bio);
  auto key = make_shared_evp_pkey(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  REQUIRE(key);
  return key;
}

shared_ptr<ZMQClient> zmqClient(const string &_cert, const string &_key) {
  return make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true, _cert, _key);
}

shared_ptr<ZMQClient> rootClient() { return zmqClient(rootCACert, rootCAKey); }

// Returns the path of a second client certificate issued by this wallet's CA.
string signOtherCert() {
  const auto result = SGXRegistrationServer::getServer()->SignCertificate(
      readFile("insecure-samples/yourdomain.csr"));
  REQUIRE(result["status"] == 0);
  return string(CERT_DIR) + "/" + result["hash"].asString() + ".crt";
}

shared_ptr<ZMQClient> foreignClient() {
  const string cert = "sgx_data/foreign.crt";
  const string key = "sgx_data/foreign.key";
  REQUIRE(system(("openssl req -x509 -newkey rsa:2048 -nodes -days 1 "
                  "-subj /CN=Foreign -keyout " +
                  key + " -out " + cert + " 2>/dev/null")
                     .c_str()) == 0);
  return zmqClient(cert, key);
}

// A getServerStatus request signed with the root CA key, as ZMQClient does.
string signedStatusRequest(bool _tamperSignature) {
  Json::Value request;
  request["type"] = ZMQMessage::GET_SERVER_STATUS_REQ;
  request["cert"] = readFile(rootCACert);
  Json::StreamWriterBuilder compact;
  compact["indentation"] = "";
  auto signature = ZMQClient::signString(readKey(rootCAKey).get(),
                                         Json::writeString(compact, request));
  if (_tamperSignature) {
    signature[0] = signature[0] == '0' ? '1' : '0';
  }
  request["msgSig"] = signature;
  return Json::writeString(compact, request);
}

Json::Value rawRequest(const string &_request) {
  zmq::context_t ctx(1);
  zmq::socket_t socket(ctx, ZMQ_DEALER);
  socket.set(zmq::sockopt::linger, 0);
  socket.connect("tcp://" + string(ZMQ_IP) + ":" + to_string(ZMQ_PORT));
  s_send(socket, _request);

  zmq::pollitem_t items[] = {{static_cast<void *>(socket), 0, ZMQ_POLLIN, 0}};
  zmq::poll(&items[0], 1, REQUEST_TIMEOUT);
  REQUIRE((items[0].revents & ZMQ_POLLIN));

  return parseJson(s_recv(socket));
}

// Exposes the lock under which ZMQ creates and claims keys.
struct OwnershipLock : ZMQMessage {
  using ZMQMessage::ownershipMutex;
};

// Writes to _path a certificate for _key named _subject, issued by the wallet
// CA and valid for _seconds.
void signWithCAKey(const string &_path, EVP_PKEY *_key, X509_NAME *_subject,
                   long _seconds) {
  const auto ca =
      ZMQClient::readPublicKeyFromCertStr(readFile(rootCACert)).second;
  const auto cert = make_shared_x509(X509_new());
  REQUIRE(cert);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
  X509_set_subject_name(cert.get(), _subject);
  X509_set_issuer_name(cert.get(), X509_get_subject_name(ca.get()));
  X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
  X509_gmtime_adj(X509_getm_notAfter(cert.get()), _seconds);
  X509_set_pubkey(cert.get(), _key);
  REQUIRE(X509_sign(cert.get(), readKey(rootCAKey).get(), EVP_sha256()) > 0);

  const unique_ptr<BIO, decltype(&BIO_free)> out(
      BIO_new_file(_path.c_str(), "w"), BIO_free);
  REQUIRE(out);
  REQUIRE(PEM_write_bio_X509(out.get(), cert.get()) == 1);
}

// Returns the path of a certificate for otherKey, valid for _seconds.
string otherKeyCert(long _seconds) {
  const unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(),
                                                              X509_NAME_free);
  REQUIRE(name);
  X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char *>("Other"),
                             -1, -1, 0);
  const string path = "sgx_data/other-" + to_string(_seconds) + ".crt";
  signWithCAKey(path, readKey(otherKey).get(), name.get(), _seconds);
  return path;
}

} // namespace

TEST_CASE_METHOD(TestFixture, "ZMQ accepts only requests signed with this CA",
                 "[integration][zmq-auth][zmq-auth-signature]") {
  REQUIRE_NOTHROW(rootClient()->getServerStatus());

  const auto unsignedClient =
      make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, false, "", "");
  REQUIRE_THROWS(unsignedClient->getServerStatus());
  REQUIRE_THROWS(foreignClient()->getServerStatus());

  REQUIRE(rawRequest(signedStatusRequest(false))["status"] == 0);
  REQUIRE(rawRequest(signedStatusRequest(true))["status"] != 0);
}

TEST_CASE_METHOD(TestFixture, "ZMQ verifies signed requests of every type",
                 "[integration][zmq-auth][zmq-auth-canonical]") {
  // BLS signing and the DKG flow cover nine request types.
  DKGIntegrationTestSupport::sendRPCRequestZMQ();

  const auto client = rootClient();
  REQUIRE_NOTHROW(client->getServerStatus());
  REQUIRE(client->getServerVersion() == SGXWalletServer::getVersion());
  REQUIRE_NOTHROW(client->multG2("1"));

  const string ecdsaName = "NEK:abcdef";
  const auto publicKey = client->importECDSAKey(keyHex, ecdsaName);
  REQUIRE(client->getECDSAPublicKey(ecdsaName) == publicKey);
  REQUIRE_NOTHROW(client->ecdsaSignMessageHash(16, ecdsaName, SAMPLE_HASH));

  const string importedName = "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:0";
  REQUIRE(client->importBLSKeyShare(keyHex, importedName));
  REQUIRE_NOTHROW(client->popProve(importedName));
  Json::Value noCiphertexts;
  noCiphertexts["publicDecryptionValues"] = Json::Value(Json::arrayValue);
  REQUIRE_NOTHROW(client->getDecryptionShares(importedName, noCiphertexts));
  REQUIRE(client->deleteBLSKey(importedName));

  // One-node DKG v3; its free term must be a generated BLS key.
  const string previousName = "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:1";
  REQUIRE(client->generateBLSPrivateKey(previousName));
  const auto ethKey = client->generateECDSAKey();
  const string polyName = "POLY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:2";
  REQUIRE(client->generateDKGPolyV3(polyName, previousName, 1));
  REQUIRE(client->isPolyExists(polyName));
  Json::Value ethPublicKeys;
  ethPublicKeys.append(ethKey.first);
  const auto secretShares =
      client->getSecretShare(polyName, ethPublicKeys, 1, 1);
  REQUIRE(client->createBLSPrivateKeyV3(
      "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:2", ethKey.second, "",
      DKGIntegrationTestSupport::dkgV3SecretContributionsForRecipient(
          {secretShares}, 0),
      1, 1));
  REQUIRE_NOTHROW(client->complaintResponse(polyName, 1, 1, 0));
}

TEST_CASE_METHOD(TestFixture, "ZMQ keys are usable only by their owner",
                 "[integration][zmq-auth][zmq-auth-ownership]") {
  const auto owner = rootClient();
  const string otherCert = signOtherCert();
  const auto other = zmqClient(otherCert, otherKey);

  const auto ecdsaKey = owner->generateECDSAKey();
  const string blsName = "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:0";
  REQUIRE(owner->importBLSKeyShare(keyHex, blsName));
  Json::Value noCiphertexts;
  noCiphertexts["publicDecryptionValues"] = Json::Value(Json::arrayValue);

  REQUIRE_THROWS(other->ecdsaSignMessageHash(16, ecdsaKey.second, SAMPLE_HASH));
  REQUIRE_THROWS(other->getECDSAPublicKey(ecdsaKey.second));
  REQUIRE_THROWS(other->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1));
  REQUIRE_THROWS(other->getBLSPublicKey(blsName));
  REQUIRE_THROWS(other->getDecryptionShares(blsName, noCiphertexts));
  REQUIRE_THROWS(other->popProve(blsName));
  REQUIRE_THROWS(other->deleteBLSKey(blsName));
  REQUIRE(owner->getECDSAPublicKey(ecdsaKey.second) == ecdsaKey.first);
  REQUIRE_NOTHROW(owner->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1));

  // Ownership rows survive a restart.
  destroyTestEnclave();
  initConfig config = makeTestInitConfig(false, false, true, true, true);
  initAll(config);
  REQUIRE_THROWS(zmqClient(otherCert, otherKey)
                     ->ecdsaSignMessageHash(16, ecdsaKey.second, SAMPLE_HASH));
  REQUIRE_NOTHROW(
      rootClient()->ecdsaSignMessageHash(16, ecdsaKey.second, SAMPLE_HASH));
}

TEST_CASE_METHOD(TestFixture, "ZMQ sign claims a key created over HTTP",
                 "[integration][zmq-auth][zmq-auth-first-use]") {
  HttpClient httpClient(RPC_ENDPOINT);
  StubClient c(httpClient, JSONRPC_CLIENT_V2);
  const string keyName = genECDSAKeyAPI(c);
  const auto owner = rootClient();
  const auto other = zmqClient(signOtherCert(), otherKey);

  REQUIRE_THROWS(other->getECDSAPublicKey(keyName));
  sleep(1); // the ownership row must be newer than the key for the last check
  REQUIRE_NOTHROW(owner->ecdsaSignMessageHash(16, keyName, SAMPLE_HASH));
  REQUIRE_NOTHROW(owner->getECDSAPublicKey(keyName));
  REQUIRE_THROWS(other->ecdsaSignMessageHash(16, keyName, SAMPLE_HASH));
  REQUIRE_THROWS(other->getECDSAPublicKey(keyName));

  HttpClient infoClient("http://localhost:" + to_string(BASE_PORT + 4));
  StubClient info(infoClient, JSONRPC_CLIENT_V2);
  REQUIRE(info.getLatestCreatedKey()["keyName"].asString() == keyName);
}

TEST_CASE_METHOD(TestFixture, "ZMQ key names cannot be squatted",
                 "[integration][zmq-auth][zmq-auth-no-squatting]") {
  const auto owner = rootClient();
  const auto other = zmqClient(signOtherCert(), otherKey);
  const auto ownerRow = [](const string &_name) {
    return LevelDB::getLevelDb()->readString(_name +
                                             string(WalletDBKeys::ownerSuffix));
  };

  // A sign request claims neither a missing key...
  const string blsName = "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:3";
  REQUIRE_THROWS(other->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1));
  REQUIRE(ownerRow(blsName) == nullptr);
  REQUIRE(owner->importBLSKeyShare(keyHex, blsName));
  REQUIRE_NOTHROW(owner->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1));

  // ...nor a key it cannot sign with.
  HttpClient httpClient(RPC_ENDPOINT);
  StubClient c(httpClient, JSONRPC_CLIENT_V2);
  const string polyName = "POLY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:6";
  REQUIRE(c.generateDKGPoly(polyName, 1)["status"] == 0);
  REQUIRE_THROWS(other->ecdsaSignMessageHash(16, polyName, SAMPLE_HASH));
  REQUIRE(ownerRow(polyName) == nullptr);

  // The ownership row of a deleted key still reserves its name.
  const string deletedName = "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:5";
  REQUIRE(other->importBLSKeyShare(keyHex, deletedName));
  REQUIRE(other->deleteBLSKey(deletedName));
  REQUIRE_THROWS(owner->importBLSKeyShare(keyHex, deletedName));
  REQUIRE(LevelDB::getLevelDb()->readString(deletedName) == nullptr);
}

TEST_CASE_METHOD(TestFixture, "ZMQ sign racing a key import cannot use it",
                 "[integration][zmq-auth][zmq-auth-concurrent-import]") {
  const auto owner = rootClient();
  const auto other = zmqClient(signOtherCert(), otherKey);
  const string blsName = "BLS_KEY:SCHAIN_ID:777:NODE_ID:0:DKG_ID:4";
  atomic<bool> importDone{false};
  atomic<int> otherSignatures{0};

  // The server pauses 100 ms on a repeated identical sign request, between
  // its ownership check and the signing, so the import lands inside a request.
  thread racer([&] {
    while (!importDone) {
      try {
        other->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1);
        otherSignatures++;
      } catch (...) {
      }
      usleep(1000);
    }
  });
  usleep(20 * 1000);
  bool imported = false;
  try {
    imported = owner->importBLSKeyShare(keyHex, blsName);
  } catch (...) {
  }
  importDone = true;
  racer.join();

  REQUIRE(imported);
  REQUIRE(otherSignatures == 0);
  REQUIRE_THROWS(other->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1));
  REQUIRE_NOTHROW(owner->blsSignMessageHash(blsName, SAMPLE_HASH, 1, 1));
}

TEST_CASE_METHOD(TestFixture,
                 "ZMQ ECDSA key generation holds the ownership lock",
                 "[integration][zmq-auth][zmq-auth-generate-ecdsa]") {
  const auto owner = rootClient();
  const auto other = zmqClient(signOtherCert(), otherKey);
  future<pair<string, string>> generated;
  {
    // Signs claim keys under this lock, so none can find the new key unowned.
    const lock_guard<mutex> lock(OwnershipLock::ownershipMutex);
    generated = async(launch::async, [&] { return owner->generateECDSAKey(); });
    REQUIRE(generated.wait_for(chrono::milliseconds(500)) ==
            future_status::timeout);
  }
  const string keyName = generated.get().second;
  REQUIRE_THROWS(other->ecdsaSignMessageHash(16, keyName, SAMPLE_HASH));
  REQUIRE_NOTHROW(owner->ecdsaSignMessageHash(16, keyName, SAMPLE_HASH));
}

TEST_CASE_METHOD(TestFixture, "JSON-RPC ignores ZMQ key ownership",
                 "[integration][zmq-auth][zmq-auth-https-bypass]") {
  destroyTestEnclave();
  resetTestDB();
  initConfig config = makeTestInitConfig(true, true, true, true, true);
  initAll(config);

  const string keyName = rootClient()->generateECDSAKey().second;
  const string request =
      "{\"jsonrpc\":\"2.0\",\"method\":\"ecdsaSignMessageHash\",\"params\":{"
      "\"base\":16,\"keyName\":\"" +
      keyName + "\",\"messageHash\":\"" + SAMPLE_HASH + "\"},\"id\":1}";
  const auto reply = parseJson(httpsRequest(RPC_ENDPOINT_HTTPS, request, false,
                                            otherKey, signOtherCert()));
  REQUIRE(reply["result"]["status"] == 0);
}

TEST_CASE_METHOD(TestFixture, "ZMQ certificate checks never prompt",
                 "[integration][zmq-auth][zmq-auth-no-prompt]") {
  auto cert = readFile(rootCACert);
  cert.insert(cert.find('\n') + 1,
              "Proc-Type: 4,ENCRYPTED\n"
              "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n");
  Json::Value request;
  request["type"] = ZMQMessage::GET_SERVER_STATUS_REQ;
  request["cert"] = cert;
  request["msgSig"] = "00";
  Json::StreamWriterBuilder compact;
  compact["indentation"] = "";

  Json::Value reply;
  REQUIRE(TestSupport::leavesStdinUnread(
      [&] { reply = rawRequest(Json::writeString(compact, request)); }));
  REQUIRE(reply["status"] != 0);
}

TEST_CASE_METHOD(TestFixture,
                 "ZMQ rejects a cached certificate once it expires",
                 "[integration][zmq-auth][zmq-auth-cert-expiry]") {
  const auto client = zmqClient(otherKeyCert(3), otherKey);
  REQUIRE_NOTHROW(client->getServerStatus());
  sleep(4);
  REQUIRE_THROWS(client->getServerStatus());
}

TEST_CASE_METHOD(TestFixture,
                 "ZMQ rejects a cached certificate once its CA expires",
                 "[integration][zmq-auth][zmq-auth-ca-expiry]") {
  const auto client = zmqClient(otherKeyCert(24 * 60 * 60), otherKey);

  // Reissue the wallet CA certificate to expire in three seconds.
  struct RestoreCACert {
    const string pem = readFile(rootCACert);
    ~RestoreCACert() { ofstream(rootCACert) << pem; }
  } restore;
  const auto ca = ZMQClient::readPublicKeyFromCertStr(restore.pem).second;
  signWithCAKey(rootCACert, readKey(rootCAKey).get(),
                X509_get_subject_name(ca.get()), 3);

  REQUIRE_NOTHROW(client->getServerStatus());
  sleep(4);
  REQUIRE_THROWS(client->getServerStatus());
}
