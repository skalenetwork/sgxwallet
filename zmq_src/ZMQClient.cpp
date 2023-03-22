/*
    Copyright (C) 2018-2019 SKALE Labs

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

    @file ZMQClient.cpp
    @author Stan Kladko
    @date 2020
*/

#include "sys/random.h"
#include <sys/syscall.h>
#include <sys/types.h>

#include <fstream>
#include <regex>
#include <streambuf>

#include "CryptoTools.h"
#include "ReqMessage.h"
#include "RspMessage.h"
#include "ZMQClient.h"
#include "common.h"
#include "sgxwallet_common.h"

shared_ptr<ZMQMessage> ZMQClient::doRequestReply(Json::Value &_req) {
  Json::FastWriter fastWriter;

  if (sign) {
    CHECK_STATE(!certificate.empty());
    CHECK_STATE(!key.empty());

    _req["cert"] = certificate;

    string msgToSign = fastWriter.write(_req);

    _req["msgSig"] = signString(pkey, msgToSign);
  }

  string reqStr = fastWriter.write(_req);

  reqStr = reqStr.substr(0, reqStr.size() - 1);
  CHECK_STATE(reqStr.front() == '{');
  CHECK_STATE(reqStr.at(reqStr.size() - 1) == '}');

  auto resultStr = doZmqRequestReply(reqStr);

  try {
    CHECK_STATE(resultStr.size() > 5)
    CHECK_STATE(resultStr.front() == '{')
    CHECK_STATE(resultStr.back() == '}')

    return ZMQMessage::parse(resultStr.c_str(), resultStr.size(), false, false,
                             false);
  } catch (std::exception &e) {
    spdlog::error(string("Error in doRequestReply:") + e.what());
    throw;
  } catch (...) {
    spdlog::error("Error in doRequestReply");
    throw;
  }
}

string ZMQClient::doZmqRequestReply(string &_req) {
  stringstream request;

  shared_ptr<zmq::socket_t> clientSocket = nullptr;

  {
    lock_guard<recursive_mutex> m(mutex);
    if (!clientSockets.count(getProcessID()))
      reconnect();
    clientSocket = clientSockets.at(getProcessID());
    CHECK_STATE(clientSocket);
  }
  CHECK_STATE(clientSocket);

  spdlog::debug("ZMQ client sending: \n {}", _req);

  s_send(*clientSocket, _req);

  while (true) {
    //  Poll socket for a reply, with timeout
    zmq::pollitem_t items[] = {
        {static_cast<void *>(*clientSocket), 0, ZMQ_POLLIN, 0}};
    zmq::poll(&items[0], 1, REQUEST_TIMEOUT);
    //  If we got a reply, process it
    if (items[0].revents & ZMQ_POLLIN) {
      string reply = s_recv(*clientSocket);
      CHECK_STATE(reply.size() > 5);
      spdlog::debug("ZMQ client received reply:{}", reply);
      CHECK_STATE(reply.front() == '{');
      CHECK_STATE(reply.back() == '}');

      return reply;
    } else {
      spdlog::error("W: no response from server, retrying...");
      reconnect();
      //  Send request again, on new socket
      s_send(*clientSocket, _req);
    }
  }
}

string ZMQClient::readFileIntoString(const string &_fileName) {
  ifstream t(_fileName);
  string str((istreambuf_iterator<char>(t)), istreambuf_iterator<char>());
  return str;
}

void ZMQClient::verifySig(EVP_PKEY *_pubkey, const string &_str,
                          const string &_sig) {
  CHECK_STATE(_pubkey);
  CHECK_STATE(!_str.empty());

  static std::regex r("\\s+");
  auto msgToSign = std::regex_replace(_str, r, "");

  vector<uint8_t> binSig(256, 0);

  uint64_t binLen = 0;

  CHECK_STATE2(hex2carray(_sig.c_str(), &binLen, binSig.data(), binSig.size()),
               ZMQ_COULD_NOT_PARSE);

  CHECK_STATE(binLen > 0);

  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;

  size_t slen = 0;

  CHECK_STATE(mdctx = EVP_MD_CTX_create());

  CHECK_STATE(
      (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, _pubkey) == 1));

  CHECK_STATE(
      EVP_DigestVerifyUpdate(mdctx, msgToSign.c_str(), msgToSign.size()) == 1);

  CHECK_STATE2(EVP_DigestVerifyFinal(mdctx, binSig.data(), binLen) == 1,
               ZMQ_COULD_NOT_VERIFY_SIG);

  if (mdctx)
    EVP_MD_CTX_destroy(mdctx);

  return;
}

string ZMQClient::signString(EVP_PKEY *_pkey, const string &_str) {
  CHECK_STATE(_pkey);
  CHECK_STATE(!_str.empty());

  static std::regex r("\\s+");
  auto msgToSign = std::regex_replace(_str, r, "");

  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;
  unsigned char *signature = NULL;
  auto sig = &signature;
  size_t slen = 0;

  CHECK_STATE(mdctx = EVP_MD_CTX_create());

  CHECK_STATE(
      (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, _pkey) == 1));

  CHECK_STATE(
      EVP_DigestSignUpdate(mdctx, msgToSign.c_str(), msgToSign.size()) == 1);

  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the
   * length of the signature. Length is returned in slen */

  CHECK_STATE(EVP_DigestSignFinal(mdctx, NULL, &slen) == 1);
  signature = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * slen);
  CHECK_STATE(signature);
  CHECK_STATE(EVP_DigestSignFinal(mdctx, signature, &slen) == 1);

  auto hexSig = carray2Hex(signature, slen);

  string hexStringSig(hexSig.begin(), hexSig.end());

  /* Clean up */
  if (signature)
    OPENSSL_free(signature);
  if (mdctx)
    EVP_MD_CTX_destroy(mdctx);

  return hexStringSig;
}

pair<EVP_PKEY *, X509 *>
ZMQClient::readPublicKeyFromCertStr(const string &_certStr) {
  CHECK_STATE(!_certStr.empty())

  BIO *bo = BIO_new(BIO_s_mem());
  CHECK_STATE(bo);
  BIO_write(bo, _certStr.c_str(), _certStr.size());

  X509 *cert = nullptr;
  PEM_read_bio_X509(bo, &cert, 0, 0);
  CHECK_STATE(cert);
  auto key = X509_get_pubkey(cert);
  BIO_free(bo);
  CHECK_STATE(key);
  return {key, cert};
};

ZMQClient::ZMQClient(const string &ip, uint16_t port, bool _sign,
                     const string &_certFileName, const string &_certKeyName)
    : ctx(1), sign(_sign), certKeyName(_certKeyName),
      certFileName(_certFileName) {
  spdlog::info("Initing ZMQClient. Sign:{} ", _sign);

  if (sign) {
    CHECK_STATE(!_certFileName.empty());
    CHECK_STATE(!_certKeyName.empty());

    certificate = readFileIntoString(_certFileName);
    CHECK_STATE(!certificate.empty());

    key = readFileIntoString(_certKeyName);
    CHECK_STATE(!key.empty());

    BIO *bo = BIO_new(BIO_s_mem());
    CHECK_STATE(bo);
    BIO_write(bo, key.c_str(), key.size());

    PEM_read_bio_PrivateKey(bo, &pkey, 0, 0);
    CHECK_STATE(pkey);
    BIO_free(bo);

    auto pubKeyStr = readFileIntoString(_certFileName);
    CHECK_STATE(!pubKeyStr.empty());

    tie(pubkey, x509Cert) = readPublicKeyFromCertStr(pubKeyStr);

    auto sig = signString(pkey, "sample");
    verifySig(pubkey, "sample", sig);

  } else {
    CHECK_STATE(_certFileName.empty());
    CHECK_STATE(_certKeyName.empty());
  }

  certFileName = _certFileName;
  certKeyName = _certKeyName;

  url = "tcp://" + ip + ":" + to_string(port);
}

void ZMQClient::reconnect() {
  lock_guard<recursive_mutex> lock(mutex);

  auto pid = getProcessID();

  if (clientSockets.count(pid) > 0) {
    clientSockets.erase(pid);
  }

  uint64_t randNumber;
  CHECK_STATE(getrandom(&randNumber, sizeof(uint64_t), 0) == sizeof(uint64_t));

  string identity = to_string(135) + ":" + to_string(randNumber);

  auto clientSocket = make_shared<zmq::socket_t>(ctx, ZMQ_DEALER);
  clientSocket->setsockopt(ZMQ_IDENTITY, identity.c_str(), identity.size() + 1);
  //  Configure socket to not wait at close time
  int linger = 0;
  clientSocket->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));
  clientSocket->connect(url);
  clientSockets.insert({pid, clientSocket});
}

string ZMQClient::blsSignMessageHash(const std::string &keyShareName,
                                     const std::string &messageHash, int t,
                                     int n) {
  Json::Value p;
  p["type"] = ZMQMessage::BLS_SIGN_REQ;
  p["keyShareName"] = keyShareName;
  p["messageHash"] = messageHash;
  p["n"] = n;
  p["t"] = t;
  auto result = dynamic_pointer_cast<BLSSignRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);

  return result->getSigShare();
}

string ZMQClient::ecdsaSignMessageHash(int base, const std::string &keyName,
                                       const std::string &messageHash) {
  Json::Value p;
  p["type"] = ZMQMessage::ECDSA_SIGN_REQ;
  p["base"] = base;
  p["keyName"] = keyName;
  p["messageHash"] = messageHash;
  auto result = dynamic_pointer_cast<ECDSASignRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getSignature();
}

bool ZMQClient::importBLSKeyShare(const std::string &keyShare,
                                  const std::string &keyName) {
  Json::Value p;
  p["type"] = ZMQMessage::IMPORT_BLS_REQ;
  p["keyShareName"] = keyName;
  p["keyShare"] = keyShare;
  auto result = dynamic_pointer_cast<importBLSRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  return result->getStatus() == 0;
}

string ZMQClient::importECDSAKey(const std::string &keyShare,
                                 const std::string &keyName) {
  Json::Value p;
  p["type"] = ZMQMessage::IMPORT_ECDSA_REQ;
  p["keyName"] = keyName;
  p["key"] = keyShare;
  auto result = dynamic_pointer_cast<importECDSARspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getECDSAPublicKey();
}

pair<string, string> ZMQClient::generateECDSAKey() {
  Json::Value p;
  p["type"] = ZMQMessage::GENERATE_ECDSA_REQ;
  auto result =
      dynamic_pointer_cast<generateECDSARspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return {result->getECDSAPublicKey(), result->getKeyName()};
}

string ZMQClient::getECDSAPublicKey(const string &keyName) {
  Json::Value p;
  p["type"] = ZMQMessage::GET_PUBLIC_ECDSA_REQ;
  p["keyName"] = keyName;
  auto result =
      dynamic_pointer_cast<getPublicECDSARspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getECDSAPublicKey();
}

bool ZMQClient::generateDKGPoly(const string &polyName, int t) {
  Json::Value p;
  p["type"] = ZMQMessage::GENERATE_DKG_POLY_REQ;
  p["polyName"] = polyName;
  p["t"] = t;
  auto result =
      dynamic_pointer_cast<generateDKGPolyRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  return result->getStatus() == 0;
}

Json::Value ZMQClient::getVerificationVector(const string &polyName, int t) {
  Json::Value p;
  p["type"] = ZMQMessage::GET_VV_REQ;
  p["polyName"] = polyName;
  p["t"] = t;
  auto result =
      dynamic_pointer_cast<getVerificationVectorRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getVerificationVector();
}

string ZMQClient::getSecretShare(const string &polyName,
                                 const Json::Value &pubKeys, int t, int n) {
  Json::Value p;
  p["type"] = ZMQMessage::GET_SECRET_SHARE_REQ;
  p["polyName"] = polyName;
  p["publicKeys"] = pubKeys;
  p["t"] = t;
  p["n"] = n;
  auto result =
      dynamic_pointer_cast<getSecretShareRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getSecretShare();
}

bool ZMQClient::dkgVerification(const string &publicShares,
                                const string &ethKeyName,
                                const string &secretShare, int t, int n,
                                int idx) {
  Json::Value p;
  p["type"] = ZMQMessage::DKG_VERIFY_REQ;
  p["ethKeyName"] = ethKeyName;
  p["publicShares"] = publicShares;
  p["secretShare"] = secretShare;
  p["t"] = t;
  p["n"] = n;
  p["index"] = idx;
  auto result =
      dynamic_pointer_cast<dkgVerificationRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->isCorrect();
}

bool ZMQClient::createBLSPrivateKey(const string &blsKeyName,
                                    const string &ethKeyName,
                                    const string &polyName,
                                    const string &secretShare, int t, int n) {
  Json::Value p;
  p["type"] = ZMQMessage::CREATE_BLS_PRIVATE_REQ;
  p["ethKeyName"] = ethKeyName;
  p["polyName"] = polyName;
  p["blsKeyName"] = blsKeyName;
  p["secretShare"] = secretShare;
  p["t"] = t;
  p["n"] = n;
  auto result =
      dynamic_pointer_cast<createBLSPrivateKeyRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  return result->getStatus() == 0;
}

Json::Value ZMQClient::getBLSPublicKey(const string &blsKeyName) {
  Json::Value p;
  p["type"] = ZMQMessage::GET_BLS_PUBLIC_REQ;
  p["blsKeyName"] = blsKeyName;
  auto result = dynamic_pointer_cast<getBLSPublicRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getBLSPublicKey();
}

Json::Value ZMQClient::getAllBlsPublicKeys(const Json::Value &publicShares,
                                           int n, int t) {
  Json::Value p;
  p["type"] = ZMQMessage::GET_ALL_BLS_PUBLIC_REQ;
  p["publicShares"] = publicShares["publicShares"];
  p["t"] = t;
  p["n"] = n;
  auto result =
      dynamic_pointer_cast<getAllBLSPublicKeysRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getPublicKeys();
}

tuple<string, string, Json::Value>
ZMQClient::complaintResponse(const string &polyName, int t, int n, int idx) {
  Json::Value p;
  p["type"] = ZMQMessage::COMPLAINT_RESPONSE_REQ;
  p["polyName"] = polyName;
  p["t"] = t;
  p["n"] = n;
  p["ind"] = idx;
  auto result =
      dynamic_pointer_cast<complaintResponseRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return {result->getDHKey(), result->getShare(),
          result->getVerificationVectorMult()};
}

Json::Value ZMQClient::multG2(const string &x) {
  Json::Value p;
  p["type"] = ZMQMessage::MULT_G2_REQ;
  p["x"] = x;
  auto result = dynamic_pointer_cast<multG2RspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getResult();
}

bool ZMQClient::isPolyExists(const string &polyName) {
  Json::Value p;
  p["type"] = ZMQMessage::IS_POLY_EXISTS_REQ;
  p["polyName"] = polyName;
  auto result = dynamic_pointer_cast<isPolyExistsRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->isExists();
}

void ZMQClient::getServerStatus() {
  Json::Value p;
  p["type"] = ZMQMessage::GET_SERVER_STATUS_REQ;
  auto result =
      dynamic_pointer_cast<getServerStatusRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
}

string ZMQClient::getServerVersion() {
  Json::Value p;
  p["type"] = ZMQMessage::GET_SERVER_VERSION_REQ;
  auto result =
      dynamic_pointer_cast<getServerVersionRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getVersion();
}

bool ZMQClient::deleteBLSKey(const string &blsKeyName) {
  Json::Value p;
  p["type"] = ZMQMessage::DELETE_BLS_KEY_REQ;
  p["blsKeyName"] = blsKeyName;
  auto result = dynamic_pointer_cast<deleteBLSKeyRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->isSuccessful();
}

Json::Value
ZMQClient::getDecryptionShares(const string &blsKeyName,
                               const Json::Value &publicDecryptionValues) {
  Json::Value p;
  p["type"] = ZMQMessage::GET_DECRYPTION_SHARE_REQ;
  p["blsKeyName"] = blsKeyName;
  p["publicDecryptionValues"] =
      publicDecryptionValues["publicDecryptionValues"];
  auto result =
      dynamic_pointer_cast<GetDecryptionShareRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  CHECK_STATE(result->getStatus() == 0);
  return result->getShare();
}

bool ZMQClient::generateBLSPrivateKey(const string &blsKeyName) {
  Json::Value p;
  p["blsKeyName"] = blsKeyName;
  p["type"] = ZMQMessage::GENERATE_BLS_PRIVATE_KEY_REQ;
  auto result =
      dynamic_pointer_cast<generateBLSPrivateKeyRspMessage>(doRequestReply(p));
  CHECK_STATE(result);
  return result->getStatus() == 0;

  Json::Value ZMQClient::getDecryptionShares(
      const string &blsKeyName, const Json::Value &publicDecryptionValues) {
    Json::Value p;
    p["type"] = ZMQMessage::GET_DECRYPTION_SHARE_REQ;
    p["blsKeyName"] = blsKeyName;
    p["publicDecryptionValues"] =
        publicDecryptionValues["publicDecryptionValues"];
    auto result =
        dynamic_pointer_cast<GetDecryptionShareRspMessage>(doRequestReply(p));
    CHECK_STATE(result);
    CHECK_STATE(result->getStatus() == 0);
    return result->getShare();
  }

  std::string ZMQClient::popProve(const string &blsKeyName) {
    Json::Value p;
    p["blsKeyName"] = blsKeyName;
    p["type"] = ZMQMessage::POP_PROVE_REQ;
    auto result = dynamic_pointer_cast<popProveRspMessage>(doRequestReply(p));
    CHECK_STATE(result);
    CHECK_STATE(result->getStatus() == 0);
    return result->getPopProve();
  }

  uint64_t ZMQClient::getProcessID() { return syscall(__NR_gettid); }
