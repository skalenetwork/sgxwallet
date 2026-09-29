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

    @file BLSCrypto.cpp
    @author Stan Kladko
    @date 2019
*/

#include "backends/interface/group/G2Point.hpp"
#include "leveldb/db.h"
#include "libBLS/backends/interface/init.hpp"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <memory>

#include "third_party/intel/create_enclave.h"

#include <tools/utils.h>

#include "SGXException.h"
#include "SGXWalletServer.hpp"
#include "common.h"
#include "sgxwallet.h"
#include "sgxwallet_common.h"
#include "third_party/spdlog/spdlog.h"

#include "BLSCrypto.h"
#include "CryptoTools.h"
#include "LevelDB.h"
#include "SEKManager.h"
#include "ServerInit.h"

shared_ptr<string> FqToString(const libBLS::algebra::FqElement &fq) {
  return make_shared<string>(fq.toString(libBLS::algebra::Base::DEC));
}

bool sign_aes(const char *_encryptedKeyHex, const char *_hashHex, size_t _t,
              size_t _n, char *_sig) {

  CHECK_STATE(_encryptedKeyHex);
  CHECK_STATE(_hashHex);
  CHECK_STATE(_sig);

  auto hash = make_shared<array<uint8_t, 32>>();

  uint64_t binLen;

  if (!hex2carray(_hashHex, &binLen, hash->data(), hash->size())) {
    throw SGXException(SIGN_AES_INVALID_HASH,
                       string(__FUNCTION__) + ":Invalid hash");
  }

  shared_ptr<libBLS::Bls> obj;
  obj = make_shared<libBLS::Bls>(libBLS::Bls(_t, _n));

  pair<libBLS::algebra::G1Point, string> hash_with_hint =
      libBLS::algebra::hashToG1withHint(*hash);

  shared_ptr<string> xStr = FqToString(hash_with_hint.first.getX());

  CHECK_STATE(xStr);

  shared_ptr<string> yStr = FqToString(hash_with_hint.first.getY());

  CHECK_STATE(yStr);

  vector<char> errMsg(BUF_LEN, 0);

  SAFE_CHAR_BUF(xStrArg, BUF_LEN);
  SAFE_CHAR_BUF(yStrArg, BUF_LEN);
  SAFE_CHAR_BUF(signature, BUF_LEN);

  snprintf(xStrArg, BUF_LEN, "%s", xStr->c_str());
  snprintf(yStrArg, BUF_LEN, "%s", yStr->c_str());

  size_t sz = 0;

  SAFE_UINT8_BUF(encryptedKey, BUF_LEN);

  bool result = hex2carray(_encryptedKeyHex, &sz, encryptedKey, BUF_LEN);

  if (!result) {
    BOOST_THROW_EXCEPTION(invalid_argument("Invalid hex encrypted key"));
  }

  int errStatus = 0;

  sgx_status_t status = SGX_SUCCESS;

  status = trustedBlsSignMessage(eid, &errStatus, errMsg.data(), encryptedKey,
                                 sz, xStrArg, yStrArg, signature);

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

  string hint =
      hash_with_hint.first.getY().toString(libBLS::algebra::Base::DEC) + ":" +
      hash_with_hint.second;

  string sig = signature;

  sig.append(":");
  sig.append(hint);

  strncpy(_sig, sig.c_str(), BUF_LEN);

  return true;
}

bool bls_sign(const char *_encryptedKeyHex, const char *_hashHex, size_t _t,
              size_t _n, char *_sig) {
  CHECK_STATE(_encryptedKeyHex);
  CHECK_STATE(_hashHex);
  return sign_aes(_encryptedKeyHex, _hashHex, _t, _n, _sig);
}

bool popProveSGX(const char *encryptedKeyHex, char *prove) {
  CHECK_STATE(encryptedKeyHex);

  SAFE_UINT8_BUF(encryptedKey, BUF_LEN);

  size_t sz = 0;

  if (!hex2carray(encryptedKeyHex, &sz, encryptedKey, BUF_LEN)) {
    BOOST_THROW_EXCEPTION(invalid_argument("Invalid hex encrypted key"));
  }

  sgx_status_t status = SGX_SUCCESS;

  vector<char> errMsg(BUF_LEN, 0);

  int errStatus = 0;

  SAFE_CHAR_BUF(pubKey, 320)

  status = trustedGetBlsPubKey(eid, &errStatus, errMsg.data(), encryptedKey, sz,
                               pubKey);

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

  vector<string> pubKeyVect = splitString(pubKey, ':');

  spdlog::debug("pub key is ");
  for (int i = 0; i < 4; i++)
    spdlog::debug("{}", pubKeyVect.at(i));

  libBLS::algebra::G2Point publicKey = libBLS::algebra::G2Point::fromString(
      pubKeyVect, libBLS::algebra::Base::DEC);

  pair<libBLS::algebra::G1Point, string> hashPublicKeyWithHint =
      libBLS::Bls::HashPublicKeyToG1WithHint(publicKey);

  hashPublicKeyWithHint.first.toAffineCoordinates();

  shared_ptr<string> xStr = FqToString(hashPublicKeyWithHint.first.getX());

  CHECK_STATE(xStr);

  shared_ptr<string> yStr = FqToString(hashPublicKeyWithHint.first.getY());

  CHECK_STATE(yStr);

  SAFE_CHAR_BUF(xStrArg, BUF_LEN);
  SAFE_CHAR_BUF(yStrArg, BUF_LEN);

  snprintf(xStrArg, BUF_LEN, "%s", xStr->c_str());
  snprintf(yStrArg, BUF_LEN, "%s", yStr->c_str());

  errStatus = 0;

  status = trustedBlsSignMessage(eid, &errStatus, errMsg.data(), encryptedKey,
                                 sz, xStrArg, yStrArg, prove);

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

  string hint =
      hashPublicKeyWithHint.first.getY().toString(libBLS::algebra::Base::DEC) +
      ":" + hashPublicKeyWithHint.second;

  string _prove = prove;

  _prove.append(":");
  _prove.append(hint);

  strncpy(prove, _prove.c_str(), BUF_LEN);

  return true;
}

bool generateBLSPrivateKeyAggegated(const char *blsKeyName) {
  CHECK_STATE(blsKeyName);

  vector<char> errMsg(BUF_LEN, 0);
  int errStatus = 0;

  int exportable = 0;

  uint64_t encBlsLen = 0;

  sgx_status_t status = SGX_SUCCESS;

  SAFE_UINT8_BUF(encrBlsKey, BUF_LEN)

  status = trustedGenerateBLSKey(eid, &errStatus, errMsg.data(), &exportable,
                                 encrBlsKey, &encBlsLen);

  HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

  vector<char> hexBLSKey = carray2Hex(encrBlsKey, encBlsLen);

  SGXWalletServer::writeDataToDB(blsKeyName, hexBLSKey.data());

  return true;
}

string encryptBLSKeyShare2Hex(int *errStatus, char *err_string,
                              const char *_key) {
  CHECK_STATE(errStatus);
  CHECK_STATE(err_string);
  CHECK_STATE(_key);

  const std::string normalizedKey = normalizeAndValidateScalarHex(
      _key, ALT_BN128_ORDER_DEC, 10, BLS_IMPORT_INVALID_KEY_SHARE,
      "BLS key share");

  auto keyArray = make_shared<vector<char>>(BUF_LEN, 0);
  auto encryptedKey = make_shared<vector<uint8_t>>(BUF_LEN, 0);

  vector<char> errMsg(BUF_LEN, 0);

  strncpy(keyArray->data(), normalizedKey.c_str(), BUF_LEN);
  *errStatus = 0;

  uint64_t encryptedLen = 0;

  sgx_status_t status = SGX_SUCCESS;

  status = trustedEncryptKey(eid, errStatus, errMsg.data(), keyArray->data(),
                             encryptedKey->data(), &encryptedLen);

  HANDLE_TRUSTED_FUNCTION_ERROR(status, *errStatus, errMsg.data());

  vector<char> resultBuf = carray2Hex(encryptedKey->data(), encryptedLen);

  return string(resultBuf.begin(), resultBuf.end());
}
