/*
  Copyright (C) 2018-2019 SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file BLSPrivateKeyShare.cpp
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

using namespace std;

#include "BLSSigShare.h"
#include "BLSSignature.h"
#include "BLSutils.h"

#include "secure_enclave_u.h"
#include "sgxwallet_common.h"
#include "sgxwallet.h"

#include "BLSCrypto.h"
#include "ServerInit.h"

#include "BLSPrivateKeyShareSGX.h"


std::string *stringFromFq(libff::alt_bn128_Fq*_fq) {

  mpz_t t;
  mpz_init(t);

  _fq->as_bigint().to_mpz(t);

  char arr[mpz_sizeinbase(t, 10) + 2];

  char *tmp = mpz_get_str(arr, 10, t);
  mpz_clear(t);

  return new std::string(tmp);
}

std::string *stringFromG1(libff::alt_bn128_G1 *_g1) {


  auto sX = stringFromFq(&_g1->X);
  auto sY = stringFromFq(&_g1->Y);
  auto sZ = stringFromFq(&_g1->Z);


  auto sG1 = new std::string(*sX + ":" +  *sY + ":" + *sZ);

  delete(sX);
  delete(sY);
  delete(sZ);

  return sG1;

}



BLSPrivateKeyShareSGX::BLSPrivateKeyShareSGX(
    shared_ptr<string> _encryptedKeyHex, size_t _requiredSigners,
    size_t _totalSigners) {

  requiredSigners = _requiredSigners;
  totalSigners = _totalSigners;

  if (requiredSigners > totalSigners) {

    throw std::invalid_argument("requiredSigners > totalSigners");
  }

  if (totalSigners == 0) {
    throw std::invalid_argument("totalSigners == 0");
  }

  if (_encryptedKeyHex == nullptr) {
    throw std::invalid_argument("Null key");
  }

  if (_encryptedKeyHex->size() > 2 * MAX_ENCRYPTED_KEY_LENGTH) {
    throw std::invalid_argument("Encrypted key size too long");
  }

  encryptedKeyHex = _encryptedKeyHex;
}

std::shared_ptr<BLSSigShare> BLSPrivateKeyShareSGX::signWithHelperSGX(
    std::shared_ptr<std::array<uint8_t, 32>> hash_byte_arr,
    size_t _signerIndex) {
  shared_ptr<signatures::Bls> obj;

  if (_signerIndex == 0) {
    BOOST_THROW_EXCEPTION(runtime_error("Zero signer index"));
  }
  if (hash_byte_arr == nullptr) {
    BOOST_THROW_EXCEPTION(runtime_error("Hash is null"));
  }

  obj = make_shared<signatures::Bls>(
      signatures::Bls(requiredSigners, totalSigners));

  std::pair<libff::alt_bn128_G1, std::string> hash_with_hint =
      obj->HashtoG1withHint(hash_byte_arr);

  int errStatus = 0;


  string* xStr = stringFromFq(&(hash_with_hint.first.X));

  if (xStr == nullptr) {
    BOOST_THROW_EXCEPTION(runtime_error("Null xStr"));
  }

  string* yStr = stringFromFq(&(hash_with_hint.first.Y));

  if (xStr == nullptr) {
    BOOST_THROW_EXCEPTION(runtime_error("Null yStr"));
  }




  char errMsg[BUF_LEN];
  memset(errMsg, 0, BUF_LEN);

  char xStrArg[BUF_LEN];
  char yStrArg[BUF_LEN];
  char signature [BUF_LEN];

  memset(xStrArg, 0, BUF_LEN);
  memset(yStrArg, 0, BUF_LEN);

  strncpy(xStrArg, xStr->c_str(), BUF_LEN);
  strncpy(yStrArg, yStr->c_str(), BUF_LEN);

  size_t sz = 0;


  uint8_t encryptedKey[BUF_LEN];

  bool result = hex2carray(encryptedKeyHex->c_str(), &sz, encryptedKey);

  if (!result) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("Invalid hex encrypted key"));
  }

  sgx_status_t status =
      bls_sign_message(eid, &errStatus, errMsg, encryptedKey,
                       encryptedKeyHex->size() / 2, xStrArg, yStrArg, signature);


  if (status != SGX_SUCCESS) {
    gmp_printf("SGX enclave call  to bls_sign_message failed: 0x%04x\n", status);
    BOOST_THROW_EXCEPTION(runtime_error("SGX enclave call  to bls_sign_message failed"));
  }


  if (errStatus != 0) {
    BOOST_THROW_EXCEPTION(runtime_error("Enclave bls_sign_message failed:" + to_string(errStatus) + ":" + errMsg ));
    return nullptr;
  }

  int sigLen;

  if ((sigLen = strnlen(signature, 10)) < 10) {
      BOOST_THROW_EXCEPTION(runtime_error("Signature too short:" + sigLen));
  }



  std::string hint = BLSutils::ConvertToString(hash_with_hint.first.Y) + ":" +
                     hash_with_hint.second;

  auto sig = make_shared<string>(signature);

  auto s = make_shared<BLSSigShare>(sig, _signerIndex, requiredSigners,
                                    totalSigners);

  return s;
}
