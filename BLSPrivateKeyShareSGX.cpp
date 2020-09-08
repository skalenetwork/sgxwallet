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
  along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

  @file BLSPrivateKeyShare.cpp
  @author Stan Kladko
  @date 2019
*/

#include "BLSSigShare.h"
#include "BLSSignature.h"
#include "BLSutils.h"

#include "third_party/spdlog/spdlog.h"

#include "secure_enclave_u.h"
#include "sgxwallet_common.h"
#include "sgxwallet.h"

#include "BLSCrypto.h"
#include "ServerInit.h"
#include "common.h"

#include "BLSPrivateKeyShareSGX.h"

string *stringFromFq(libff::alt_bn128_Fq *_fq) {

    CHECK_STATE(_fq);

    mpz_t t;
    mpz_init(t);

    _fq->as_bigint().to_mpz(t);

    SAFE_CHAR_BUF(arr, mpz_sizeinbase(t, 10) + 2);

    char *tmp = mpz_get_str(arr, 10, t);

    mpz_clear(t);

    return new string(tmp);
}

string *stringFromG1(libff::alt_bn128_G1 *_g1) {

    CHECK_STATE(_g1);

    auto sX = stringFromFq(&_g1->X);
    auto sY = stringFromFq(&_g1->Y);
    auto sZ = stringFromFq(&_g1->Z);

    auto sG1 = new string(*sX + ":" + *sY + ":" + *sZ);

    delete (sX);
    delete (sY);
    delete (sZ);

    return sG1;
}

BLSPrivateKeyShareSGX::BLSPrivateKeyShareSGX(
        shared_ptr <string> _encryptedKeyHex, size_t _requiredSigners,
        size_t _totalSigners) {
    requiredSigners = _requiredSigners;
    totalSigners = _totalSigners;

    if (requiredSigners > totalSigners) {
        throw invalid_argument("requiredSigners > totalSigners");
    }

    if (totalSigners == 0) {
        throw invalid_argument("totalSigners == 0");
    }

    if (_encryptedKeyHex == nullptr) {
        throw invalid_argument("Null key");
    }

    if (_encryptedKeyHex->size() > 2 * MAX_ENCRYPTED_KEY_LENGTH) {
        throw invalid_argument("Encrypted key size too long");
    }

    encryptedKeyHex = _encryptedKeyHex;
}

string BLSPrivateKeyShareSGX::signWithHelperSGXstr(
        shared_ptr <array<uint8_t, 32>> hash_byte_arr,
        size_t _signerIndex) {
    shared_ptr <signatures::Bls> obj;

    CHECK_STATE(hash_byte_arr)

    obj = make_shared<signatures::Bls>(
            signatures::Bls(requiredSigners, totalSigners));

    pair <libff::alt_bn128_G1, string> hash_with_hint =
            obj->HashtoG1withHint(hash_byte_arr);

    int errStatus = 0;

    string *xStr = stringFromFq(&(hash_with_hint.first.X));

    CHECK_STATE(xStr);

    string *yStr = stringFromFq(&(hash_with_hint.first.Y));

    if (yStr == nullptr) {
        delete xStr;
        BOOST_THROW_EXCEPTION(runtime_error("Null yStr"));
    }


    vector<char> errMsg(BUF_LEN, 0);


    SAFE_CHAR_BUF(xStrArg, BUF_LEN)SAFE_CHAR_BUF(yStrArg, BUF_LEN)SAFE_CHAR_BUF(signature, BUF_LEN);


    strncpy(xStrArg, xStr->c_str(), BUF_LEN);
    strncpy(yStrArg, yStr->c_str(), BUF_LEN);

    delete xStr;
    delete yStr;

    size_t sz = 0;

    SAFE_UINT8_BUF(encryptedKey, BUF_LEN);

    bool result = hex2carray(encryptedKeyHex->c_str(), &sz, encryptedKey,
                             BUF_LEN);

    if (!result) {
        spdlog::error("Invalid hex encrypted key");
        BOOST_THROW_EXCEPTION(invalid_argument("Invalid hex encrypted key"));
    }

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedBlsSignMessageAES(eid, &errStatus, errMsg.data(), encryptedKey,
                                          encryptedKeyHex->size() / 2, xStrArg, yStrArg, signature);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());


    int sigLen;

    if ((sigLen = strnlen(signature, 10)) < 10) {
        BOOST_THROW_EXCEPTION(runtime_error("Signature is too short:" + to_string(sigLen)));
    }

    string hint = BLSutils::ConvertToString(hash_with_hint.first.Y) + ":" +
                  hash_with_hint.second;

    string sig = signature;

    sig.append(":");
    sig.append(hint);

    return sig;
}

shared_ptr <BLSSigShare> BLSPrivateKeyShareSGX::signWithHelperSGX(
        shared_ptr <array<uint8_t, 32>> hash_byte_arr,
        size_t _signerIndex) {

    CHECK_STATE(hash_byte_arr);

    string signature = signWithHelperSGXstr(hash_byte_arr, _signerIndex);

    auto sig = make_shared<string>(signature);

    shared_ptr <BLSSigShare> s = make_shared<BLSSigShare>(sig, _signerIndex, requiredSigners,
                                                          totalSigners);

    return s;
}
