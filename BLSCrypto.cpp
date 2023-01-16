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

#include <memory>
#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"
#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include "third_party/intel/create_enclave.h"


#include "bls.h"
#include <tools/utils.h>

#include "BLSPrivateKeyShareSGX.h"


#include "sgxwallet_common.h"
#include "sgxwallet.h"
#include "SGXException.h"
#include "third_party/spdlog/spdlog.h"
#include "common.h"
#include "SGXWalletServer.hpp"

#include "SEKManager.h"
#include "LevelDB.h"
#include "ServerInit.h"
#include "BLSCrypto.h"
#include "CryptoTools.h"


string *FqToString(libff::alt_bn128_Fq *_fq) {

    CHECK_STATE(_fq);

    mpz_t t;
    mpz_init(t);

    _fq->as_bigint().to_mpz(t);

    SAFE_CHAR_BUF(arr, mpz_sizeinbase(t, 10) + 2);

    mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return new string(arr);
}

bool sign_aes(const char *_encryptedKeyHex, const char *_hashHex, size_t _t, size_t _n, char *_sig) {

    CHECK_STATE(_encryptedKeyHex);
    CHECK_STATE(_hashHex);
    CHECK_STATE(_sig);

    auto hash = make_shared < array < uint8_t, 32 >> ();

    uint64_t binLen;

    if (!hex2carray(_hashHex, &binLen, hash->data(), hash->size())) {
        throw SGXException(SIGN_AES_INVALID_HASH, string(__FUNCTION__) +  ":Invalid hash");
    }

    shared_ptr <libBLS::Bls> obj;
    obj = make_shared<libBLS::Bls>(libBLS::Bls(_t, _n));

    pair <libff::alt_bn128_G1, string> hash_with_hint = obj->HashtoG1withHint(hash);

    string *xStr = FqToString(&(hash_with_hint.first.X));

    CHECK_STATE(xStr);

    string *yStr = FqToString(&(hash_with_hint.first.Y));

    if (yStr == nullptr) {
        delete xStr;
        BOOST_THROW_EXCEPTION(runtime_error("Null yStr"));
    }

    vector<char> errMsg(BUF_LEN, 0);

    SAFE_CHAR_BUF(xStrArg, BUF_LEN);SAFE_CHAR_BUF(yStrArg, BUF_LEN);SAFE_CHAR_BUF(signature, BUF_LEN);

    strncpy(xStrArg, xStr->c_str(), BUF_LEN);
    strncpy(yStrArg, yStr->c_str(), BUF_LEN);

    delete xStr;
    delete yStr;

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

    string hint = libBLS::ThresholdUtils::fieldElementToString(hash_with_hint.first.Y) + ":" + hash_with_hint.second;

    string sig = signature;

    sig.append(":");
    sig.append(hint);

    strncpy(_sig, sig.c_str(), BUF_LEN);

    return true;
}

bool bls_sign(const char *_encryptedKeyHex, const char *_hashHex, size_t _t, size_t _n, char *_sig) {
    CHECK_STATE(_encryptedKeyHex);
    CHECK_STATE(_hashHex);
    return sign_aes(_encryptedKeyHex, _hashHex, _t, _n, _sig);
}

bool popProveSGX( const char* encryptedKeyHex, char* prove ) {
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

    status = trustedGetBlsPubKey(eid, &errStatus, errMsg.data(), encryptedKey, sz, pubKey);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    vector <string> pubKeyVect = splitString(pubKey, ':');

    spdlog::debug("pub key is ");
    for (int i = 0; i < 4; i++)
        spdlog::debug("{}", pubKeyVect.at(i));

    libff::alt_bn128_G2 public_key;
    public_key.Z = libff::alt_bn128_Fq2::one();
    public_key.X.c0 = libff::alt_bn128_Fq(pubKeyVect[0].c_str());
    public_key.X.c1 = libff::alt_bn128_Fq(pubKeyVect[1].c_str());
    public_key.Y.c0 = libff::alt_bn128_Fq(pubKeyVect[2].c_str());
    public_key.Y.c1 = libff::alt_bn128_Fq(pubKeyVect[3].c_str());

    pair <libff::alt_bn128_G1, string> hash_public_key_with_hint = libBLS::Bls::HashPublicKeyToG1WithHint( public_key );

    hash_public_key_with_hint.first.to_affine_coordinates();

    string *xStr = FqToString(&(hash_public_key_with_hint.first.X));

    CHECK_STATE(xStr);

    string *yStr = FqToString(&(hash_public_key_with_hint.first.Y));

    if (yStr == nullptr) {
        delete xStr;
        BOOST_THROW_EXCEPTION(runtime_error("Null yStr"));
    }

    SAFE_CHAR_BUF(xStrArg, BUF_LEN);SAFE_CHAR_BUF(yStrArg, BUF_LEN);

    strncpy(xStrArg, xStr->c_str(), BUF_LEN);
    strncpy(yStrArg, yStr->c_str(), BUF_LEN);

    delete xStr;
    delete yStr;

    errStatus = 0;

    status = trustedBlsSignMessage(eid, &errStatus, errMsg.data(), encryptedKey, sz, xStrArg, yStrArg, prove);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    string hint = libBLS::ThresholdUtils::fieldElementToString(hash_public_key_with_hint.first.Y) + ":" + hash_public_key_with_hint.second;

    string _prove = prove;

    _prove.append(":");
    _prove.append(hint);

    strncpy(prove, _prove.c_str(), BUF_LEN);

    return true;
}

bool generateBLSPrivateKeyAggegated(const char* blsKeyName) {
    CHECK_STATE(blsKeyName);

    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;

    int exportable = 0;

    uint64_t enc_bls_len = 0;

    sgx_status_t status = SGX_SUCCESS;

    SAFE_UINT8_BUF(encr_bls_key, BUF_LEN)

    status = trustedGenerateBLSKey(eid, &errStatus, errMsg.data(), &exportable, encr_bls_key, &enc_bls_len);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    vector<char> hexBLSKey = carray2Hex(encr_bls_key, enc_bls_len);

    SGXWalletServer::writeDataToDB(blsKeyName, hexBLSKey.data());

    return true;
}

string encryptBLSKeyShare2Hex(int *errStatus, char *err_string, const char *_key) {
    CHECK_STATE(errStatus);
    CHECK_STATE(err_string);
    CHECK_STATE(_key);
    auto keyArray = make_shared < vector < char >> (BUF_LEN, 0);
    auto encryptedKey = make_shared < vector < uint8_t >> (BUF_LEN, 0);

    vector<char> errMsg(BUF_LEN, 0);

    strncpy(keyArray->data(), _key, BUF_LEN);
    *errStatus = 0;

    uint64_t encryptedLen = 0;

    sgx_status_t status = SGX_SUCCESS;

    status = trustedEncryptKey(eid, errStatus, errMsg.data(), keyArray->data(), encryptedKey->data(),
                               &encryptedLen);

    HANDLE_TRUSTED_FUNCTION_ERROR(status, *errStatus, errMsg.data());

    vector<char> resultBuf = carray2Hex(encryptedKey->data(), encryptedLen);

    return string(resultBuf.begin(), resultBuf.end());
}
