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
#include <bls/BLSutils.h>

#include "BLSPrivateKeyShareSGX.h"


#include "sgxwallet_common.h"
#include "sgxwallet.h"
#include "SGXException.h"
#include "third_party/spdlog/spdlog.h"
#include "common.h"
#include "SGXWalletServer.h"

#include "SEKManager.h"
#include "LevelDB.h"
#include "ServerInit.h"
#include "BLSCrypto.h"


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

int char2int(char _input) {
    if (_input >= '0' && _input <= '9')
        return _input - '0';
    if (_input >= 'A' && _input <= 'F')
        return _input - 'A' + 10;
    if (_input >= 'a' && _input <= 'f')
        return _input - 'a' + 10;
    return -1;
}

void carray2Hex(const unsigned char *d, uint64_t _len, char *_hexArray,
                uint64_t _hexArrayLen) {

    CHECK_STATE(d);
    CHECK_STATE(_hexArray);

    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    CHECK_STATE(_hexArrayLen > 2 * _len);

    for (uint64_t j = 0; j < _len; j++) {
        _hexArray[j * 2] = hexval[((d[j] >> 4) & 0xF)];
        _hexArray[j * 2 + 1] = hexval[(d[j]) & 0x0F];
    }

    _hexArray[_len * 2] = 0;
}


bool hex2carray(const char *_hex, uint64_t *_bin_len,
                uint8_t *_bin, uint64_t _max_length) {


    CHECK_STATE(_hex);
    CHECK_STATE(_bin);
    CHECK_STATE(_bin_len)


    uint64_t len = strnlen(_hex, 2 * _max_length + 1);

    CHECK_STATE(len != 2 * _max_length + 1);

    CHECK_STATE(len <= 2 * _max_length);


    if (len == 0 && len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (uint64_t i = 0; i < len / 2; i++) {
        int high = char2int((char) _hex[i * 2]);
        int low = char2int((char) _hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        _bin[i] = (unsigned char) (high * 16 + low);
    }

    return true;
}

bool sign(const char *_encryptedKeyHex, const char *_hashHex, size_t _t, size_t _n, size_t _signerIndex,
          char *_sig) {


    CHECK_STATE(_encryptedKeyHex);
    CHECK_STATE(_hashHex);
    CHECK_STATE(_sig);

    auto keyStr = make_shared<string>(_encryptedKeyHex);

    auto hash = make_shared < array < uint8_t,
    32 >> ();

    uint64_t binLen;

    if (!hex2carray(_hashHex, &binLen, hash->data(), hash->size())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    auto keyShare = make_shared<BLSPrivateKeyShareSGX>(keyStr, _t, _n);

    auto sigShare = keyShare->signWithHelperSGX(hash, _signerIndex);

    auto sigShareStr = sigShare->toString();

    strncpy(_sig, sigShareStr->c_str(), BUF_LEN);

    return true;
}

bool sign_aes(const char *_encryptedKeyHex, const char *_hashHex, size_t _t, size_t _n, char *_sig) {

    CHECK_STATE(_encryptedKeyHex);
    CHECK_STATE(_hashHex);
    CHECK_STATE(_sig);

    auto hash = make_shared < array < uint8_t,
    32 >> ();

    uint64_t binLen;

    if (!hex2carray(_hashHex, &binLen, hash->data(), hash->size())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    shared_ptr <signatures::Bls> obj;
    obj = make_shared<signatures::Bls>(signatures::Bls(_t, _n));

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
    int attempts = 0;
    do {
        attempts++;
        {
            READ_LOCK(initMutex);

            status = trustedBlsSignMessageAES(eid, &errStatus, errMsg.data(), encryptedKey,
                                              sz, xStrArg, yStrArg, signature);

        }
        if (status != SGX_SUCCESS) {
            spdlog::error(__FUNCTION__);
            spdlog::error("Restarting sgx ...");
            reinitEnclave();
        }
    } while (attempts < 2);




    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());

    string hint = BLSutils::ConvertToString(hash_with_hint.first.Y) + ":" + hash_with_hint.second;

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
    {
        READ_LOCK(initMutex);
        status = trustedEncryptKeyAES(eid, errStatus, errMsg.data(), keyArray->data(), encryptedKey->data(),
                                      &encryptedLen);

    }
    HANDLE_TRUSTED_FUNCTION_ERROR(status, *errStatus, errMsg.data());

    SAFE_CHAR_BUF(resultBuf, 2 * BUF_LEN + 1);

    carray2Hex(encryptedKey->data(), encryptedLen, resultBuf, 2 * BUF_LEN + 1);

    return string(resultBuf);
}
