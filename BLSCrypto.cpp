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

#include "bls.h"
#include <bls/BLSutils.h>


#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "BLSPrivateKeyShareSGX.h"


#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>

#include "sgxwallet.h"

#include "SGXWalletServer.h"

#include "BLSCrypto.h"
#include "ServerInit.h"

#include "RPCException.h"

#include "spdlog/spdlog.h"
#include "common.h"


std::string *FqToString(libff::alt_bn128_Fq *_fq) {

    mpz_t t;
    mpz_init(t);

    _fq->as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return new std::string(tmp);
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


void carray2Hex(const unsigned char *d, int _len, char *_hexArray) {

    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (int j = 0; j < _len; j++) {
        _hexArray[j * 2] = hexval[((d[j] >> 4) & 0xF)];
        _hexArray[j * 2 + 1] = hexval[(d[j]) & 0x0F];
    }

    _hexArray[_len * 2] = 0;

}


bool hex2carray(const char *_hex, uint64_t *_bin_len,
                uint8_t *_bin) {

    int len = strnlen(_hex, 2 * BUF_LEN);


    if (len == 0 && len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (int i = 0; i < len / 2; i++) {
        int high = char2int((char) _hex[i * 2]);
        int low = char2int((char) _hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        _bin[i] = (unsigned char) (high * 16 + low);
    }

    return true;

}

bool hex2carray2(const char *_hex, uint64_t *_bin_len,
                 uint8_t *_bin, const int _max_length) {

    int len = strnlen(_hex, _max_length);//2 * BUF_LEN);


    if (len == 0 && len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (int i = 0; i < len / 2; i++) {
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

    //cerr << "ENTER SIGN" << endl;

    auto keyStr = make_shared<string>(_encryptedKeyHex);

    auto hash = make_shared<array<uint8_t, 32>>();

    uint64_t binLen;

    if (!hex2carray(_hashHex, &binLen, hash->data())) {
        throw RPCException(INVALID_HEX, "Invalid hash");
    }
    // assert(binLen == hash->size());



    auto keyShare = make_shared<BLSPrivateKeyShareSGX>(keyStr, _t, _n);

    //cerr << "keyShare created" << endl;
    // {
    auto sigShare = keyShare->signWithHelperSGX(hash, _signerIndex);
    // }

    auto sigShareStr = sigShare->toString();

    strncpy(_sig, sigShareStr->c_str(), BUF_LEN);

    //string sigShareStr = keyShare->signWithHelperSGXstr(hash, _signerIndex);
    //strncpy(_sig, sigShareStr.c_str(), BUF_LEN);

    // string test_sig = "8175162913343900215959836578795929492705714455632345516427532159927644835012:15265825550804683171644566522808807137117748565649051208189914766494241035855:9810286616503120081238481858289626967170509983220853777870754480048381194141:5";
    // auto sig_ptr = make_shared<string>(test_sig);
    // strncpy(_sig, sig_ptr->c_str(), BUF_LEN);

    //cerr<< "sig " << _sig <<endl;

    return true;
}

bool sign_aes(const char *_encryptedKeyHex, const char *_hashHex, size_t _t, size_t _n, size_t _signerIndex,
              char *_sig) {

    //cerr << "ENTER SIGN" << endl;

    auto keyStr = make_shared<string>(_encryptedKeyHex);

    auto hash = make_shared<array<uint8_t, 32>>();

    uint64_t binLen;

    if (!hex2carray(_hashHex, &binLen, hash->data())) {
        throw RPCException(INVALID_HEX, "Invalid hash");
    }
    // assert(binLen == hash->size());



//  auto keyShare = make_shared<BLSPrivateKeyShareSGX>(keyStr, _t, _n);
//
//  //cerr << "keyShare created" << endl;
//  // {
//  auto sigShare = keyShare->signWithHelperSGX(hash, _signerIndex);
//  // }
//
//  auto sigShareStr = sigShare->toString();
//
//  strncpy(_sig, sigShareStr->c_str(), BUF_LEN);
    shared_ptr<signatures::Bls> obj;
    obj = make_shared<signatures::Bls>(signatures::Bls(_t, _n));

    std::pair<libff::alt_bn128_G1, std::string> hash_with_hint =
            obj->HashtoG1withHint(hash);

    int errStatus = 0;


    string *xStr = FqToString(&(hash_with_hint.first.X));

    if (xStr == nullptr) {
        std::cerr << "Null xStr" << std::endl;
        BOOST_THROW_EXCEPTION(runtime_error("Null xStr"));
    }

    string *yStr = FqToString(&(hash_with_hint.first.Y));

    if (yStr == nullptr) {
        std::cerr << "Null yStr" << std::endl;
        BOOST_THROW_EXCEPTION(runtime_error("Null yStr"));
    }


    char errMsg[BUF_LEN];
    memset(errMsg, 0, BUF_LEN);

    char xStrArg[BUF_LEN];
    char yStrArg[BUF_LEN];
    char signature[BUF_LEN];

    memset(xStrArg, 0, BUF_LEN);
    memset(yStrArg, 0, BUF_LEN);

    strncpy(xStrArg, xStr->c_str(), BUF_LEN);
    strncpy(yStrArg, yStr->c_str(), BUF_LEN);

    size_t sz = 0;


    uint8_t encryptedKey[BUF_LEN];

    bool result = hex2carray(_encryptedKeyHex, &sz, encryptedKey);

    if (!result) {
        cerr << "Invalid hex encrypted key" << endl;
        BOOST_THROW_EXCEPTION(std::invalid_argument("Invalid hex encrypted key"));
    }

    sgx_status_t status =
            bls_sign_message_aes(eid, &errStatus, errMsg, encryptedKey,
                                 sz, xStrArg, yStrArg, signature);


    if (status != SGX_SUCCESS) {
        cerr << "SGX enclave call  to bls_sign_message failed:" << status << std::endl;
        BOOST_THROW_EXCEPTION(runtime_error("SGX enclave call  to bls_sign_message failed"));
    }


    std::string hint = BLSutils::ConvertToString(hash_with_hint.first.Y) + ":" +
                       hash_with_hint.second;


    std::string sig = signature;

    sig.append(":");
    sig.append(hint);

    strncpy(_sig, sig.c_str(), BUF_LEN);

    printf("_sig is: %s\n", sig.c_str());

    //string sigShareStr = keyShare->signWithHelperSGXstr(hash, _signerIndex);
    //strncpy(_sig, sigShareStr.c_str(), BUF_LEN);

    // string test_sig = "8175162913343900215959836578795929492705714455632345516427532159927644835012:15265825550804683171644566522808807137117748565649051208189914766494241035855:9810286616503120081238481858289626967170509983220853777870754480048381194141:5";
    // auto sig_ptr = make_shared<string>(test_sig);
    // strncpy(_sig, sig_ptr->c_str(), BUF_LEN);

    //cerr<< "sig " << _sig <<endl;

    return true;
}

bool bls_sign(const char *_encryptedKeyHex, const char *_hashHex, size_t _t, size_t _n, size_t _signerIndex,
              char *_sig) {

    if (!encryptKeys) {
        return sign(_encryptedKeyHex, _hashHex, _t, _n, _signerIndex, _sig);
    } else {
        return sign_aes(_encryptedKeyHex, _hashHex, _t, _n, _signerIndex, _sig);
    }
}

char *encryptBLSKeyShare2Hex(int *errStatus, char *err_string, const char *_key) {
    auto keyArray = make_shared<vector<char>>(BUF_LEN, 0);
    auto encryptedKey = make_shared<vector<uint8_t>>(BUF_LEN, 0);
    auto errMsg = make_shared<vector<char>>(BUF_LEN, 0);
    strncpy(keyArray->data(), _key, BUF_LEN);
    *errStatus = -1;

    unsigned int encryptedLen = 0;

    //status = encrypt_key(eid, errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);
    status = encrypt_key_aes(eid, errStatus, errMsg->data(), keyArray->data(), encryptedKey->data(), &encryptedLen);

    spdlog::debug("errStatus is {}", *errStatus);
    spdlog::debug(" errMsg is ", errMsg->data());


    if (status != SGX_SUCCESS) {

        *errStatus = -1;
        return nullptr;
    }

    if (*errStatus != 0) {
        throw RPCException(-666, errMsg->data());
    }


    char *result = (char *) calloc(2 * BUF_LEN, 1);

    carray2Hex(encryptedKey->data(), encryptedLen, result);

    return result;
}

char *decryptBLSKeyShareFromHex(int *errStatus, char *errMsg, const char *_encryptedKey) {


    *errStatus = -1;

    uint64_t decodedLen = 0;

    uint8_t decoded[BUF_LEN];

    if (!(hex2carray(_encryptedKey, &decodedLen, decoded))) {
        return nullptr;
    }

    char *plaintextKey = (char *) calloc(BUF_LEN, 1);

    //status = decrypt_key(eid, errStatus, errMsg, decoded, decodedLen, plaintextKey);
    status = decrypt_key_aes(eid, errStatus, errMsg, decoded, decodedLen, plaintextKey);

    if (status != SGX_SUCCESS) {
        return nullptr;
    }

    if (*errStatus != 0) {
        return nullptr;
    }

    return plaintextKey;

}