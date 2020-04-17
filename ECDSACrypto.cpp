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

    @file ECDSACrypto.cpp
    @author Stan Kladko
    @date 2019
*/

#include "ECDSACrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"

#include "SGXException.h"

#include <iostream>
#include <gmp.h>
#include <random>

#include "spdlog/spdlog.h"


static default_random_engine randGen((unsigned int) time(0));

string concatPubKeyWith0x(char *pub_key_x, char *pub_key_y) {
    string px = pub_key_x;
    string py = pub_key_y;
    string result = "0x" + px + py;
    return result;
}

std::vector<std::string> genECDSAKey() {
    char *errMsg = (char *) calloc(1024, 1);
    int err_status = 0;
    uint8_t *encr_pr_key = (uint8_t *) calloc(1024, 1);
    char *pub_key_x = (char *) calloc(1024, 1);
    char *pub_key_y = (char *) calloc(1024, 1);
    uint32_t enc_len = 0;

    if (!encryptKeys)
        status = trustedGenerateEcdsaKey(eid, &err_status, errMsg, encr_pr_key, &enc_len, pub_key_x, pub_key_y);
    else
        status = trustedGenerateEcdsaKey_aes(eid, &err_status, errMsg, encr_pr_key, &enc_len, pub_key_x, pub_key_y);

    if (status != SGX_SUCCESS || err_status != 0) {
        spdlog::error("RPCException thrown with status {}", status);
        throw SGXException(status, errMsg);
    }
    std::vector<std::string> keys(3);



    char *hexEncrKey = (char *) calloc(BUF_LEN * 2, 1);
    carray2Hex(encr_pr_key, enc_len, hexEncrKey);
    keys.at(0) = hexEncrKey;
    keys.at(1) = std::string(pub_key_x) + std::string(pub_key_y);//concatPubKeyWith0x(pub_key_x, pub_key_y);//


    unsigned long seed = randGen();
    spdlog::debug("seed is {}", seed);
    gmp_randstate_t state;
    gmp_randinit_default(state);

    gmp_randseed_ui(state, seed);

    mpz_t rand32;
    mpz_init(rand32);
    mpz_urandomb(rand32, state, 256);

    char arr[mpz_sizeinbase(rand32, 16) + 2];
    char *rand_str = mpz_get_str(arr, 16, rand32);

    keys.at(2) = rand_str;


    gmp_randclear(state);
    mpz_clear(rand32);

    free(errMsg);
    free(pub_key_x);
    free(pub_key_y);
    free(encr_pr_key);
    free(hexEncrKey);

    return keys;
}

std::string getECDSAPubKey(const char *_encryptedKeyHex) {

    vector<char> errMsg(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    vector<uint8_t> encrPrKey(BUF_LEN, 0);

    int err_status = 0;
    uint64_t enc_len = 0;

    if (!hex2carray(_encryptedKeyHex, &enc_len, encrPrKey.data())) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    if (!encryptKeys)
        status = trustedGetPublicEcdsaKey(eid, &err_status, errMsg.data(), encrPrKey.data(), enc_len, pubKeyX.data(),
                pubKeyY.data());
    else status = trustedGetPublicEcdsaKey_aes(eid, &err_status,
            errMsg.data(), encrPrKey.data(), enc_len, pubKeyX.data(), pubKeyY.data());
    if (err_status != 0) {
        throw SGXException(-666, errMsg.data());
    }
    string pubKey = string(pubKeyX.data()) + string(pubKeyY.data());//concatPubKeyWith0x(pub_key_x, pub_key_y);//

        spdlog::debug("enc_len is {}", enc_len);
        spdlog::debug("pubkey is {}", pubKey);
        spdlog::debug("pubkey length is {}", pubKey.length());
        spdlog::debug("err str is {}", errMsg.data());
        spdlog::debug("err status is {}", err_status);


    return pubKey;
}

vector<string> ecdsaSignHash(const char *encryptedKeyHex, const char *hashHex, int base) {
    vector<string> signature_vect(3);

    char *errMsg = (char *) calloc(1024, 1);
    int err_status = 0;
    char *signature_r = (char *) calloc(1024, 1);
    char *signature_s = (char *) calloc(1024, 1);
    uint8_t signature_v = 0;
    uint64_t dec_len = 0;

    //uint8_t encr_key[BUF_LEN];
    uint8_t *encr_key = (uint8_t *) calloc(1024, 1);
    if (!hex2carray(encryptedKeyHex, &dec_len, encr_key)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }


    spdlog::debug("encryptedKeyHex: {}", encryptedKeyHex);
    spdlog::debug("HASH: {}", hashHex);
    spdlog::debug("encrypted len: {}", dec_len);


    if (!encryptKeys)
        status = trustedEcdsaSign(eid, &err_status, errMsg, encr_key, ECDSA_ENCR_LEN, (unsigned char *) hashHex, signature_r,
                             signature_s, &signature_v, base);
    else
        status = trustedEcdsaSignAES(eid, &err_status, errMsg, encr_key, dec_len, (unsigned char *) hashHex, signature_r,
                                signature_s, &signature_v, base);
    if (err_status != 0) {
        throw SGXException(-666, errMsg);
    }


    spdlog::debug("signature r in  ecdsa_sign_hash: {}", signature_r);
    spdlog::debug("signature s in  ecdsa_sign_hash: {}", signature_s);


    if (status != SGX_SUCCESS) {
        spdlog::error("  failed to sign ");
    }
    signature_vect.at(0) = to_string(signature_v);
    if (base == 16) {
        signature_vect.at(1) = "0x" + string(signature_r);
        signature_vect.at(2) = "0x" + string(signature_s);
    } else {
        signature_vect.at(1) = string(signature_r);
        signature_vect.at(2) = string(signature_s);
    }

    free(errMsg);
    free(signature_r);
    free(signature_s);
    free(encr_key);

    return signature_vect;
}