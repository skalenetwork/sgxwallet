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

#include "sgxwallet.h"

#include "SGXException.h"

#include <iostream>
#include <fstream>

#include <gmp.h>
#include <random>

#include "third_party/spdlog/spdlog.h"
#include "common.h"

#include "secure_enclave/Verify.h"

#include "BLSCrypto.h"

#include "SEKManager.h"
#include "ECDSACrypto.h"

void fillRandomBuffer(vector<unsigned char> &_buffer) {
    ifstream devRandom("/dev/urandom", ios::in | ios::binary);
    devRandom.exceptions(ifstream::failbit | ifstream::badbit);
    devRandom.read((char *) _buffer.data(), _buffer.size());
    devRandom.close();
}

vector <string> genECDSAKey() {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encr_pr_key(BUF_LEN, 0);
    vector<char> pub_key_x(BUF_LEN, 0);
    vector<char> pub_key_y(BUF_LEN, 0);

    uint64_t enc_len = 0;

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedGenerateEcdsaKey(eid, &errStatus,
                                   errMsg.data(), encr_pr_key.data(), &enc_len,
                                   pub_key_x.data(), pub_key_y.data());
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus,errMsg.data());

    vector <string> keys(3);

    vector<char> hexEncrKey = carray2Hex(encr_pr_key.data(), enc_len);
    keys.at(0) = hexEncrKey.data();
    keys.at(1) = string(pub_key_x.data()) + string(pub_key_y.data());

    vector<unsigned char> randBuffer(32, 0);
    fillRandomBuffer(randBuffer);

    vector<char> rand_str = carray2Hex(randBuffer.data(), 32);

    keys.at(2) = rand_str.data();

    CHECK_STATE(keys.at(2).size() == 64);

    return keys;
}

string getECDSAPubKey(const std::string& _encryptedKeyHex) {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    vector<uint8_t> encrPrKey(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t enc_len = 0;

    if (!hex2carray(_encryptedKeyHex.c_str(), &enc_len, encrPrKey.data(),
                    BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedGetPublicEcdsaKey(eid, &errStatus,
                                             errMsg.data(), encrPrKey.data(), enc_len, pubKeyX.data(), pubKeyY.data());
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data())

    string pubKey = string(pubKeyX.data()) + string(pubKeyY.data());

    if (pubKey.size() != 128) {
        spdlog::error("Incorrect pub key size", status);
        throw SGXException(666, "Incorrect pub key size");
    }

    return pubKey;
}

bool verifyECDSASig(string& pubKeyStr, const char *hashHex, const char *signatureR,
        const char *signatureS, int base) {

    CHECK_STATE(hashHex)
    CHECK_STATE(signatureR)
    CHECK_STATE(signatureS)

    auto x = pubKeyStr.substr(0, 64);
    auto y = pubKeyStr.substr(64, 128);

    mpz_t msgMpz;
    mpz_init(msgMpz);
    if (mpz_set_str(msgMpz, hashHex, 16) == -1) {
        spdlog::error("invalid message hash {}", hashHex);
        mpz_clear(msgMpz);
        return false;
    }

    signature sig = signature_init();
    if (signature_set_str(sig, signatureR, signatureS, base) != 0) {
        spdlog::error("Failed to set str signature");
        mpz_clear(msgMpz);
        signature_free(sig);
        return false;
    }

    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);

    point publicKey = point_init();

    point_set_hex(publicKey, x.c_str(), y.c_str());
    if (!signature_verify(msgMpz, sig, publicKey, curve)) {
        spdlog::error("ECDSA sig not verified");
        mpz_clear(msgMpz);
        signature_free(sig);
        domain_parameters_clear(curve);
        point_clear(publicKey);
        return false;
    }

    mpz_clear(msgMpz);
    signature_free(sig);
    domain_parameters_clear(curve);
    point_clear(publicKey);

    return true;
}

vector <string> ecdsaSignHash(const std::string& encryptedKeyHex, const char *hashHex, int base) {

    CHECK_STATE(hashHex);

    vector <string> signatureVector(3);

    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    vector<uint8_t> encryptedKey(BUF_LEN, 0);
    uint8_t signatureV = 0;
    uint64_t decLen = 0;

    string pubKeyStr = "";

    if (!hex2carray(encryptedKeyHex.c_str(), &decLen, encryptedKey.data(),
                    BUF_LEN)) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    sgx_status_t status = SGX_SUCCESS;

    RESTART_BEGIN
        status = trustedEcdsaSign(eid, &errStatus,
                            errMsg.data(), encryptedKey.data(), decLen, hashHex,
                            signatureR.data(),
                            signatureS.data(), &signatureV, base);
    RESTART_END

    HANDLE_TRUSTED_FUNCTION_ERROR(status, errStatus, errMsg.data());


    signatureVector.at(0) = to_string(signatureV);

    if (base == 16) {
        signatureVector.at(1) = "0x" + string(signatureR.data());
        signatureVector.at(2) = "0x" + string(signatureS.data());
    } else {
        signatureVector.at(1) = string(signatureR.data());
        signatureVector.at(2) = string(signatureS.data());
    }

    /* Now verify signature */

    pubKeyStr = getECDSAPubKey(encryptedKeyHex);

    static uint64_t  i = 0;

    i++;

    if (i % 1000 == 0) {

        if (!verifyECDSASig(pubKeyStr, hashHex, signatureR.data(), signatureS.data(), base)) {
            spdlog::error("failed to verify ecdsa signature");
            throw SGXException(667, "ECDSA did not verify");
        }
    }

    return signatureVector;
}

string encryptECDSAKey(const string& _key) {
    vector<char> key(BUF_LEN, 0);
    for (size_t i = 0; i < _key.size(); ++i) {
        key[i] = _key[i];
    }

    vector<uint8_t> encryptedKey(BUF_LEN, 0);

    int errStatus = 0;
    vector<char> errString(BUF_LEN, 0);
    uint64_t enc_len = 0;

    sgx_status_t status = SGX_SUCCESS;
    RESTART_BEGIN
        status = trustedEncryptKey(eid, &errStatus, errString.data(), key.data(),
                                   encryptedKey.data(), &enc_len);
    RESTART_END

    if (status != 0) {
        throw SGXException(status, string("Could not encrypt ECDSA key: " + string(errString.begin(), errString.end())).c_str());
    }

    vector<char> hexEncrKey = carray2Hex(encryptedKey.data(), enc_len);

    return string(hexEncrKey.begin(), hexEncrKey.end());
}
