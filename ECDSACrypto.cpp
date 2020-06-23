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

#include "spdlog/spdlog.h"
#include "common.h"

#include "secure_enclave/Verify.h"

#include "BLSCrypto.h"

#include "ECDSACrypto.h"

void fillRandomBuffer(vector<unsigned char> &_buffer) {
    ifstream devRandom("/dev/urandom", ios::in | ios::binary);
    devRandom.exceptions(ifstream::failbit | ifstream::badbit);
    devRandom.read((char *) _buffer.data(), _buffer.size());
    devRandom.close();
}

vector <string> genECDSAKey() {
    vector<char> errMsg(1024, 0);
    int errStatus = 0;
    vector <uint8_t> encr_pr_key(1024, 0);
    vector<char> pub_key_x(1024, 0);
    vector<char> pub_key_y(1024, 0);

    uint32_t enc_len = 0;

    status = trustedGenerateEcdsaKeyAES(eid, &errStatus,
                                        errMsg.data(), encr_pr_key.data(), &enc_len,
                                        pub_key_x.data(), pub_key_y.data());

    if (status != SGX_SUCCESS || errStatus != 0) {
        spdlog::error("RPCException thrown with status {}", status);
        throw SGXException(status, errMsg.data());
    }
    vector <string> keys(3);

    vector<char> hexEncrKey(BUF_LEN * 2, 0);
    carray2Hex(encr_pr_key.data(), enc_len, hexEncrKey.data());
    keys.at(0) = hexEncrKey.data();
    keys.at(1) = string(pub_key_x.data()) + string(pub_key_y.data());

    vector<unsigned char> randBuffer(32, 0);
    fillRandomBuffer(randBuffer);

    vector<char> rand_str(64, 0);

    carray2Hex(randBuffer.data(), 32, rand_str.data());

    keys.at(2) = rand_str.data();

    CHECK_STATE(keys.at(2).size() == 64);

    return keys;
}

string getECDSAPubKey(const char *_encryptedKeyHex) {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    vector <uint8_t> encrPrKey(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t enc_len = 0;

    if (!hex2carray(_encryptedKeyHex, &enc_len, encrPrKey.data())) {
        throw SGXException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    status = trustedGetPublicEcdsaKeyAES(eid, &errStatus,
                                         errMsg.data(), encrPrKey.data(), enc_len, pubKeyX.data(), pubKeyY.data());

    if (errStatus != 0) {
        throw SGXException(-666, errMsg.data());
    }

    if (status != SGX_SUCCESS) {
        spdlog::error("failed to get ECDSA public key {}", status);
        throw SGXException(666, "failed to get ECDSA public key");
    }
    string pubKey = string(pubKeyX.data()) + string(pubKeyY.data());//concatPubKeyWith0x(pub_key_x, pub_key_y);//


    if (pubKey.size() != 128) {
        spdlog::error("Incorrect pub key size", status);
        throw SGXException(666, "Incorrect pub key size");
    }

    return pubKey;
}

bool verifyECDSASig(string& pubKeyStr, const char *hashHex, const char *signatureR,
        const char *signatureS, int base) {
    bool result = false;

    signature sig = signature_init();

    auto x = pubKeyStr.substr(0, 64);
    auto y = pubKeyStr.substr(64, 128);
    domain_parameters curve = domain_parameters_init();
    domain_parameters_load_curve(curve, secp256k1);
    point publicKey = point_init();

    mpz_t msgMpz;
    mpz_init(msgMpz);
    if (mpz_set_str(msgMpz, hashHex, 16) == -1) {
        spdlog::error("invalid message hash {}", hashHex);
        goto clean;
    }

    if (signature_set_str(sig, signatureR, signatureS, base) != 0) {
        spdlog::error("Failed to set str signature");
        goto clean;
    }

    point_set_hex(publicKey, x.c_str(), y.c_str());
    if (!signature_verify(msgMpz, sig, publicKey, curve)) {
        spdlog::error("ECDSA sig not verified");
        goto clean;
    }

    result = true;

    clean:

    mpz_clear(msgMpz);
    domain_parameters_clear(curve);
    point_clear(publicKey);
    signature_free(sig);

    return result;
}

vector <string> ecdsaSignHash(const char *encryptedKeyHex, const char *hashHex, int base) {
    vector <string> signatureVector(3);

    vector<char> errMsg(1024, 0);
    int errStatus = 0;
    vector<char> signatureR(1024, 0);
    vector<char> signatureS(1024, 0);
    vector<uint8_t> encryptedKey(1024, 0);
    uint8_t signatureV = 0;
    uint64_t decLen = 0;

    string pubKeyStr = "";

    shared_ptr<SGXException> exception = NULL;

    if (!hex2carray(encryptedKeyHex, &decLen, encryptedKey.data())) {
        exception = make_shared<SGXException>(INVALID_HEX, "Invalid encryptedKeyHex");
        goto clean;
    }

    pubKeyStr = getECDSAPubKey(encryptedKeyHex);

    status = trustedEcdsaSignAES(eid, &errStatus,
            errMsg.data(), encryptedKey.data(), decLen, (unsigned char *) hashHex,
                                 signatureR.data(),
                                 signatureS.data(), &signatureV, base);

    if (errStatus != 0) {
        exception = make_shared<SGXException>(666, errMsg.data());
        goto clean;
    }

    if (status != SGX_SUCCESS) {
        spdlog::error("failed to sign {}", status);
        exception = make_shared<SGXException>(666, "failed to sign");
        goto clean;
    }
    signatureVector.at(0) = to_string(signatureV);
    if (base == 16) {
        signatureVector.at(1) = "0x" + string(signatureR.data());
        signatureVector.at(2) = "0x" + string(signatureS.data());
    } else {
        signatureVector.at(1) = string(signatureR.data());
        signatureVector.at(2) = string(signatureS.data());
    }

    /* Now verify signature */

    if (!verifyECDSASig(pubKeyStr, hashHex, signatureR.data(), signatureS.data(), base)) {
        exception = make_shared<SGXException>(667, "ECDSA did not verify");
        goto clean;
    }

    clean:

    if (exception)
        throw *exception;

    return signatureVector;
}
