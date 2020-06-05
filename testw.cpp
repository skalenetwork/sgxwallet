/*

Modifications Copyright (C) 2019 SKALE Labs

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>
#include <stdio.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <sgx_tcrypto.h>

#include "BLSCrypto.h"
#include "ServerInit.h"
#include "DKGCrypto.h"
#include "SGXException.h"
#include "LevelDB.h"
#include "SGXWalletServer.hpp"


#define CATCH_CONFIG_MAIN

#include "catch.hpp"
#include "stubclient.h"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "BLSPublicKeyShare.h"
#include "BLSPublicKey.h"
#include "SEKManager.h"
#include <thread>
#include "common.h"
#include "stubclient.h"
#include "SGXRegistrationServer.h"
#include "SGXWalletServer.h"
#include "testw.h"


using namespace jsonrpc;
using namespace std;


default_random_engine randGen((unsigned int) time(0));

string stringFromFr(libff::alt_bn128_Fr &el) {
    mpz_t t;
    mpz_init(t);
    el.as_bigint().to_mpz(t);
    char arr[mpz_sizeinbase(t, 10) + 2];
    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return string(tmp);
}


string convertDecToHex(string dec, int numBytes = 32) {
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, dec.c_str(), 10);

    vector<char> tmp(mpz_sizeinbase(num, 16) + 2, 0);
    char *hex = mpz_get_str(tmp.data(), 16, num);

    string result = hex;
    int n_zeroes = numBytes * 2 - result.length();
    result.insert(0, n_zeroes, '0');

    return result;
}


sgx_launch_token_t token = {0};
sgx_enclave_id_t eid = 0;
sgx_status_t status;
int updated;


void resetDB() {
    REQUIRE(system("bash -c \"rm -rf " SGXDATA_FOLDER "* \"") == 0);
}

shared_ptr <string> encryptTestKey() {
    const char *key = TEST_BLS_KEY_SHARE;
    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);;
    char *encryptedKeyHex = encryptBLSKeyShare2Hex(&errStatus, errMsg.data(), key);

    REQUIRE(encryptedKeyHex != nullptr);
    REQUIRE(errStatus == 0);

    return make_shared<string>(encryptedKeyHex);
}


vector <libff::alt_bn128_Fr> splitStringToFr(const char *coeffs, const char symbol) {
    string str(coeffs);
    string delim;
    delim.push_back(symbol);
    vector <libff::alt_bn128_Fr> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            libff::alt_bn128_Fr coeff(token.c_str());
            tokens.push_back(coeff);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return tokens;
}

vector <string> splitStringTest(const char *coeffs, const char symbol) {
    string str(coeffs);
    string delim;
    delim.push_back(symbol);
    vector <string> g2Strings;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            string coeff(token.c_str());
            g2Strings.push_back(coeff);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return g2Strings;
}

libff::alt_bn128_G2 vectStringToG2(const vector <string> &G2_str_vect) {
    libff::alt_bn128_G2 coeff = libff::alt_bn128_G2::zero();
    coeff.X.c0 = libff::alt_bn128_Fq(G2_str_vect.at(0).c_str());
    coeff.X.c1 = libff::alt_bn128_Fq(G2_str_vect.at(1).c_str());
    coeff.Y.c0 = libff::alt_bn128_Fq(G2_str_vect.at(2).c_str());
    coeff.Y.c1 = libff::alt_bn128_Fq(G2_str_vect.at(3).c_str());
    coeff.Z.c0 = libff::alt_bn128_Fq::one();
    coeff.Z.c1 = libff::alt_bn128_Fq::zero();

    return coeff;
}

void sendRPCRequest() {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    int n = 16, t = 16;
    Json::Value ethKeys[n];
    Json::Value verifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector <string> pubShares(n);
    vector <string> polyNames(n);

    int schainID = randGen();
    int dkgID = randGen();
    for (uint8_t i = 0; i < n; i++) {
        ethKeys[i] = c.generateECDSAKey();
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        c.generateDKGPoly(polyName, t);
        polyNames[i] = polyName;
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(verifVects[i]["status"] == 0);

        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        for (uint8_t k = 0; k < t; k++) {
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["Verification Vector"][k][j].asString();
                pubShares[i] += convertDecToHex(pubShare);
            }
        }
    }

    int k = 0;

    vector <string> secShares(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            Json::Value verif = c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);

            k++;
        }

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t,
    32 >> ();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        string secretShare = secretShares[i]["secretShare"].asString();

        c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t, n);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        REQUIRE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));
    }

    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
}

void destroyEnclave() {
    if (eid != 0) {
        sgx_destroy_enclave(eid);
        eid = 0;
    }
}

class TestFixture {
public:
    TestFixture() {
        resetDB();
        setOptions(false, false, false, true);
        initAll(0, false, true);
    }

    ~TestFixture() {
        destroyEnclave();
    }
};

class TestFixtureHTTPS {
public:
    TestFixtureHTTPS() {
        resetDB();
        setOptions(false, false, true, true);
        initAll(0, false, true);
    }

    ~TestFixtureHTTPS() {
        destroyEnclave();
    }
};

TEST_CASE_METHOD(TestFixture, "ECDSA keygen and signature test", "[ecdsa-key-sig-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);

    uint32_t encLen = 0;
    status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen, pubKeyX.data(),
                                     pubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);


    string hex = SAMPLE_HEX_HASH;
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    uint8_t signatureV = 0;

    status = trustedEcdsaSign(eid, &errStatus, errMsg.data(), encrPrivKey.data(), encLen, (unsigned char *) hex.data(),
                              signatureR.data(),
                              signatureS.data(), &signatureV, 16);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES keygen and signature test", "[ecdsa-aes-key-sig-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);

    uint32_t encLen = 0;
    status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen, pubKeyX.data(),
                                     pubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);


    string hex = SAMPLE_HEX_HASH;
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    uint8_t signatureV = 0;

    status = trustedEcdsaSignAES(eid, &errStatus, errMsg.data(), encrPrivKey.data(), encLen, (unsigned char *) hex.data(),
                              signatureR.data(),
                              signatureS.data(), &signatureV, 16);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA key gen", "[ecdsa-key-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;
    status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen, pubKeyX.data(),
                                     pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES key gen", "[ecdsa-aes-key-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;
    status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen, pubKeyX.data(),
                                     pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA get public key", "[ecdsa-get-pub-key]") {
    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    vector <uint8_t> encPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;

    status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), encPrivKey.data(), &encLen, pubKeyX.data(),
                                     pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> receivedPubKeyX(BUF_LEN, 0);
    vector<char> receivedPubKeyY(BUF_LEN, 0);

    status = trustedGetPublicEcdsaKey(eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen, receivedPubKeyX.data(),
                                      receivedPubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "ECDSA AES get public key", "[ecdsa-aes-get-pub-key]") {
    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    vector <uint8_t> encPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint32_t encLen = 0;

    status = trustedGenerateEcdsaKeyAES(eid, &errStatus, errMsg.data(), encPrivKey.data(), &encLen, pubKeyX.data(),
                                     pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> receivedPubKeyX(BUF_LEN, 0);
    vector<char> receivedPubKeyY(BUF_LEN, 0);

    status = trustedGetPublicEcdsaKeyAES(eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen, receivedPubKeyX.data(),
                                      receivedPubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}



/* Do later
TEST_CASE_METHOD("BLS key encrypt/decrypt", "[bls-key-encrypt-decrypt]") {
    resetDB();
    setOptions(false, false, false, true);
    initAll(0, false, true);

    //init_enclave();

    int errStatus = -1;

    vector<char> errMsg(BUF_LEN, 0);

    char *encryptedKey = encryptTestKey();
    REQUIRE(encryptedKey != nullptr);
    char *plaintextKey = decryptBLSKeyShareFromHex(&errStatus, errMsg.data(), encryptedKey);
    free(encryptedKey);

    REQUIRE(errStatus == 0);
    REQUIRE(strcmp(plaintextKey, TEST_BLS_KEY_SHARE) == 0);

    printf("Decrypt key completed with status: %d %s \n", errStatus, errMsg.data());
    printf("Decrypted key len %d\n", (int) strlen(plaintextKey));
    printf("Decrypted key: %s\n", plaintextKey);
    free(plaintextKey);



}

*/


TEST_CASE_METHOD(TestFixture, "ECDSA key gen API", "[ecdsa-key-gen-api]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    for (int i = 0; i <= 20; i++) {
        try {
            Json::Value genKey = c.generateECDSAKey();
            REQUIRE(genKey["status"].asInt() == 0);

            auto keyName = genKey["keyName"].asString();

            REQUIRE(keyName.size() == 68);

            Json::Value sig = c.ecdsaSignMessageHash(16, genKey["keyName"].asString(), SAMPLE_HASH);
            REQUIRE(sig["status"].asInt() == 0);
            Json::Value getPubKey = c.getPublicECDSAKey(genKey["keyName"].asString());
            REQUIRE(getPubKey["status"].asInt() == 0);
        } catch (JsonRpcException &e) {
            cerr << e.what() << endl;
            throw;
        }
    }
}

TEST_CASE_METHOD(TestFixture, "BLS key encrypt", "[bls-key-encrypt]") {
    auto key = encryptTestKey();
    REQUIRE(key != nullptr);
}

TEST_CASE_METHOD(TestFixture, "DKG gen test", "[dkg-gen]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 32);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> secret(BUF_LEN, 0);
    vector<char> errMsg1(BUF_LEN, 0);

    uint32_t dec_len;
    status = trustedDecryptDkgSecret(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(),
                                     (uint8_t *) secret.data(), &dec_len);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "DKG AES gen test", "[dkg-aes-gen]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    status = trustedGenDkgSecretAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 32);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> secret(2490, 0);
    vector<char> errMsg1(BUF_LEN, 0);

    status = trustedDecryptDkgSecretAES(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(),
                                     (uint8_t *) secret.data(), &encLen);

    REQUIRE( status == SGX_SUCCESS);
    for (auto& elem : errMsg1) {
        std::cout << elem;
    }
    REQUIRE( errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "DKG public shares test", "[dkg-pub-shares]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    unsigned t = 32, n = 32;

    status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, n);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    vector<char> errMsg1(BUF_LEN, 0);

    char colon = ':';
    vector<char> pubShares(10000, 0);

    status = trustedGetPublicShares(eid, &errStatus, errMsg1.data(),
                                    encryptedDKGSecret.data(), encLen, pubShares.data(), t, n);

    vector <string> g2Strings = splitString(pubShares.data(), ',');
    vector <libff::alt_bn128_G2> pubSharesG2;
    for (u_int64_t i = 0; i < g2Strings.size(); i++) {
        vector <string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');

        pubSharesG2.push_back(vectStringToG2(coeffStr));
    }

    vector<char> secret(BUF_LEN, 0);

    status = trustedDecryptDkgSecret(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(),
                                     (uint8_t *) secret.data(), &encLen);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    signatures::Dkg dkgObj(t, n);

    vector <libff::alt_bn128_Fr> poly = splitStringToFr(secret.data(), colon);
    vector <libff::alt_bn128_G2> pubSharesDkg = dkgObj.VerificationVector(poly);
    for (uint32_t i = 0; i < pubSharesDkg.size(); i++) {
        libff::alt_bn128_G2 el = pubSharesDkg.at(i);
        el.to_affine_coordinates();
        libff::alt_bn128_Fq x_c0_el = el.X.c0;
        mpz_t x_c0;
        mpz_init(x_c0);
        x_c0_el.as_bigint().to_mpz(x_c0);

        mpz_clear(x_c0);
    }
    REQUIRE(pubSharesG2 == pubSharesDkg);
}

TEST_CASE_METHOD(TestFixture, "DKG AES public shares test", "[dkg-aes-pub-shares]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    unsigned t = 32, n = 32;

    status = trustedGenDkgSecretAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, n);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    vector<char> errMsg1(BUF_LEN, 0);

    char colon = ':';
    vector<char> pubShares(10000, 0);

    status = trustedGetPublicSharesAES(eid, &errStatus, errMsg1.data(),
                                    encryptedDKGSecret.data(), encLen, pubShares.data(), t, n);

    vector <string> g2Strings = splitString(pubShares.data(), ',');
    vector <libff::alt_bn128_G2> pubSharesG2;
    for (u_int64_t i = 0; i < g2Strings.size(); i++) {
        vector <string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');

        pubSharesG2.push_back(vectStringToG2(coeffStr));
    }

    vector<char> secret(BUF_LEN, 0);

    status = trustedDecryptDkgSecretAES(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(),
                                     (uint8_t *) secret.data(), &encLen);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    signatures::Dkg dkgObj(t, n);

    vector <libff::alt_bn128_Fr> poly = splitStringToFr(secret.data(), colon);
    vector <libff::alt_bn128_G2> pubSharesDkg = dkgObj.VerificationVector(poly);
    for (uint32_t i = 0; i < pubSharesDkg.size(); i++) {
        libff::alt_bn128_G2 el = pubSharesDkg.at(i);
        el.to_affine_coordinates();
        libff::alt_bn128_Fq x_c0_el = el.X.c0;
        mpz_t x_c0;
        mpz_init(x_c0);
        x_c0_el.as_bigint().to_mpz(x_c0);

        mpz_clear(x_c0);
    }
    REQUIRE(pubSharesG2 == pubSharesDkg);
}

TEST_CASE_METHOD(TestFixture, "DKG encrypted secret shares test", "[dkg-encr-sshares]") {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 2);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );


    status = trustedSetEncryptedDkgPoly(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    vector <uint8_t> encrPRDHKey(BUF_LEN, 0);

    string pub_keyB = SAMPLE_PUBLIC_KEY_B;

    vector<char> s_shareG2(BUF_LEN, 0);
    status = trustedGetEncryptedSecretShare(eid, &errStatus, errMsg.data(), encrPRDHKey.data(), &encLen, result.data(),
                                            s_shareG2.data(),
                                            (char *) pub_keyB.data(), 2, 2, 1);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares test", "[dkg-aes-encr-sshares]") {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int errStatus = 0;
    uint32_t encLen = 0;

    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    status = trustedGenDkgSecretAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 2);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    uint64_t enc_len = encLen;

    status = trustedSetEncryptedDkgPolyAES(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &enc_len);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );

    vector <uint8_t> encrPRDHKey(BUF_LEN, 0);

    string pub_keyB = SAMPLE_PUBLIC_KEY_B;

    vector<char> s_shareG2(BUF_LEN, 0);
    status = trustedGetEncryptedSecretShareAES(eid, &errStatus, errMsg.data(), encrPRDHKey.data(), &encLen, result.data(),
                                            s_shareG2.data(),
                                            (char *) pub_keyB.data(), 2, 2, 1);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE( errStatus == SGX_SUCCESS );
}




/*
 * ( "verification test", "[verify]" ) {


    char*  pubshares = "0d72c21fc5a43452ad5f36699822309149ce6ce2cdce50dafa896e873f1b8ddd12f65a2e9c39c617a1f695f076b33b236b47ed773901fc2762f8b6f63277f5e30d7080be8e98c97f913d1920357f345dc0916c1fcb002b7beb060aa8b6b473a011bfafe9f8a5d8ea4c643ca4101e5119adbef5ae64f8dfb39cd10f1e69e31c591858d7eaca25b4c412fe909ca87ca7aadbf6d97d32d9b984e93d436f13d43ec31f40432cc750a64ac239cad6b8f78c1f1dd37427e4ff8c1cc4fe1c950fcbcec10ebfd79e0c19d0587adafe6db4f3c63ea9a329724a8804b63a9422e6898c0923209e828facf3a073254ec31af4231d999ba04eb5b7d1e0056d742a65b766f2f3";
    char *sec_share = "11592366544581417165283270001305852351194685098958224535357729125789505948557";
    mpz_t sshare;
    mpz_init(sshare);
    mpz_set_str(sshare, "11592366544581417165283270001305852351194685098958224535357729125789505948557", 10);
    int result = Verification(pubshares, sshare, 2, 0);
    REQUIRE(result == 1);


}*/





TEST_CASE_METHOD(TestFixture, "DKG_BLS test", "[dkg-bls]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    int n = 16, t = 16;
    Json::Value etnKeys[n];
    Json::Value verifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector <string> pubShares(n);
    vector <string> polyNames(n);

    int schainID = randGen();
    int dkgID = randGen();
    for (uint8_t i = 0; i < n; i++) {
        etnKeys[i] = c.generateECDSAKey();
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);

        c.generateDKGPoly(polyName, t);
        polyNames[i] = polyName;
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(verifVects[i]["status"] == 0);
        pubEthKeys.append(etnKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        cout << secretShares[i] << endl;
        REQUIRE(secretShares[i]["status"] == 0);
        for (uint8_t k = 0; k < t; k++) {
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["verificationVector"][k][j].asString();
                REQUIRE(pubShare.length() > 60);
                pubShares[i] += convertDecToHex(pubShare);
            }
        }
    }


    int k = 0;

    vector <string> secShares(n);

    vector <string> pSharesBad(pubShares);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            bool res = c.dkgVerification(pubShares[i], etnKeys[j]["keyName"].asString(), secretShare, t, n,
                                         j)["result"].asBool();
            k++;

            REQUIRE(res);

            pSharesBad[i][0] = 'q';
            Json::Value wrongVerif = c.dkgVerification(pSharesBad[i], etnKeys[j]["keyName"].asString(), secretShare, t,
                                                       n, j);
            res = wrongVerif["result"].asBool();
            REQUIRE(!res);
        }

    BLSSigShareSet sigShareSet(t, n);


    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t,
    32 >> ();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }


    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffsPubKeysMap;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        string secretShare = secretShares[i]["secretShare"].asString();

        c.createBLSPrivateKey(blsName, etnKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t, n);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector <string> pubKeyVect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared < vector < string >> (pubKeyVect), t, n);
        REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        coeffsPubKeysMap[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);
    }


    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey common_public(make_shared < map < size_t, shared_ptr < BLSPublicKeyShare >> > (coeffsPubKeysMap), t,
                               n);
    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));
}

TEST_CASE_METHOD(TestFixture, "Get ServerStatus", "[get-server-status]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    REQUIRE(c.getServerStatus()["status"] == 0);
}

TEST_CASE_METHOD(TestFixture, "Get ServerVersion", "[get-server-version]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    REQUIRE(c.getServerVersion()["version"] == SGXWalletServer::getVersion());
}

TEST_CASE_METHOD(TestFixtureHTTPS, "Cert request sign", "[cert-sign]") {
    REQUIRE(SGXRegistrationServer::getServer() != nullptr);

    string csrFile = "insecure-samples/yourdomain.csr";

    ifstream infile(csrFile);
    infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    ostringstream ss;
    ss << infile.rdbuf();
    infile.close();

    auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());

    REQUIRE(result["status"] == 0);

    result = SGXRegistrationServer::getServer()->SignCertificate("Haha");

    REQUIRE(result["status"] != 0);
}

TEST_CASE_METHOD(TestFixture, "DKG API test", "[dkg-api]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;

    Json::Value genPoly = c.generateDKGPoly(polyName, 2);

    Json::Value publicKeys;
    publicKeys.append(SAMPLE_DKG_PUB_KEY_1);
    publicKeys.append(SAMPLE_DKG_PUB_KEY_2);

    // wrongName
    Json::Value genPolyWrongName = c.generateDKGPoly("poly", 2);
    REQUIRE(genPolyWrongName["status"].asInt() != 0);

    Json::Value verifVectWrongName = c.getVerificationVector("poly", 2, 2);
    REQUIRE(verifVectWrongName["status"].asInt() != 0);

    Json::Value secretSharesWrongName = c.getSecretShare("poly", publicKeys, 2, 2);
    REQUIRE(secretSharesWrongName["status"].asInt() != 0);

    // wrong_t
    Json::Value genPolyWrong_t = c.generateDKGPoly(polyName, 33);
    REQUIRE(genPolyWrong_t["status"].asInt() != 0);

    Json::Value verifVectWrong_t = c.getVerificationVector(polyName, 1, 2);
    REQUIRE(verifVectWrong_t["status"].asInt() != 0);

    Json::Value secretSharesWrong_t = c.getSecretShare(polyName, publicKeys, 3, 3);
    REQUIRE(secretSharesWrong_t["status"].asInt() != 0);

    // wrong_n
    Json::Value verifVectWrong_n = c.getVerificationVector(polyName, 2, 1);
    REQUIRE(verifVectWrong_n["status"].asInt() != 0);

    Json::Value publicKeys1;
    publicKeys1.append(SAMPLE_DKG_PUB_KEY_1);
    Json::Value secretSharesWrong_n = c.getSecretShare(polyName, publicKeys1, 2, 1);
    REQUIRE(secretSharesWrong_n["status"].asInt() != 0);

    //wrong number of publicKeys
    Json::Value secretSharesWrongPkeys = c.getSecretShare(polyName, publicKeys, 2, 3);
    REQUIRE(secretSharesWrongPkeys["status"].asInt() != 0);

    //wrong verif
    Json::Value Skeys = c.getSecretShare(polyName, publicKeys, 2, 2);
    Json::Value verifVect = c.getVerificationVector(polyName, 2, 2);
    Json::Value verificationWrongSkeys = c.dkgVerification("", "", "", 2, 2, 1);
    REQUIRE(verificationWrongSkeys["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixture, "PolyExists test", "[dkg-poly-exists]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;
    Json::Value genPoly = c.generateDKGPoly(polyName, 2);

    Json::Value polyExists = c.isPolyExists(polyName);

    REQUIRE(polyExists["IsExist"].asBool());

    Json::Value polyDoesNotExist = c.isPolyExists("Vasya");

    REQUIRE(!polyDoesNotExist["IsExist"].asBool());
}

TEST_CASE_METHOD(TestFixture, "AES_DKG test", "[aes-dkg]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    int n = 2, t = 2;
    Json::Value ethKeys[n];
    Json::Value verifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector <string> pubShares(n);
    vector <string> polyNames(n);

    int schainID = randGen();
    int dkgID = randGen();
    for (uint8_t i = 0; i < n; i++) {
        ethKeys[i] = c.generateECDSAKey();
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        REQUIRE(ethKeys[i]["status"] == 0);
        c.generateDKGPoly(polyName, t);
        polyNames[i] = polyName;
        verifVects[i] = c.getVerificationVector(polyName, t, n);

        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);

        REQUIRE(secretShares[i]["status"] == 0);
        for (uint8_t k = 0; k < t; k++)
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["verificationVector"][k][j].asString();
                pubShares[i] += convertDecToHex(pubShare);
            }
    }

    int k = 0;
    vector <string> secShares(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            Json::Value verif = c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
            bool res = verif["result"].asBool();
            k++;
            REQUIRE(res);
        }

    Json::Value complaintResponse = c.complaintResponse(polyNames[1], 0);

    REQUIRE(complaintResponse["status"] == 0);

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t, 32 >> ();

    uint64_t binLen;

    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t, n);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);

        REQUIRE(pubBLSKeys[i]["status"] == 0);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);

        REQUIRE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector <string> pubKey_vect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared < vector < string >> (pubKey_vect), t, n);
        REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        coeffs_pkeys_map[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);
    }

    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey common_public(make_shared < map < size_t, shared_ptr < BLSPublicKeyShare >> > (coeffs_pkeys_map), t,
                               n);
    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));
}

TEST_CASE_METHOD(TestFixture, "AES encrypt/decrypt", "[aes-encrypt-decrypt]") {
    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);
    uint32_t encLen;
    string key = SAMPLE_AES_KEY;
    vector <uint8_t> encrypted_key(BUF_LEN, 0);

    status = trustedEncryptKeyAES(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key.data(), &encLen);

    REQUIRE(status == 0);
    REQUIRE( errStatus == 0 );


    vector<char> decr_key(BUF_LEN, 0);
    status = trustedDecryptKeyAES(eid, &errStatus, errMsg.data(), encrypted_key.data(), encLen, decr_key.data());

    REQUIRE(status == 0);
    REQUIRE( errStatus == 0 );
    REQUIRE(key.compare(decr_key.data()) == 0);

}

TEST_CASE_METHOD(TestFixture, "SGX encrypt/decrypt", "[sgx-encrypt-decrypt]") {
    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);
    uint32_t encLen;
    string key = SAMPLE_AES_KEY;
    vector <uint8_t> encrypted_key(BUF_LEN, 0);

    status = trustedEncryptKey(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key.data(), &encLen);

    REQUIRE(status == 0);
    REQUIRE( errStatus == 0 );


    vector<char> decr_key(BUF_LEN, 0);
    status = trustedDecryptKey(eid, &errStatus, errMsg.data(), encrypted_key.data(), encLen, decr_key.data());

    REQUIRE(status == 0);
    REQUIRE( errStatus == 0 );
    REQUIRE(key.compare(decr_key.data()) == 0);
}

TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg bls", "[many-threads-crypto]") {
    vector <thread> threads;
    int num_threads = 4;
    for (int i = 0; i < num_threads; i++) {
        threads.push_back(thread(sendRPCRequest));
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_CASE_METHOD(TestFixture, "AES == NOT AES", "[aes-not-aes]") {
    std::string key = SAMPLE_AES_KEY;
    std::string hex = SAMPLE_HEX_HASH;

    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    uint32_t enc_len = 0;
    trustedEncryptKey(eid, &errStatus, errMsg.data(), key.c_str(), encrPrivKey.data(), &enc_len);
    REQUIRE(errStatus == SGX_SUCCESS);

    errMsg.clear();
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    uint8_t signatureV = 0;

    status = trustedEcdsaSign(eid, &errStatus, errMsg.data(), encrPrivKey.data(), enc_len, (unsigned char *) hex.data(),
                              signatureR.data(),
                              signatureS.data(), &signatureV, 16);
    REQUIRE( status == SGX_SUCCESS );
    REQUIRE( errStatus == SGX_SUCCESS );

    errMsg.clear();
    vector<char> receivedPubKeyX(BUF_LEN, 0);
    vector<char> receivedPubKeyY(BUF_LEN, 0);
    status = trustedGetPublicEcdsaKey(eid, &errStatus, errMsg.data(), encrPrivKey.data(), enc_len, receivedPubKeyX.data(),
                                      receivedPubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    int errStatusAES = 0;
    vector<char> errMsgAES(BUF_LEN, 0);
    vector <uint8_t> encrPrivKeyAES(BUF_LEN, 0);
    uint32_t enc_lenAES = 0;
    trustedEncryptKeyAES(eid, &errStatusAES, errMsgAES.data(), key.c_str(), encrPrivKeyAES.data(), &enc_lenAES);
    REQUIRE( errStatusAES == SGX_SUCCESS );

    errMsgAES.clear();
    vector<char> signatureRAES(BUF_LEN, 0);
    vector<char> signatureSAES(BUF_LEN, 0);
    uint8_t signatureVAES = 0;

    status = trustedEcdsaSignAES(eid, &errStatusAES, errMsgAES.data(), encrPrivKeyAES.data(), enc_lenAES, (unsigned char *) hex.data(),
                              signatureRAES.data(),
                              signatureSAES.data(), &signatureVAES, 16);
    REQUIRE( status == SGX_SUCCESS );
    REQUIRE( errStatusAES == SGX_SUCCESS );

    errMsgAES.clear();
    vector<char> receivedPubKeyXAES(BUF_LEN, 0);
    vector<char> receivedPubKeyYAES(BUF_LEN, 0);
    status = trustedGetPublicEcdsaKeyAES(eid, &errStatusAES, errMsgAES.data(), encrPrivKeyAES.data(), enc_lenAES, receivedPubKeyXAES.data(),
                                      receivedPubKeyYAES.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatusAES == SGX_SUCCESS);

    REQUIRE( receivedPubKeyX == receivedPubKeyXAES );
    REQUIRE( receivedPubKeyY == receivedPubKeyYAES );
}
