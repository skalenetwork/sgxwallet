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
#include "sgxwallet.h"
#include "testw.h"
#include "TestUtils.h"


using namespace jsonrpc;
using namespace std;


default_random_engine TestUtils::randGen((unsigned int) time(0));

string TestUtils::stringFromFr(libff::alt_bn128_Fr &el) {
    mpz_t t;
    mpz_init(t);
    el.as_bigint().to_mpz(t);
    char arr[mpz_sizeinbase(t, 10) + 2];
    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return string(tmp);
}


string TestUtils::convertDecToHex(string dec, int numBytes) {
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




void TestUtils::resetDB() {
    CHECK_STATE(system("bash -c \"rm -rf " SGXDATA_FOLDER "* \"") == 0);
}

shared_ptr <string> TestUtils::encryptTestKey() {
    const char *key = TEST_BLS_KEY_SHARE;
    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);;
    char *encryptedKeyHex = encryptBLSKeyShare2Hex(&errStatus, errMsg.data(), key);

    CHECK_STATE(encryptedKeyHex != nullptr);
    CHECK_STATE(errStatus == 0);

    return make_shared<string>(encryptedKeyHex);
}


vector <libff::alt_bn128_Fr> TestUtils::splitStringToFr(const char *coeffs, const char symbol) {
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

vector <string> TestUtils::splitStringTest(const char *coeffs, const char symbol) {
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

libff::alt_bn128_G2 TestUtils::vectStringToG2(const vector <string> &G2_str_vect) {
    libff::alt_bn128_G2 coeff = libff::alt_bn128_G2::zero();
    coeff.X.c0 = libff::alt_bn128_Fq(G2_str_vect.at(0).c_str());
    coeff.X.c1 = libff::alt_bn128_Fq(G2_str_vect.at(1).c_str());
    coeff.Y.c0 = libff::alt_bn128_Fq(G2_str_vect.at(2).c_str());
    coeff.Y.c1 = libff::alt_bn128_Fq(G2_str_vect.at(3).c_str());
    coeff.Z.c0 = libff::alt_bn128_Fq::one();
    coeff.Z.c1 = libff::alt_bn128_Fq::zero();

    return coeff;
}

void TestUtils::sendRPCRequest() {
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
        CHECK_STATE(ethKeys[i]["status"] == 0);
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        auto response = c.generateDKGPoly(polyName, t);
        CHECK_STATE(response["status"] == 0);
        polyNames[i] = polyName;
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        CHECK_STATE(verifVects[i]["status"] == 0);

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
            CHECK_STATE(verif["status"] == 0);

            k++;
        }

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
        string secretShare = secretShares[i]["secretShare"].asString();

        auto response = c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t, n);
        CHECK_STATE(response["status"] == 0);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        CHECK_STATE(pubBLSKeys[i]["status"] == 0);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        CHECK_STATE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));
    }

    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
}

void TestUtils::destroyEnclave() {
    if (eid != 0) {
        sgx_destroy_enclave(eid);
        eid = 0;
    }
}

