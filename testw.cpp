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

    @file testw.cpp
    @author Stan Kladko
    @date 2020
*/

#include <dkg/dkg.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <dkg/dkg.h>
#include "sgxwallet_common.h"
#include "third_party/intel/create_enclave.h"
#include "secure_enclave_u.h"
#include "secure_enclave/DHDkg.h"
#include "third_party/intel/sgx_detect.h"
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

#include "SGXRegistrationServer.h"
#include "SGXWalletServer.h"
#include "ZMQClient.h"
#include "sgxwallet.h"
#include "TestUtils.h"
#include "testw.h"

#define PRINT_SRC_LINE cerr << "Executing line " <<  to_string(__LINE__) << endl;


using namespace jsonrpc;
using namespace std;

class TestFixture {
public:
    TestFixture() {
        TestUtils::resetDB();
        setOptions(L_INFO, false, true);
        initAll(L_INFO, false, true, false);
    }

    ~TestFixture() {
        exitZMQServer();
        TestUtils::destroyEnclave();
    }
};

class TestFixtureHTTPS {
public:
    TestFixtureHTTPS() {
        TestUtils::resetDB();
        setOptions(L_INFO, true, true);
        initAll(L_INFO, false, true, false);
    }

    ~TestFixtureHTTPS() {
        exitZMQServer();
        TestUtils::destroyEnclave();
    }
};

class TestFixtureNoResetFromBackup {
public:
    TestFixtureNoResetFromBackup() {
        setFullOptions(L_INFO, false, true, true);
        initAll(L_INFO, false, true, false);
    }

    ~TestFixtureNoResetFromBackup() {
        exitZMQServer();
        TestUtils::destroyEnclave();
    }
};


class TestFixtureNoReset {
public:
    TestFixtureNoReset() {
        setOptions(L_INFO, false, true);
        initAll(L_INFO, false, true, false);
    }

    ~TestFixtureNoReset() {
        exitZMQServer();
        TestUtils::destroyEnclave();
    }
};

TEST_CASE_METHOD(TestFixture, "ECDSA AES keygen and signature test", "[ecdsa-aes-key-sig-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);

    uint64_t encLen = 0;
    PRINT_SRC_LINE
    auto status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen,
                                          pubKeyX.data(),
                                          pubKeyY.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    string hex = SAMPLE_HEX_HASH;
    vector<char> signatureR(BUF_LEN, 0);
    vector<char> signatureS(BUF_LEN, 0);
    uint8_t signatureV = 0;


    for (int i = 0; i < 50; i++) {
        PRINT_SRC_LINE
        status = trustedEcdsaSign(eid, &errStatus, errMsg.data(), encrPrivKey.data(), encLen,
                                  hex.data(),
                                  signatureR.data(),
                                  signatureS.data(), &signatureV, 16);
        REQUIRE(status == SGX_SUCCESS);
        REQUIRE(errStatus == SGX_SUCCESS);
    }

}


TEST_CASE_METHOD(TestFixture, "ECDSA AES key gen", "[ecdsa-aes-key-gen]") {
    vector<char> errMsg(BUF_LEN, 0);
    int errStatus = 0;
    vector <uint8_t> encrPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);
    uint64_t encLen = 0;
    PRINT_SRC_LINE
    auto status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), encrPrivKey.data(), &encLen,
                                          pubKeyX.data(),
                                          pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}


TEST_CASE_METHOD(TestFixture, "ECDSA AES get public key", "[ecdsa-aes-get-pub-key]") {
    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    vector <uint8_t> encPrivKey(BUF_LEN, 0);
    vector<char> pubKeyX(BUF_LEN, 0);
    vector<char> pubKeyY(BUF_LEN, 0);

    uint64_t encLen = 0;

    PRINT_SRC_LINE
    auto status = trustedGenerateEcdsaKey(eid, &errStatus, errMsg.data(), encPrivKey.data(), &encLen, pubKeyX.data(),
                                          pubKeyY.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> receivedPubKeyX(BUF_LEN, 0);
    vector<char> receivedPubKeyY(BUF_LEN, 0);

    PRINT_SRC_LINE
    status = trustedGetPublicEcdsaKey(eid, &errStatus, errMsg.data(), encPrivKey.data(), encLen,
                                      receivedPubKeyX.data(),
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

    char *encryptedKey = TestUtils::encryptTestKey();
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


string genECDSAKeyAPI(StubClient &_c) {
    Json::Value genKey = _c.generateECDSAKey();
    CHECK_STATE(genKey["status"].asInt() == 0);
    auto keyName = genKey["keyName"].asString();
    CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);
    return keyName;
}

TEST_CASE_METHOD(TestFixture, "ECDSA key gen API", "[ecdsa-key-gen-api]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    for (int i = 0; i <= 20; i++) {
        try {
            PRINT_SRC_LINE
            auto keyName = genECDSAKeyAPI(c);
            PRINT_SRC_LINE
            Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
            REQUIRE(sig["status"].asInt() == 0);
            Json::Value getPubKey = c.getPublicECDSAKey(keyName);
            REQUIRE(getPubKey["status"].asInt() == 0);
        } catch (JsonRpcException &e) {
            cerr << e.what() << endl;
            throw;
        }
    }

    auto keyName = genECDSAKeyAPI(c);


    Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);


    for (int i = 0; i <= 20; i++) {
        try {
            PRINT_SRC_LINE
            auto keyName = genECDSAKeyAPI(c);
            PRINT_SRC_LINE
            Json::Value sig = c.ecdsaSignMessageHash(10, keyName, SAMPLE_HASH);
            REQUIRE(sig["status"].asInt() == 0);
            PRINT_SRC_LINE
            Json::Value getPubKey = c.getPublicECDSAKey(keyName);
            REQUIRE(getPubKey["status"].asInt() == 0);
        } catch (JsonRpcException &e) {
            cerr << e.what() << endl;
            throw;
        }
    }
}

TEST_CASE_METHOD(TestFixture, "BLS key encrypt", "[bls-key-encrypt]") {
    auto key = TestUtils::encryptTestKey();
    REQUIRE(key != nullptr);
}


TEST_CASE_METHOD(TestFixture, "DKG AES gen test", "[dkg-aes-gen]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t encLen = 0;

    PRINT_SRC_LINE
    auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 32);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> secret(BUF_LEN, 0);
    vector<char> errMsg1(BUF_LEN, 0);

    status = trustedDecryptDkgSecret(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(),
                                     encLen, (uint8_t *) secret.data());

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}


TEST_CASE_METHOD(TestFixture, "DKG AES public shares test", "[dkg-aes-pub-shares]") {
    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    vector<char> errMsg(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t encLen = 0;

    unsigned t = 32, n = 32;
    PRINT_SRC_LINE
    auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, n);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector<char> errMsg1(BUF_LEN, 0);

    char colon = ':';
    vector<char> pubShares(10000, 0);
    PRINT_SRC_LINE
    status = trustedGetPublicShares(eid, &errStatus, errMsg1.data(),
                                    encryptedDKGSecret.data(), encLen, pubShares.data(), t, n);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector <string> g2Strings = splitString(pubShares.data(), ',');
    vector <libff::alt_bn128_G2> pubSharesG2;
    for (u_int64_t i = 0; i < g2Strings.size(); i++) {
        vector <string> coeffStr = splitString(g2Strings.at(i).c_str(), ':');

        pubSharesG2.push_back(TestUtils::vectStringToG2(coeffStr));
    }

    vector<char> secret(BUF_LEN, 0);
    PRINT_SRC_LINE
    status = trustedDecryptDkgSecret(eid, &errStatus, errMsg1.data(), encryptedDKGSecret.data(), encLen,
                                     (uint8_t *) secret.data());
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    signatures::Dkg dkgObj(t, n);

    vector <libff::alt_bn128_Fr> poly = TestUtils::splitStringToFr(secret.data(), colon);
    vector <libff::alt_bn128_G2> pubSharesDkg = dkgObj.VerificationVector(poly);
    for (uint32_t i = 0; i < pubSharesDkg.size(); i++) {
        libff::alt_bn128_G2 el = pubSharesDkg.at(i);
        el.to_affine_coordinates();
    }
    REQUIRE(pubSharesG2 == pubSharesDkg);
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares test", "[dkg-aes-encr-sshares]") {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t encLen = 0;

    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    PRINT_SRC_LINE
    auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 2);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector <uint8_t> encrPRDHKey(BUF_LEN, 0);

    string pub_keyB = SAMPLE_PUBLIC_KEY_B;

    vector<char> s_shareG2(BUF_LEN, 0);
    PRINT_SRC_LINE
    status = trustedGetEncryptedSecretShare(eid, &errStatus, errMsg.data(),
                                            encryptedDKGSecret.data(), encLen,
                                            encrPRDHKey.data(), &encLen,
                                            result.data(),
                                            s_shareG2.data(),
                                            (char *) pub_keyB.data(), 2, 2, 1);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
}

TEST_CASE_METHOD(TestFixture, "DKG AES encrypted secret shares version 2 test", "[dkg-aes-encr-sshares-v2]") {
    vector<char> errMsg(BUF_LEN, 0);
    vector<char> result(BUF_LEN, 0);

    int errStatus = 0;
    uint64_t encLen = 0;

    vector <uint8_t> encryptedDKGSecret(BUF_LEN, 0);
    PRINT_SRC_LINE
    auto status = trustedGenDkgSecret(eid, &errStatus, errMsg.data(), encryptedDKGSecret.data(), &encLen, 2);
    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);

    vector <uint8_t> encrPRDHKey(BUF_LEN, 0);

    string pub_keyB = SAMPLE_PUBLIC_KEY_B;

    vector<char> s_shareG2(BUF_LEN, 0);
    PRINT_SRC_LINE
    status = trustedGetEncryptedSecretShareV2(eid, &errStatus, errMsg.data(),
                                              encryptedDKGSecret.data(), encLen,
                                              encrPRDHKey.data(), &encLen,
                                              result.data(),
                                              s_shareG2.data(),
                                              (char *) pub_keyB.data(), 2, 2, 1);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == SGX_SUCCESS);
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

    vector <string> ecdsaKeyNames;
    vector <string> blsKeyNames;

    int schainID = TestUtils::randGen();
    int dkgID = TestUtils::randGen();

    PRINT_SRC_LINE
    TestUtils::doDKG(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

    REQUIRE(blsKeyNames.size() == 4);

    schainID = TestUtils::randGen();
    dkgID = TestUtils::randGen();

    TestUtils::doDKG(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "DKG_BLS V2 test", "[dkg-bls-v2]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    vector <string> ecdsaKeyNames;
    vector <string> blsKeyNames;

    int schainID = TestUtils::randGen();
    int dkgID = TestUtils::randGen();

    PRINT_SRC_LINE
    TestUtils::doDKGV2(c, 4, 1, ecdsaKeyNames, blsKeyNames, schainID, dkgID);

    REQUIRE(blsKeyNames.size() == 4);

    schainID = TestUtils::randGen();
    dkgID = TestUtils::randGen();

    TestUtils::doDKGV2(c, 16, 5, ecdsaKeyNames, blsKeyNames, schainID, dkgID);
}

TEST_CASE_METHOD(TestFixture, "Delete Bls Key", "[delete-bls-key]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    std::string name = "BLS_KEY:SCHAIN_ID:123456789:NODE_ID:0:DKG_ID:0";
    libff::alt_bn128_Fr key = libff::alt_bn128_Fr(
            "6507625568967977077291849236396320012317305261598035438182864059942098934847");
    std::string key_str = TestUtils::stringFromFr(key);
    auto response = c.importBLSKeyShare(key_str, name);
    REQUIRE(response["status"] != 0);

    key_str = "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
    response = c.importBLSKeyShare(key_str, name);
    REQUIRE(response["status"] == 0);

    REQUIRE(c.blsSignMessageHash(name, SAMPLE_HASH, 1, 1)["status"] == 0);

    REQUIRE(c.deleteBlsKey(name)["deleted"] == true);
}

TEST_CASE_METHOD(TestFixture, "Import ECDSA Key", "[import-ecdsa-key]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    std::string name = "NEK:abcdef";
    auto response = c.importECDSAKey("6507625568967977077291849236396320012317305261598035438182864059942098934847",
                                     name);
    REQUIRE(response["status"] != 0);

    string key_str = "0xe632f7fde2c90a073ec43eaa90dca7b82476bf28815450a11191484934b9c3f";
    response = c.importECDSAKey(key_str, name);
    REQUIRE(response["status"] == 0);

    REQUIRE(c.ecdsaSignMessageHash(16, name, SAMPLE_HASH)["status"] == 0);
}

TEST_CASE_METHOD(TestFixture, "Backup Key", "[backup-key]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    std::ifstream sek_file("sgx_data/sgxwallet_backup_key.txt");
    REQUIRE(sek_file.good());

    std::string sek;
    sek_file >> sek;

    REQUIRE(sek.size() == 32);
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

    PRINT_SRC_LINE

    REQUIRE_NOTHROW(SGXRegistrationServer::getServer());

    PRINT_SRC_LINE

    string csrFile = "insecure-samples/yourdomain.csr";

    ifstream infile(csrFile);
    infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    ostringstream ss;
    ss << infile.rdbuf();
    infile.close();

    PRINT_SRC_LINE

    auto result = SGXRegistrationServer::getServer()->SignCertificate(ss.str());

    REQUIRE(result["status"] == 0);


    PRINT_SRC_LINE
    result = SGXRegistrationServer::getServer()->SignCertificate("Haha");

    REQUIRE(result["status"] != 0);
}

TEST_CASE_METHOD(TestFixture, "DKG API test", "[dkg-api]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;

    PRINT_SRC_LINE
    Json::Value genPoly = c.generateDKGPoly(polyName, 2);
    REQUIRE(genPoly["status"].asInt() == 0);

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
    REQUIRE_NOTHROW(c.getSecretShare(polyName, publicKeys, 2, 2));
    REQUIRE(Skeys == c.getSecretShare(polyName, publicKeys, 2, 2));

    Json::Value verifVect = c.getVerificationVector(polyName, 2, 2);
    REQUIRE_NOTHROW(c.getVerificationVector(polyName, 2, 2));
    REQUIRE(verifVect == c.getVerificationVector(polyName, 2, 2));

    Json::Value verificationWrongSkeys = c.dkgVerification("", "", "", 2, 2, 1);
    REQUIRE(verificationWrongSkeys["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixture, "DKG API V2 test", "[dkg-api-v2]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;

    PRINT_SRC_LINE
    Json::Value genPoly = c.generateDKGPoly(polyName, 2);
    REQUIRE(genPoly["status"].asInt() == 0);

    Json::Value publicKeys;
    publicKeys.append(SAMPLE_DKG_PUB_KEY_1);
    publicKeys.append(SAMPLE_DKG_PUB_KEY_2);

    // wrongName
    Json::Value genPolyWrongName = c.generateDKGPoly("poly", 2);
    REQUIRE(genPolyWrongName["status"].asInt() != 0);

    Json::Value verifVectWrongName = c.getVerificationVector("poly", 2, 2);
    REQUIRE(verifVectWrongName["status"].asInt() != 0);

    Json::Value secretSharesWrongName = c.getSecretShareV2("poly", publicKeys, 2, 2);
    REQUIRE(secretSharesWrongName["status"].asInt() != 0);

    // wrong_t
    Json::Value genPolyWrong_t = c.generateDKGPoly(polyName, 33);
    REQUIRE(genPolyWrong_t["status"].asInt() != 0);

    Json::Value verifVectWrong_t = c.getVerificationVector(polyName, 1, 2);
    REQUIRE(verifVectWrong_t["status"].asInt() != 0);

    Json::Value secretSharesWrong_t = c.getSecretShareV2(polyName, publicKeys, 3, 3);
    REQUIRE(secretSharesWrong_t["status"].asInt() != 0);

    // wrong_n
    Json::Value verifVectWrong_n = c.getVerificationVector(polyName, 2, 1);
    REQUIRE(verifVectWrong_n["status"].asInt() != 0);

    Json::Value publicKeys1;
    publicKeys1.append(SAMPLE_DKG_PUB_KEY_1);
    Json::Value secretSharesWrong_n = c.getSecretShareV2(polyName, publicKeys1, 2, 1);
    REQUIRE(secretSharesWrong_n["status"].asInt() != 0);

    //wrong number of publicKeys
    Json::Value secretSharesWrongPkeys = c.getSecretShareV2(polyName, publicKeys, 2, 3);
    REQUIRE(secretSharesWrongPkeys["status"].asInt() != 0);

    //wrong verif
    Json::Value Skeys = c.getSecretShareV2(polyName, publicKeys, 2, 2);
    REQUIRE_NOTHROW(c.getSecretShare(polyName, publicKeys, 2, 2));
    REQUIRE(Skeys == c.getSecretShare(polyName, publicKeys, 2, 2));

    Json::Value verifVect = c.getVerificationVector(polyName, 2, 2);
    REQUIRE_NOTHROW(c.getVerificationVector(polyName, 2, 2));
    REQUIRE(verifVect == c.getVerificationVector(polyName, 2, 2));

    Json::Value verificationWrongSkeys = c.dkgVerificationV2("", "", "", 2, 2, 1);
    REQUIRE(verificationWrongSkeys["status"].asInt() != 0);
}

TEST_CASE_METHOD(TestFixture, "PolyExists test", "[dkg-poly-exists]") {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    string polyName = SAMPLE_POLY_NAME;
    PRINT_SRC_LINE
    Json::Value genPoly = c.generateDKGPoly(polyName, 2);
    REQUIRE(genPoly["status"] == 0);

    PRINT_SRC_LINE
    Json::Value polyExists = c.isPolyExists(polyName);
    REQUIRE(polyExists["status"] == 0);
    REQUIRE(polyExists["IsExist"].asBool());

    PRINT_SRC_LINE
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

    int schainID = TestUtils::randGen();
    int dkgID = TestUtils::randGen();
    for (uint8_t i = 0; i < n; i++) {
        PRINT_SRC_LINE
        ethKeys[i] = c.generateECDSAKey();
        REQUIRE(ethKeys[i]["status"] == 0);
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        REQUIRE(ethKeys[i]["status"] == 0);
        auto response = c.generateDKGPoly(polyName, t);
        REQUIRE(response["status"] == 0);

        polyNames[i] = polyName;
        PRINT_SRC_LINE
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(verifVects[i]["status"] == 0);

        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        PRINT_SRC_LINE
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        REQUIRE(secretShares[i]["status"] == 0);

        for (uint8_t k = 0; k < t; k++)
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["verificationVector"][k][j].asString();
                pubShares[i] += TestUtils::convertDecToHex(pubShare);
            }
    }

    int k = 0;
    vector <string> secShares(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            PRINT_SRC_LINE
            Json::Value verif = c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
            REQUIRE(verif["status"] == 0);
            bool res = verif["result"].asBool();
            k++;
            REQUIRE(res);
        }

    Json::Value complaintResponse = c.complaintResponse(polyNames[1], t, n, 0);
    REQUIRE(complaintResponse["status"] == 0);

    string dhKey = complaintResponse["dhKey"].asString();
    string shareG2 = complaintResponse["share*G2"].asString();
    string secretShare = secretShares[1]["secretShare"].asString().substr(0, 192);

    vector<char> message(65, 0);

    SAFE_CHAR_BUF(encr_sshare, BUF_LEN)
    strncpy(encr_sshare, pubEthKeys[0].asString().c_str(), 128);

    SAFE_CHAR_BUF(common_key, BUF_LEN);
    REQUIRE(sessionKeyRecoverDH(dhKey.c_str(), encr_sshare, common_key) == 0);

    SAFE_CHAR_BUF(encr_sshare_check, BUF_LEN)
    strncpy(encr_sshare_check, secretShare.c_str(), ECDSA_SKEY_LEN - 1);

    REQUIRE(xorDecryptDH(common_key, encr_sshare_check, message) == 0);

    mpz_t hex_share;
    mpz_init(hex_share);
    mpz_set_str(hex_share, message.data(), 16);

    libff::alt_bn128_Fr share(hex_share);
    libff::alt_bn128_G2 decrypted_share_G2 = share * libff::alt_bn128_G2::one();
    decrypted_share_G2.to_affine_coordinates();

    mpz_clear(hex_share);

    REQUIRE(convertG2ToString(decrypted_share_G2) == shareG2);

    Json::Value verificationVectorMult = complaintResponse["verificationVectorMult"];

    libff::alt_bn128_G2 verificationValue = libff::alt_bn128_G2::zero();
    for (int i = 0; i < t; ++i) {
        libff::alt_bn128_G2 value;
        value.Z = libff::alt_bn128_Fq2::one();
        value.X.c0 = libff::alt_bn128_Fq(verificationVectorMult[i][0].asCString());
        value.X.c1 = libff::alt_bn128_Fq(verificationVectorMult[i][1].asCString());
        value.Y.c0 = libff::alt_bn128_Fq(verificationVectorMult[i][2].asCString());
        value.Y.c1 = libff::alt_bn128_Fq(verificationVectorMult[i][3].asCString());
        verificationValue = verificationValue + value;
    }
    verificationValue.to_affine_coordinates();
    REQUIRE(verificationValue == decrypted_share_G2);

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t,
    32 > > ();

    uint64_t binLen;

    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
        throw SGXException(TEST_INVALID_HEX, "Invalid hash");
    }

    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        auto response = c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t,
                                              n);
        REQUIRE(response["status"] == 0);

        PRINT_SRC_LINE
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        REQUIRE(pubBLSKeys[i]["status"] == 0);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
        REQUIRE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector <string> pubKey_vect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared < vector < string >> (pubKey_vect), t, n);
        PRINT_SRC_LINE
        REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        coeffs_pkeys_map[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);
    }

    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey
    common_public(make_shared < map < size_t, shared_ptr < BLSPublicKeyShare >>>(coeffs_pkeys_map), t,
            n);
    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));
}

TEST_CASE_METHOD(TestFixture, "AES_DKG V2 test", "[aes-dkg-v2]") {
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

    int schainID = TestUtils::randGen();
    int dkgID = TestUtils::randGen();
    for (uint8_t i = 0; i < n; i++) {
        PRINT_SRC_LINE
        ethKeys[i] = c.generateECDSAKey();
        REQUIRE(ethKeys[i]["status"] == 0);
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        REQUIRE(ethKeys[i]["status"] == 0);
        auto response = c.generateDKGPoly(polyName, t);
        REQUIRE(response["status"] == 0);

        polyNames[i] = polyName;
        PRINT_SRC_LINE
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        REQUIRE(verifVects[i]["status"] == 0);

        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        PRINT_SRC_LINE
        secretShares[i] = c.getSecretShareV2(polyNames[i], pubEthKeys, t, n);
        REQUIRE(secretShares[i]["status"] == 0);

        for (uint8_t k = 0; k < t; k++)
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["verificationVector"][k][j].asString();
                pubShares[i] += TestUtils::convertDecToHex(pubShare);
            }
    }

    int k = 0;
    vector <string> secShares(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            PRINT_SRC_LINE
            Json::Value verif = c.dkgVerificationV2(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n,
                                                    j);
            REQUIRE(verif["status"] == 0);
            bool res = verif["result"].asBool();
            k++;
            REQUIRE(res);
        }

    Json::Value complaintResponse = c.complaintResponse(polyNames[1], t, n, 0);
    REQUIRE(complaintResponse["status"] == 0);

    string dhKey = complaintResponse["dhKey"].asString();
    string shareG2 = complaintResponse["share*G2"].asString();
    string secretShare = secretShares[1]["secretShare"].asString().substr(0, 192);

    vector<char> message(65, 0);

    SAFE_CHAR_BUF(encr_sshare, BUF_LEN)
    strncpy(encr_sshare, pubEthKeys[0].asString().c_str(), 128);

    SAFE_CHAR_BUF(common_key, BUF_LEN);
    REQUIRE(sessionKeyRecoverDH(dhKey.c_str(), encr_sshare, common_key) == 0);

    auto hashed_key = cryptlite::sha256::hash_hex(string(common_key, 64));

    SAFE_CHAR_BUF(derived_key, 33)

    uint64_t key_length;
    REQUIRE(hex2carray(&hashed_key[0], &key_length, (uint8_t *) derived_key, 33));

    SAFE_CHAR_BUF(encr_sshare_check, BUF_LEN)
    strncpy(encr_sshare_check, secretShare.c_str(), ECDSA_SKEY_LEN - 1);

    REQUIRE(xorDecryptDHV2(derived_key, encr_sshare_check, message) == 0);

    mpz_t hex_share;
    mpz_init(hex_share);
    mpz_set_str(hex_share, message.data(), 16);

    libff::alt_bn128_Fr share(hex_share);
    libff::alt_bn128_G2 decrypted_share_G2 = share * libff::alt_bn128_G2::one();
    decrypted_share_G2.to_affine_coordinates();

    mpz_clear(hex_share);

    REQUIRE(convertG2ToString(decrypted_share_G2) == shareG2);

    Json::Value verificationVectorMult = complaintResponse["verificationVectorMult"];

    libff::alt_bn128_G2 verificationValue = libff::alt_bn128_G2::zero();
    for (int i = 0; i < t; ++i) {
        libff::alt_bn128_G2 value;
        value.Z = libff::alt_bn128_Fq2::one();
        value.X.c0 = libff::alt_bn128_Fq(verificationVectorMult[i][0].asCString());
        value.X.c1 = libff::alt_bn128_Fq(verificationVectorMult[i][1].asCString());
        value.Y.c0 = libff::alt_bn128_Fq(verificationVectorMult[i][2].asCString());
        value.Y.c1 = libff::alt_bn128_Fq(verificationVectorMult[i][3].asCString());
        verificationValue = verificationValue + value;
    }
    verificationValue.to_affine_coordinates();
    REQUIRE(verificationValue == decrypted_share_G2);

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t,
    32 > > ();

    uint64_t binLen;

    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
        throw SGXException(TEST_INVALID_HEX, "Invalid hash");
    }

    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        auto response = c.createBLSPrivateKeyV2(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i],
                                                t,
                                                n);
        REQUIRE(response["status"] == 0);

        PRINT_SRC_LINE
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        REQUIRE(pubBLSKeys[i]["status"] == 0);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
        REQUIRE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        vector <string> pubKey_vect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKey_vect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared < vector < string >> (pubKey_vect), t, n);
        PRINT_SRC_LINE
        REQUIRE(pubKey.VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));

        coeffs_pkeys_map[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);
    }

    shared_ptr <BLSSignature> commonSig = sigShareSet.merge();
    BLSPublicKey
    common_public(make_shared < map < size_t, shared_ptr < BLSPublicKeyShare >>>(coeffs_pkeys_map), t, n);
    REQUIRE(common_public.VerifySigWithHelper(hash_arr, commonSig, t, n));
}

TEST_CASE_METHOD(TestFixture, "AES encrypt/decrypt", "[aes-encrypt-decrypt]") {
    int errStatus = 0;
    vector<char> errMsg(BUF_LEN, 0);
    uint64_t encLen;
    string key = SAMPLE_AES_KEY;
    vector <uint8_t> encrypted_key(BUF_LEN, 0);

    PRINT_SRC_LINE
    auto status = trustedEncryptKey(eid, &errStatus, errMsg.data(), key.c_str(), encrypted_key.data(), &encLen);

    REQUIRE(status == 0);
    REQUIRE(errStatus == 0);

    vector<char> decr_key(BUF_LEN, 0);
    PRINT_SRC_LINE
    status = trustedDecryptKey(eid, &errStatus, errMsg.data(), encrypted_key.data(), encLen, decr_key.data());

    REQUIRE(status == 0);
    REQUIRE(key.compare(decr_key.data()) == 0);
    REQUIRE(errStatus == 0);
}


TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg bls", "[many-threads-crypto]") {
    vector <thread> threads;
    int num_threads = 16;
    for (int i = 0; i < num_threads; i++) {
        threads.push_back(thread(TestUtils::sendRPCRequest));
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_CASE_METHOD(TestFixture, "Many threads ecdsa dkg v2 bls", "[many-threads-crypto-v2]") {
    vector <thread> threads;
    int num_threads = 4;
    for (int i = 0; i < num_threads; i++) {
        threads.push_back(thread(TestUtils::sendRPCRequestV2));
    }

    for (auto &thread : threads) {
        thread.join();
    }
}

TEST_CASE_METHOD(TestFixture, "First run", "[first-run]") {

    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    try {
        PRINT_SRC_LINE
        auto keyName = genECDSAKeyAPI(c);
        ofstream namefile("/tmp/keyname");
        namefile << keyName;

        PRINT_SRC_LINE
    } catch (JsonRpcException &e) {
        cerr << e.what() << endl;
        throw;
    }


}

TEST_CASE_METHOD(TestFixtureNoReset, "Second run", "[second-run]") {

    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);
    try {
        PRINT_SRC_LINE
        string keyName;
        ifstream namefile("/tmp/keyname");
        getline(namefile, keyName);

        Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
        REQUIRE(sig["status"].asInt() == 0);
        Json::Value getPubKey = c.getPublicECDSAKey(keyName);
        REQUIRE(getPubKey["status"].asInt() == 0);
    } catch (JsonRpcException &e) {
        cerr << e.what() << endl;
        throw;
    }
}


TEST_CASE_METHOD(TestFixture, "ZMQ-ecdsa", "[zmq-ecdsa]") {

    HttpClient htp(RPC_ENDPOINT);
    StubClient c(htp, JSONRPC_CLIENT_V2);

    string ip = ZMQ_IP;

    auto client = make_shared<ZMQClient>(ip, ZMQ_PORT);

    string keyName = "";

    PRINT_SRC_LINE
    keyName = genECDSAKeyAPI(c);
    int end = 10000000;
    string sh = string(SAMPLE_HASH);


    std::vector <std::thread> workers;


    PRINT_SRC_LINE

    for (int j = 0; j < 2; j++) {
        workers.push_back(std::thread([client, sh, keyName, end, j]() {
            CHECK_STATE(client);
            for (int i = (j * 2000); i < (j * 2000) + 1000; i++) {

                auto hash = sh.substr(0, sh.size() - 8) + to_string(end + i);

                auto sig = client->ecdsaSignMessageHash(16, keyName, hash);
                REQUIRE(sig.size() > 10);
            }

        }));
    };

    std::for_each(workers.begin(), workers.end(), [](
            std::thread &t) { t.join(); });
    PRINT_SRC_LINE

}


TEST_CASE_METHOD(TestFixtureNoResetFromBackup, "Backup restore", "[backup-restore]") {
}
