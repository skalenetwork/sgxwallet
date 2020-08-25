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

    @file SGXWalletServer.cpp
    @author Stan Kladko
    @date 2019
*/

#include <iostream>

#include "abstractstubserver.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <stdio.h>

#include "sgxwallet_common.h"
#include "sgxwallet.h"


#include "SGXException.h"
#include "LevelDB.h"
#include "BLSCrypto.h"
#include "ECDSACrypto.h"
#include "DKGCrypto.h"

#include "SGXWalletServer.h"
#include "SGXWalletServer.hpp"

#include "ServerDataChecker.h"

#include <algorithm>
#include <stdlib.h>

#include <unistd.h>

#include "ServerInit.h"

#include "Log.h"

using namespace std;

void setFullOptions(uint64_t _logLevel, int _useHTTPS, int _autoconfirm, int _enterBackupKey) {
    spdlog::info("Entering {}", __FUNCTION__);

    CHECK_STATE(_logLevel <= 2)

    if (_logLevel == L_TRACE) {
        spdlog::set_level(spdlog::level::trace);
    } else if (_logLevel == L_DEBUG) {
        spdlog::set_level(spdlog::level::debug);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    useHTTPS = _useHTTPS;
    spdlog::info("useHTTPS set to " + to_string(_useHTTPS));
    autoconfirm = _autoconfirm;
    spdlog::info("autoconfirm set to " + to_string(autoconfirm));
    enterBackupKey = _enterBackupKey;
    spdlog::info("enterBackupKey set to " + to_string(enterBackupKey));
}

void setOptions(uint64_t _logLevel, int _useHTTPS, int _autoconfirm) {
    spdlog::info("Entering {}", __FUNCTION__);
    setFullOptions(_logLevel, _useHTTPS, _autoconfirm, false);
}

bool isStringDec(const string &_str) {
    auto res = find_if_not(_str.begin(), _str.end(), [](char c) -> bool {
        return isdigit(c);
    });
    return !_str.empty() && res == _str.end();
}

shared_ptr <SGXWalletServer> SGXWalletServer::server = nullptr;
shared_ptr <HttpServer> SGXWalletServer::httpServer = nullptr;

SGXWalletServer::SGXWalletServer(AbstractServerConnector &_connector,
                                 serverVersion_t _type)
        : AbstractStubServer(_connector, _type) {}

void SGXWalletServer::printDB() {
    cout << "PRINTING LEVELDB: " << endl;
    class MyVisitor : public LevelDB::KeyVisitor {
    public:
        virtual void visitDBKey(const char *_data) {
            cout << _data << endl;
        }
    };

    MyVisitor v;

    LevelDB::getLevelDb()->visitKeys(&v, 100000000);
}

int SGXWalletServer::initHttpsServer(bool _checkCerts) {
    spdlog::info("Entering {}", __FUNCTION__);
    string rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
    string keyCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.key";

    if (access(rootCAPath.c_str(), F_OK) != 0 || access(keyCAPath.c_str(), F_OK) != 0) {
        spdlog::info("NO ROOT CA CERTIFICATE YET. CREATING ...");

        string genRootCACert = "cd cert && ./create_CA";

        if (system(genRootCACert.c_str()) == 0) {
            spdlog::info("ROOT CA CERTIFICATE IS SUCCESSFULLY GENERATED");
        } else {
            spdlog::error("ROOT CA CERTIFICATE GENERATION FAILED");
            exit(-1);
        }
    }

    string certPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.crt";
    string keyPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.key";

    if (access(certPath.c_str(), F_OK) != 0 || access(certPath.c_str(), F_OK) != 0) {
        spdlog::info("YOU DO NOT HAVE SERVER CERTIFICATE");
        spdlog::info("SERVER CERTIFICATE IS GOING TO BE CREATED");

        string genCert = "cd cert && ./create_server_cert";

        if (system(genCert.c_str()) == 0) {
            spdlog::info("SERVER CERTIFICATE IS SUCCESSFULLY GENERATED");
        } else {
            spdlog::info("SERVER CERTIFICATE GENERATION FAILED");
            exit(-1);
        }
    }

    httpServer = make_shared<HttpServer>(BASE_PORT, certPath, keyPath, rootCAPath, _checkCerts, 64);
    server = make_shared<SGXWalletServer>(*httpServer,
                                          JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)

    if (!server->StartListening()) {
        spdlog::error("SGX Server could not start listening");
        exit(-1);
    } else {
        spdlog::info("SGX Server started on port {}", BASE_PORT);
    }
    return 0;
}

int SGXWalletServer::initHttpServer() { //without ssl
    spdlog::info("Entering {}", __FUNCTION__);
    httpServer = make_shared<HttpServer>(BASE_PORT + 3);
    server = make_shared<SGXWalletServer>(*httpServer,
                                          JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
    if (!server->StartListening()) {
        spdlog::error("Server could not start listening");
        exit(-1);
    }
    return 0;
}

Json::Value
SGXWalletServer::importBLSKeyShareImpl(const string &_keyShare, const string &_keyShareName, int t, int n, int _index) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result);

    result["encryptedKeyShare"] = "";

    string encryptedKeyShareHex;

    try {
        encryptedKeyShareHex = encryptBLSKeyShare2Hex(&errStatus, (char *) errMsg.data(), _keyShare.c_str());

        if (errStatus != 0) {
            throw SGXException(errStatus, errMsg.data());
        }

        if (encryptedKeyShareHex.empty()) {
            throw SGXException(UNKNOWN_ERROR, "");
        }

        result["encryptedKeyShare"] = encryptedKeyShareHex;

        writeKeyShare(_keyShareName, encryptedKeyShareHex, _index, n, t);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value
SGXWalletServer::blsSignMessageHashImpl(const string &_keyShareName, const string &_messageHash, int t, int n,
                                        int _signerIndex) {
    spdlog::trace("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["status"] = -1;

    result["signatureShare"] = "";

    vector<char> signature(BUF_LEN, 0);

    shared_ptr <string> value = nullptr;

    try {
        if (!checkName(_keyShareName, "BLS_KEY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid BLSKey name");
        }
        string hashTmp = _messageHash;
        if (hashTmp[0] == '0' && (hashTmp[1] == 'x' || hashTmp[1] == 'X')) {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 2);
        }
        while (hashTmp[0] == '0') {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 1);
        }

        if (!checkHex(hashTmp)) {
            throw SGXException(INVALID_HEX, "Invalid hash");
        }

        value = readFromDb(_keyShareName);
        if (!bls_sign(value->c_str(), _messageHash.c_str(), t, n, _signerIndex, signature.data())) {
            throw SGXException(-1, "Could not sign data ");
        }
    } HANDLE_SGX_EXCEPTION(result)


    result["signatureShare"] = string(signature.data());

    RETURN_SUCCESS(result);

}

Json::Value SGXWalletServer::importECDSAKeyImpl(const string &_key, const string &_keyName) {
    INIT_RESULT(result)
    result["encryptedKey"] = "";
    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::generateECDSAKeyImpl() {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["encryptedKey"] = "";

    vector <string> keys;

    try {
        keys = genECDSAKey();

        if (keys.size() == 0) {
            throw SGXException(UNKNOWN_ERROR, "key was not generated");
        }

        string keyName = "NEK:" + keys.at(2);

        writeDataToDB(keyName, keys.at(0));

        result["encryptedKey"] = keys.at(0);
        result["publicKey"] = keys.at(1);
        result["PublicKey"] = keys.at(1);
        result["keyName"] = keyName;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::renameECDSAKeyImpl(const string &_keyName, const string &_tempKeyName) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["encryptedKey"] = "";

    try {
        string prefix = _tempKeyName.substr(0, 8);
        if (prefix != "tmp_NEK:") {
            throw SGXException(UNKNOWN_ERROR, "invalid temp key name");
        }
        prefix = _keyName.substr(0, 12);
        if (prefix != "NEK_NODE_ID:") {
            throw SGXException(UNKNOWN_ERROR, "invalid key name");
        }
        string postfix = _keyName.substr(12, _keyName.length());
        if (!isStringDec(postfix)) {
            throw SGXException(UNKNOWN_ERROR, "invalid key name");
        }

        shared_ptr <string> encryptedKey = readFromDb(_tempKeyName);

        writeDataToDB(_keyName, *encryptedKey);
        LevelDB::getLevelDb()->deleteTempNEK(_tempKeyName);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::ecdsaSignMessageHashImpl(int _base, const string &_keyName, const string &_messageHash) {
    spdlog::trace("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["signature_v"] = "";
    result["signature_r"] = "";
    result["signature_s"] = "";

    vector <string> signatureVector(3);

    try {
        string hashTmp = _messageHash;
        if (hashTmp[0] == '0' && (hashTmp[1] == 'x' || hashTmp[1] == 'X')) {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 2);
        }
        while (hashTmp[0] == '0') {
            hashTmp.erase(hashTmp.begin(), hashTmp.begin() + 1);
        }

        if (!checkECDSAKeyName(_keyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        if (!checkHex(hashTmp)) {
            throw SGXException(INVALID_HEX, "Invalid hash");
        }
        if (_base <= 0 || _base > 32) {
            throw SGXException(-22, "Invalid base");
        }

        shared_ptr <string> encryptedKey = readFromDb(_keyName, "");

        signatureVector = ecdsaSignHash(encryptedKey->c_str(), hashTmp.c_str(), _base);
        if (signatureVector.size() != 3) {
            throw SGXException(INVALID_ECSDA_SIGNATURE, "Invalid ecdsa signature");
        }


        result["signature_v"] = signatureVector.at(0);
        result["signature_r"] = signatureVector.at(1);
        result["signature_s"] = signatureVector.at(2);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::getPublicECDSAKeyImpl(const string &_keyName) {
    spdlog::debug("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["publicKey"] = "";
    result["PublicKey"] = "";

    string publicKey;

    try {
        if (!checkECDSAKeyName(_keyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        shared_ptr <string> keyStr = readFromDb(_keyName);
        publicKey = getECDSAPubKey(keyStr->c_str());
        result["PublicKey"] = publicKey;
        result["publicKey"] = publicKey;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::generateDKGPolyImpl(const string &_polyName, int _t) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    string encrPolyHex;

    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME,
                               "Invalid polynomial name, it should be like POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1");
        }
        if (_t <= 0 || _t > 32) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid parameter t ");
        }
        encrPolyHex = gen_dkg_poly(_t);
        writeDataToDB(_polyName, encrPolyHex);
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::getVerificationVectorImpl(const string &_polyName, int _t, int _n) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    vector <vector<string>> verifVector;
    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid parameters: n or t ");
        }

        shared_ptr <string> encrPoly = readFromDb(_polyName);

        verifVector = get_verif_vect(encrPoly->c_str(), _t, _n);

        for (int i = 0; i < _t; i++) {
            vector <string> currentCoef = verifVector.at(i);
            for (int j = 0; j < 4; j++) {
                result["verificationVector"][i][j] = currentCoef.at(j);
            }
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)

}

Json::Value SGXWalletServer::getSecretShareImpl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result);
    result["secretShare"] = "";
    result["SecretShare"] = "";

    try {
        if (_pubKeys.size() != (uint64_t) _n) {
            throw SGXException(INVALID_DKG_PARAMS, "invalid number of public keys");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
        }

        shared_ptr <string> encrPoly = readFromDb(_polyName);

        vector <string> pubKeysStrs;
        for (int i = 0; i < _n; i++) {
            if (!checkHex(_pubKeys[i].asString(), 64)) {
                throw SGXException(INVALID_HEX, "Invalid public key");
            }
            pubKeysStrs.push_back(_pubKeys[i].asString());
        }

        string s = trustedGetSecretShares(_polyName, encrPoly->c_str(), pubKeysStrs, _t, _n);
        result["secretShare"] = s;
        result["SecretShare"] = s;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::dkgVerificationImpl(const string &_publicShares, const string &_ethKeyName,
                                                 const string &_secretShare, int _t, int _n, int _index) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)
    result["result"] = false;

    try {
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        if (!check_n_t(_t, _n) || _index > _n || _index < 0) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
        }
        if (!checkHex(_secretShare, SECRET_SHARE_NUM_BYTES)) {
            throw SGXException(INVALID_HEX, "Invalid Secret share");
        }
        if (_publicShares.length() != (uint64_t) 256 * _t) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid length of public shares");
        }

        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        if (verifyShares(_publicShares.c_str(), _secretShare.c_str(), encryptedKeyHex_ptr->c_str(), _t, _n, _index)) {
            result["result"] = true;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value
SGXWalletServer::createBLSPrivateKeyImpl(const string &_blsKeyName, const string &_ethKeyName, const string &_polyName,
                                         const string &_secretShare, int _t, int _n) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (_secretShare.length() != (uint64_t) _n * 192) {
            throw SGXException(INVALID_SECRET_SHARES_LENGTH, "Invalid secret share length");
        }
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_BLS_NAME, "Invalid BLS key name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
        }
        vector <string> sshares_vect;



        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        bool res = CreateBLSShare(_blsKeyName, _secretShare.c_str(), encryptedKeyHex_ptr->c_str());
        if (res) {
            spdlog::info("BLS KEY SHARE CREATED ");
        } else {
            throw SGXException(-122, "Error while creating BLS key share");
        }

        for (int i = 0; i < _n; i++) {
            string name = _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteDHDKGKey(name);
            string shareG2_name = "shareG2_" + _polyName + "_" + to_string(i) + ":";
            LevelDB::getLevelDb()->deleteKey(shareG2_name);
        }
        LevelDB::getLevelDb()->deleteKey(_polyName);

    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::getBLSPublicKeyShareImpl(const string &_blsKeyName) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_BLS_NAME, "Invalid BLSKey name");
        }
        shared_ptr <string> encryptedKeyHex_ptr = readFromDb(_blsKeyName);

        vector <string> public_key_vect = GetBLSPubKey(encryptedKeyHex_ptr->c_str());
        for (uint8_t i = 0; i < 4; i++) {
            result["blsPublicKeyShare"][i] = public_key_vect.at(i);
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::complaintResponseImpl(const string &_polyName, int _ind) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        string shareG2_name = "shareG2_" + _polyName + "_" + to_string(_ind) + ":";
        shared_ptr <string> shareG2_ptr = readFromDb(shareG2_name);

        string DHKey = decryptDHKey(_polyName, _ind);

        result["share*G2"] = *shareG2_ptr;
        result["dhKey"] = DHKey;
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::multG2Impl(const string &_x) {
    INIT_RESULT(result)

    try {
        auto xG2_vect = mult_G2(_x);
        for (uint8_t i = 0; i < 4; i++) {
            result["x*G2"][i] = xG2_vect.at(i);
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::isPolyExistsImpl(const string &_polyName) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["IsExist"] = false;

    try {
        shared_ptr <string> poly_str_ptr = LevelDB::getLevelDb()->readString(_polyName);

        if (poly_str_ptr != nullptr) {
            result["IsExist"] = true;
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result);
}

Json::Value SGXWalletServer::getServerStatusImpl() {
    INIT_RESULT(result)
    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::getServerVersionImpl() {
    INIT_RESULT(result)
    result["version"] = TOSTRING(SGXWALLET_VERSION);
    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::deleteBlsKeyImpl(const string &name) {
    spdlog::info("Entering {}", __FUNCTION__);
    INIT_RESULT(result)

    result["deleted"] = false;
    try {
        if (!checkName(name, "BLS_KEY")) {
            throw SGXException(INVALID_BLS_NAME, "Invalid BLSKey name format");
        }
        shared_ptr <string> bls_ptr = LevelDB::getLevelDb()->readString(name);

        if (bls_ptr != nullptr) {
            LevelDB::getLevelDb()->deleteKey(name);
            result["deleted"] = true;
        } else {
            auto error_msg = "BLS key not found: " + name;
            throw SGXException(INVALID_BLS_NAME, error_msg.c_str());
        }
    } HANDLE_SGX_EXCEPTION(result)

    RETURN_SUCCESS(result)
}

Json::Value SGXWalletServer::generateDKGPoly(const string &_polyName, int _t) {
    return generateDKGPolyImpl(_polyName, _t);
}

Json::Value SGXWalletServer::getVerificationVector(const string &_polynomeName, int _t, int _n) {
    return getVerificationVectorImpl(_polynomeName, _t, _n);
}

Json::Value SGXWalletServer::getSecretShare(const string &_polyName, const Json::Value &_publicKeys, int t, int n) {
    return getSecretShareImpl(_polyName, _publicKeys, t, n);
}

Json::Value
SGXWalletServer::dkgVerification(const string &_publicShares, const string &ethKeyName, const string &SecretShare,
                                 int t,
                                 int n, int index) {
    return dkgVerificationImpl(_publicShares, ethKeyName, SecretShare, t, n, index);
}

Json::Value
SGXWalletServer::createBLSPrivateKey(const string &blsKeyName, const string &ethKeyName, const string &polyName,
                                     const string &SecretShare, int t, int n) {
    return createBLSPrivateKeyImpl(blsKeyName, ethKeyName, polyName, SecretShare, t, n);
}

Json::Value SGXWalletServer::getBLSPublicKeyShare(const string &blsKeyName) {
    return getBLSPublicKeyShareImpl(blsKeyName);
}

Json::Value SGXWalletServer::generateECDSAKey() {
    return generateECDSAKeyImpl();
}

Json::Value SGXWalletServer::renameECDSAKey(const string &_keyName, const string &_tmpKeyName) {
    return renameECDSAKeyImpl(_keyName, _tmpKeyName);
}

Json::Value SGXWalletServer::getPublicECDSAKey(const string &_keyName) {
    return getPublicECDSAKeyImpl(_keyName);
}

Json::Value SGXWalletServer::ecdsaSignMessageHash(int _base, const string &_keyShareName, const string &_messageHash) {
    return ecdsaSignMessageHashImpl(_base, _keyShareName, _messageHash);
}

Json::Value
SGXWalletServer::importBLSKeyShare(const string &_keyShare, const string &_keyShareName, int _t, int _n,
                                   int index) {
    return importBLSKeyShareImpl(_keyShare, _keyShareName, _t, _n, index);
}

Json::Value SGXWalletServer::blsSignMessageHash(const string &_keyShareName, const string &_messageHash, int _t, int _n,
                                                int _signerIndex) {
    return blsSignMessageHashImpl(_keyShareName, _messageHash, _t, _n, _signerIndex);
}

Json::Value SGXWalletServer::importECDSAKey(const string &_key, const string &_keyName) {
    return importECDSAKeyImpl(_key, _keyName);
}

Json::Value SGXWalletServer::complaintResponse(const string &polyName, int ind) {
    return complaintResponseImpl(polyName, ind);
}

Json::Value SGXWalletServer::multG2(const string &x) {
    return multG2Impl(x);
}

Json::Value SGXWalletServer::isPolyExists(const string &polyName) {
    return isPolyExistsImpl(polyName);
}

Json::Value SGXWalletServer::getServerStatus() {
    return getServerStatusImpl();
}

Json::Value SGXWalletServer::getServerVersion() {
    return getServerVersionImpl();
}

Json::Value SGXWalletServer::deleteBlsKey(const string &name) {
    return deleteBlsKeyImpl(name);
}

shared_ptr <string> SGXWalletServer::readFromDb(const string &name, const string &prefix) {
    auto dataStr = LevelDB::getLevelDb()->readString(prefix + name);

    if (dataStr == nullptr) {
        throw SGXException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exist");
    }

    return dataStr;
}

void SGXWalletServer::writeKeyShare(const string &_keyShareName, const string &_value, int _index, int _n, int _t) {
    if (LevelDB::getLevelDb()->readString(_keyShareName) != nullptr) {
        throw SGXException(KEY_SHARE_ALREADY_EXISTS, "Key share with this name already exists");
    }

    LevelDB::getLevelDb()->writeString(_keyShareName, _value);
}

void SGXWalletServer::writeDataToDB(const string &Name, const string &value) {
    Json::Value val;
    Json::FastWriter writer;

    val["value"] = value;
    writer.write(val);

    auto key = Name;

    if (LevelDB::getLevelDb()->readString(Name) != nullptr) {
        throw SGXException(KEY_NAME_ALREADY_EXISTS, "Name already exists");
    }

    LevelDB::getLevelDb()->writeString(key, value);
}
