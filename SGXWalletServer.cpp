/*

    Modifications Copyright (C) 2019-Present SKALE Labs
    
*/


/*************************************************************************
 * libjson-rpc-cpp
 *************************************************************************
 * @file    stubserver.cpp
 * @date    02.05.2013
 * @author  Peter Spiess-Knafl <dev@spiessknafl.at>
 * @license See attached LICENSE.txt
 ************************************************************************/
#include <iostream>

#include "abstractstubserver.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include <stdio.h>

#include "sgxwallet_common.h"


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

#include "spdlog/spdlog.h"

#include "common.h"

void setFullOptions(int _printDebugInfo,
                    int _printTraceInfo, int _useHTTPS, int _autoconfirm, int _encryptKeys) {
    if (_printDebugInfo)
        spdlog::set_level(spdlog::level::debug);
    else if (_printTraceInfo) {
        spdlog::set_level(spdlog::level::trace);
    } else if (_printTraceInfo) {
        spdlog::set_level(spdlog::level::info);
    }
    useHTTPS = _useHTTPS;
    autoconfirm = _autoconfirm;
    encryptKeys = _encryptKeys;
}


void setOptions(int _printDebugInfo,
                int _printTraceInfo, int _useHTTPS, int _autoconfirm) {
    setFullOptions(_printDebugInfo,
                   _printTraceInfo, _useHTTPS, _autoconfirm, false);
}


bool isStringDec(string &_str) {
    auto res = find_if_not(_str.begin(), _str.end(), [](char c) -> bool {
        return isdigit(c);
    });
    return !_str.empty() && res == _str.end();
}


SGXWalletServer *s = nullptr;
HttpServer *httpServer = nullptr;

SGXWalletServer::SGXWalletServer(AbstractServerConnector &_connector,
                                 serverVersion_t _type)
        : AbstractStubServer(_connector, _type) {}

void SGXWalletServer::printDB() {
    cout << "HERE ARE YOUR KEYS: " << endl;
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

    httpServer = new HttpServer(BASE_PORT, certPath, keyPath, rootCAPath, _checkCerts, 64);
    s = new SGXWalletServer(*httpServer,
                            JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)

    if (!s->StartListening()) {
        spdlog::error("SGX Server could not start listening");
        exit(-1);
    } else {
        spdlog::info("SGX Server started on port {}", BASE_PORT);
    }
    return 0;
}


int SGXWalletServer::initHttpServer() { //without ssl

    httpServer = new HttpServer(BASE_PORT + 3);
    s = new SGXWalletServer(*httpServer,
                            JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
    if (!s->StartListening()) {
        spdlog::error("Server could not start listening");
        exit(-1);
    }
    return 0;
}

Json::Value
SGXWalletServer::importBLSKeyShareImpl(const string &_keyShare, const string &_keyShareName, int t, int n, int _index) {
    Json::Value result;

    int errStatus = UNKNOWN_ERROR;
    char *errMsg = (char *) calloc(BUF_LEN, 1);

    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKeyShare"] = "";

    char *encryptedKeyShareHex = nullptr;

    try {

        encryptedKeyShareHex = encryptBLSKeyShare2Hex(&errStatus, errMsg, _keyShare.c_str());

        if (encryptedKeyShareHex == nullptr) {
            throw SGXException(UNKNOWN_ERROR, "");
        }

        if (errStatus != 0) {
            throw SGXException(errStatus, errMsg);
        }

        result["encryptedKeyShare"] = string(encryptedKeyShareHex);

        writeKeyShare(_keyShareName, encryptedKeyShareHex, _index, n, t);

    } catch (SGXException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    if (encryptedKeyShareHex != nullptr) {
        free(encryptedKeyShareHex);
    }

    return result;
}

Json::Value
SGXWalletServer::blsSignMessageHashImpl(const string &_keyShareName, const string &_messageHash, int t, int n,
                                        int _signerIndex) {
    Json::Value result;
    result["status"] = -1;
    result["errorMessage"] = "Unknown server error";
    result["signatureShare"] = "";

    char *signature = (char *) calloc(BUF_LEN, 1);

    shared_ptr<string> value = nullptr;

    try {
        if (!checkName(_keyShareName, "BLS_KEY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid BLSKey name");
        }
        string cutHash = _messageHash;
        if (cutHash[0] == '0' && (cutHash[1] == 'x' || cutHash[1] == 'X')) {
            cutHash.erase(cutHash.begin(), cutHash.begin() + 2);
        }
        while (cutHash[0] == '0') {
            cutHash.erase(cutHash.begin(), cutHash.begin() + 1);
        }

        if (!checkHex(cutHash)) {
            throw SGXException(INVALID_HEX, "Invalid hash");
        }

        value = readFromDb(_keyShareName);
    } catch (SGXException _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        return result;
    } catch (...) {
        exception_ptr p = current_exception();
        printf("Exception %s \n", p.__cxa_exception_type()->name());
        result["status"] = -1;
        result["errorMessage"] = "Read key share has thrown exception:";
        return result;
    }

    try {
        if (!bls_sign(value->c_str(), _messageHash.c_str(), t, n, _signerIndex, signature)) {
            result["status"] = -1;
            result["errorMessage"] = "Could not sign";
            return result;
        }
    } catch (...) {
        result["status"] = -1;
        result["errorMessage"] = "Sign has thrown exception";
        return result;
    }

    result["status"] = 0;
    result["errorMessage"] = "";
    result["signatureShare"] = signature;
    return result;
}


Json::Value SGXWalletServer::importECDSAKeyImpl(const string &_key, const string &_keyName) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";
    return result;
}


Json::Value SGXWalletServer::generateECDSAKeyImpl() {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";


    vector<string> keys;

    try {
        keys = genECDSAKey();

        if (keys.size() == 0) {
            throw SGXException(UNKNOWN_ERROR, "key was not generated");
        }

        string keyName = "NEK:" + keys.at(2);

        spdlog::debug("key name generated: {}", keyName);
        spdlog::debug("write encr key {}", keys.at(0));

        writeDataToDB(keyName, keys.at(0));

        result["encryptedKey"] = keys.at(0);
        result["publicKey"] = keys.at(1);
        result["PublicKey"] = keys.at(1);
        result["keyName"] = keyName;

    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value SGXWalletServer::renameECDSAKeyImpl(const string &_keyName, const string &_tempKeyName) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
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

        shared_ptr<string> key_ptr = readFromDb(_tempKeyName);
        cerr << "new key name is " << _keyName << endl;
        writeDataToDB(_keyName, *key_ptr);
        LevelDB::getLevelDb()->deleteTempNEK(_tempKeyName);

    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}


Json::Value SGXWalletServer::ecdsaSignMessageHashImpl(int _base, const string &_keyName, const string &_messageHash) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["signature_v"] = "";
    result["signature_r"] = "";
    result["signature_s"] = "";

    vector<string> sign_vect(3);

    try {

        string cutHash = _messageHash;
        if (cutHash[0] == '0' && (cutHash[1] == 'x' || cutHash[1] == 'X')) {
            cutHash.erase(cutHash.begin(), cutHash.begin() + 2);
        }
        while (cutHash[0] == '0') {
            cutHash.erase(cutHash.begin(), cutHash.begin() + 1);
        }

        if (!checkECDSAKeyName(_keyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        if (!checkHex(cutHash)) {
            throw SGXException(INVALID_HEX, "Invalid hash");
        }
        if (_base <= 0 || _base > 32) {
            throw SGXException(-22, "Invalid base");
        }

        shared_ptr<string> key_ptr = readFromDb(_keyName, "");

        sign_vect = ecdsaSignHash(key_ptr->c_str(), cutHash.c_str(), _base);
        if (sign_vect.size() != 3) {
            throw SGXException(INVALID_ECSDA_SIGNATURE, "Invalid ecdsa signature");
        }

        spdlog::debug("got signature_s  {}", sign_vect.at(2));

        result["signature_v"] = sign_vect.at(0);
        result["signature_r"] = sign_vect.at(1);
        result["signature_s"] = sign_vect.at(2);

    } catch (SGXException &_e) {
        cerr << "err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value SGXWalletServer::getPublicECDSAKeyImpl(const string &_keyName) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["publicKey"] = "";
    result["PublicKey"] = "";

    string publicKey;

    try {
        if (!checkECDSAKeyName(_keyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        shared_ptr<string> keyStr = readFromDb(_keyName);
        publicKey = getECDSAPubKey(keyStr->c_str());
        spdlog::debug("PublicKey {}", publicKey);
        spdlog::debug("PublicKey length {}", publicKey.length());

        result["PublicKey"] = publicKey;
        result["publicKey"] = publicKey;

    } catch (SGXException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value SGXWalletServer::generateDKGPolyImpl(const string &_polyName, int _t) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    //result["encryptedPoly"] = "";

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

        //result["encryptedPoly"] = encrPolyHex;
    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value SGXWalletServer::getVerificationVectorImpl(const string &_polyName, int _t, int _n) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    vector<vector<string>> verifVector;
    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid parameters: n or t ");
        }

        shared_ptr<string> encr_poly_ptr = readFromDb(_polyName);

        verifVector = get_verif_vect(encr_poly_ptr->c_str(), _t, _n);
        //cerr << "verif vect size " << verifVector.size() << endl;

        for (int i = 0; i < _t; i++) {
            vector<string> cur_coef = verifVector.at(i);
            for (int j = 0; j < 4; j++) {
                result["verificationVector"][i][j] = cur_coef.at(j);
                result["Verification Vector"][i][j] = cur_coef.at(j);
            }
        }

    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        result["verificationVector"] = "";
        result["Verification Vector"] = "";
    }

    return result;
}

Json::Value SGXWalletServer::getSecretShareImpl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

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

        shared_ptr<string> encr_poly_ptr = readFromDb(_polyName);

        vector<string> pubKeysStrs;
        for (int i = 0; i < _n; i++) {
            if (!checkHex(_pubKeys[i].asString(), 64)) {
                throw SGXException(INVALID_HEX, "Invalid public key");
            }
            pubKeysStrs.push_back(_pubKeys[i].asString());
        }

        string s = get_secret_shares(_polyName, encr_poly_ptr->c_str(), pubKeysStrs, _t, _n);
        //cerr << "result is " << s << endl;
        result["secretShare"] = s;

    } catch (SGXException &_e) {
        //cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        result["secretShare"] = "";
        result["SecretShare"] = "";
    }

    return result;
}

Json::Value SGXWalletServer::dkgVerificationImpl(const string &_publicShares, const string &_ethKeyName,
                                                 const string &_secretShare, int _t, int _n, int _index) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["result"] = true;

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

        shared_ptr<string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

        if (!verifyShares(_publicShares.c_str(), _secretShare.c_str(), encryptedKeyHex_ptr->c_str(), _t, _n, _index)) {
            result["result"] = false;
        }

    } catch (SGXException &_e) {
        //cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        result["result"] = false;
    }

    return result;
}

Json::Value
SGXWalletServer::createBLSPrivateKeyImpl(const string &_blsKeyName, const string &_ethKeyName, const string &_polyName,
                                         const string &_secretShare, int _t, int _n) {


    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {

        if (_secretShare.length() != (uint64_t) _n * 192) {
            spdlog::error("Invalid secret share length - {}", _secretShare.length());
            spdlog::error("Secret share - {}", _secretShare);
            throw SGXException(INVALID_SECRET_SHARES_LENGTH, "Invalid secret share length");
        }
        if (!checkECDSAKeyName(_ethKeyName)) {
            throw SGXException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
        }
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid BLS key name");
        }
        if (!check_n_t(_t, _n)) {
            throw SGXException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
        }
        vector<string> sshares_vect;

        spdlog::debug("secret shares from json are - {}", _secretShare);

        shared_ptr<string> encryptedKeyHex_ptr = readFromDb(_ethKeyName);

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

    } catch (SGXException &_e) {
        //cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;

    }

    return result;
}

Json::Value SGXWalletServer::getBLSPublicKeyShareImpl(const string &_blsKeyName) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {
        if (!checkName(_blsKeyName, "BLS_KEY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid BLSKey name");
        }
        shared_ptr<string> encryptedKeyHex_ptr = readFromDb(_blsKeyName);
        spdlog::debug("encr_bls_key_share is {}", *encryptedKeyHex_ptr);
        spdlog::debug("length is {}", encryptedKeyHex_ptr->length());

        vector<string> public_key_vect = GetBLSPubKey(encryptedKeyHex_ptr->c_str());
        for (uint8_t i = 0; i < 4; i++) {
            result["blsPublicKeyShare"][i] = public_key_vect.at(i);
            result["BlsPublicKeyShare"][i] = public_key_vect.at(i);
        }

    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    //debug_print();

    return result;
}

Json::Value SGXWalletServer::complaintResponseImpl(const string &_polyName, int _ind) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    try {
        if (!checkName(_polyName, "POLY")) {
            throw SGXException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        string shareG2_name = "shareG2_" + _polyName + "_" + to_string(_ind) + ":";
        shared_ptr<string> shareG2_ptr = readFromDb(shareG2_name);

        string DHKey = decrypt_DHKey(_polyName, _ind);

        result["share*G2"] = *shareG2_ptr;
        result["dhKey"] = DHKey;
        result["DHKey"] = DHKey;

    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;

}

Json::Value SGXWalletServer::multG2Impl(const string &_x) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    try {
        vector<string> xG2_vect = mult_G2(_x);
        for (uint8_t i = 0; i < 4; i++) {
            result["x*G2"][i] = xG2_vect.at(i);
        }

    } catch (SGXException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value SGXWalletServer::isPolyExistsImpl(const string &_polyName) {
    Json::Value result;
    try {
        std::shared_ptr<std::string> poly_str_ptr = LevelDB::getLevelDb()->readString(_polyName);
        result["IsExist"] = true;
        result["exists"] = true;
        result["status"] = 0;
        result["errorMessage"] = "";
        if (poly_str_ptr == nullptr) {
            result["IsExist"] = false;
            result["exists"] = false;
            result["status"] = 0;
            result["errorMessage"] = "";
        }
    } catch (SGXException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        result["IsExist"] = false;
        result["exists"] = false;
    }

    return result;
}

Json::Value SGXWalletServer::getServerStatusImpl() {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    return result;
}


Json::Value SGXWalletServer::generateDKGPoly(const string &_polyName, int _t) {
    lock_guard<recursive_mutex> lock(m);
    return generateDKGPolyImpl(_polyName, _t);
}

Json::Value SGXWalletServer::getVerificationVector(const string &_polynomeName, int _t, int _n) {
    lock_guard<recursive_mutex> lock(m);
    return getVerificationVectorImpl(_polynomeName, _t, _n);
}

Json::Value SGXWalletServer::getSecretShare(const string &_polyName, const Json::Value &_publicKeys, int t, int n) {
    lock_guard<recursive_mutex> lock(m);
    return getSecretShareImpl(_polyName, _publicKeys, t, n);
}

Json::Value
SGXWalletServer::dkgVerification(const string &_publicShares, const string &ethKeyName, const string &SecretShare,
                                 int t,
                                 int n, int index) {
    lock_guard<recursive_mutex> lock(m);
    return dkgVerificationImpl(_publicShares, ethKeyName, SecretShare, t, n, index);
}

Json::Value
SGXWalletServer::createBLSPrivateKey(const string &blsKeyName, const string &ethKeyName, const string &polyName,
                                     const string &SecretShare, int t, int n) {
    lock_guard<recursive_mutex> lock(m);
    return createBLSPrivateKeyImpl(blsKeyName, ethKeyName, polyName, SecretShare, t, n);
}

Json::Value SGXWalletServer::getBLSPublicKeyShare(const string &blsKeyName) {
    lock_guard<recursive_mutex> lock(m);
    return getBLSPublicKeyShareImpl(blsKeyName);
}


Json::Value SGXWalletServer::generateECDSAKey() {
    lock_guard<recursive_mutex> lock(m);
    return generateECDSAKeyImpl();
}

Json::Value SGXWalletServer::renameECDSAKey(const string &_keyName, const string &_tmpKeyName) {
    lock_guard<recursive_mutex> lock(m);
    return renameECDSAKeyImpl(_keyName, _tmpKeyName);
}

Json::Value SGXWalletServer::getPublicECDSAKey(const string &_keyName) {
    lock_guard<recursive_mutex> lock(m);
    return getPublicECDSAKeyImpl(_keyName);
}


Json::Value SGXWalletServer::ecdsaSignMessageHash(int _base, const string &_keyShareName, const string &_messageHash) {
    lock_guard<recursive_mutex> lock(m);
    spdlog::debug("MessageHash first {}", _messageHash);
    return ecdsaSignMessageHashImpl(_base, _keyShareName, _messageHash);
}


Json::Value
SGXWalletServer::importBLSKeyShare(const string &_keyShare, const string &_keyShareName, int _t, int _n,
                                   int index) {
    lock_guard<recursive_mutex> lock(m);
    return importBLSKeyShareImpl(_keyShare, _keyShareName, _t, _n, index);
}

Json::Value SGXWalletServer::blsSignMessageHash(const string &_keyShareName, const string &_messageHash, int _t, int _n,
                                                int _signerIndex) {
    lock_guard<recursive_mutex> lock(m);
    return blsSignMessageHashImpl(_keyShareName, _messageHash, _t, _n, _signerIndex);
}

Json::Value SGXWalletServer::importECDSAKey(const string &_key, const string &_keyName) {
    lock_guard<recursive_mutex> lock(m);
    return importECDSAKeyImpl(_key, _keyName);
}

Json::Value SGXWalletServer::complaintResponse(const string &polyName, int ind) {
    lock_guard<recursive_mutex> lock(m);
    return complaintResponseImpl(polyName, ind);
}

Json::Value SGXWalletServer::multG2(const string &x) {
    lock_guard<recursive_mutex> lock(m);
    return multG2Impl(x);
}

Json::Value SGXWalletServer::isPolyExists(const string &polyName) {
    lock_guard<recursive_mutex> lock(m);
    return isPolyExistsImpl(polyName);
}

Json::Value SGXWalletServer::getServerStatus() {
    lock_guard<recursive_mutex> lock(m);
    return getServerStatusImpl();
}

shared_ptr<string> SGXWalletServer::readFromDb(const string &name, const string &prefix) {

    auto dataStr = LevelDB::getLevelDb()->readString(prefix + name);

    if (dataStr == nullptr) {
        throw SGXException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exist");
    }

    return dataStr;
}

shared_ptr<string> SGXWalletServer::readKeyShare(const string &_keyShareName) {

    auto keyShareStr = LevelDB::getLevelDb()->readString("BLSKEYSHARE:" + _keyShareName);

    if (keyShareStr == nullptr) {
        throw SGXException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name does not exist");
    }

    return keyShareStr;

}

void SGXWalletServer::writeKeyShare(const string &_keyShareName, const string &_value, int _index, int _n, int _t) {

    Json::Value val;
    Json::FastWriter writer;

    val["value"] = _value;
    val["t"] = _t;
    val["index"] = _index;
    val["n'"] = _n;

    string json = writer.write(val);

    auto key = "BLSKEYSHARE:" + _keyShareName;

    if (LevelDB::getLevelDb()->readString(_keyShareName) != nullptr) {
        throw SGXException(KEY_SHARE_ALREADY_EXISTS, "Key share with this name already exists");
    }

    LevelDB::getLevelDb()->writeString(key, _value);
}

void SGXWalletServer::writeDataToDB(const string &Name, const string &value) {
    Json::Value val;
    Json::FastWriter writer;

    val["value"] = value;
    string json = writer.write(val);

    auto key = Name;

    if (LevelDB::getLevelDb()->readString(Name) != nullptr) {
        spdlog::info("name {}", Name, " already exists");
        throw SGXException(KEY_SHARE_ALREADY_EXISTS, "Key share already exists");
    }

    LevelDB::getLevelDb()->writeString(key, value);

}

