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


#include "RPCException.h"
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



bool isStringDec( string & str){
  auto res = find_if_not(str.begin(), str.end(), [](char c)->bool{
    return isdigit(c);
  });
  return !str.empty() && res == str.end();
}


SGXWalletServer *s = nullptr;
HttpServer *hs = nullptr;

SGXWalletServer::SGXWalletServer(AbstractServerConnector &connector,
                                 serverVersion_t type)
        : AbstractStubServer(connector, type) {}

void debug_print(){
  cout << "HERE ARE YOUR KEYS: " << endl;
  class MyVisitor: public LevelDB::KeyVisitor {
  public:
    virtual void visitDBKey(const char* _data){
      cout << _data << endl;
    }
  };

  MyVisitor v;

  LevelDB::getLevelDb()->visitKeys(&v, 100000000);
}

int init_https_server(bool check_certs) {

  string rootCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.pem";
  string keyCAPath = string(SGXDATA_FOLDER) + "cert_data/rootCA.key";

  if (access(rootCAPath.c_str(), F_OK) != 0 || access(keyCAPath.c_str(), F_OK) != 0){
    spdlog::info("YOU DO NOT HAVE ROOT CA CERTIFICATE");
    spdlog::info("ROOT CA CERTIFICATE IS GOING TO BE CREATED");

    string genRootCACert = "cd cert && ./create_CA";

    if (system(genRootCACert.c_str()) == 0){
      spdlog::info("ROOT CA CERTIFICATE IS SUCCESSFULLY GENERATED");
    }
    else{
      spdlog::info("ROOT CA CERTIFICATE GENERATION FAILED");
      exit(-1);
    }
  }

  string certPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.crt";
  string keyPath = string(SGXDATA_FOLDER) + "cert_data/SGXServerCert.key";

  if (access(certPath.c_str(), F_OK) != 0 || access(certPath.c_str(), F_OK) != 0){
    spdlog::info("YOU DO NOT HAVE SERVER CERTIFICATE");
    spdlog::info("SERVER CERTIFICATE IS GOING TO BE CREATED");

    string genCert = "cd cert && ./create_server_cert";

    if (system(genCert.c_str()) == 0){
      spdlog::info("SERVER CERTIFICATE IS SUCCESSFULLY GENERATED");
    }
    else{
      spdlog::info("SERVER CERTIFICATE GENERATION FAILED");
      exit(-1);
    }
  }

  hs = new HttpServer(BASE_PORT, certPath, keyPath, rootCAPath, check_certs, 64);
  s = new SGXWalletServer(*hs,
                      JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)

  if (!s->StartListening()) {
    spdlog::info("SGX Server could not start listening");
    exit(-1);
  }
  else{
    spdlog::info("SGX Server started on port {}", BASE_PORT);
  }
  return 0;
}


int init_http_server() { //without ssl

  hs = new HttpServer(BASE_PORT + 3);
  s = new SGXWalletServer(*hs,
                          JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
  if (!s->StartListening()) {
    spdlog::info("Server could not start listening");
    exit(-1);
  }
  return 0;
}

Json::Value
importBLSKeyShareImpl(const string &_keyShare, const string &_keyShareName, int t, int n, int index) {
    Json::Value result;

    int errStatus = UNKNOWN_ERROR;
    char *errMsg = (char *) calloc(BUF_LEN, 1);

    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKeyShare"] = "";

    char *encryptedKeyShareHex = nullptr;

    try {
//        if ( !checkName(_keyShare, "BLS_KEY")){
//          throw RPCException(INVALID_POLY_NAME, "Invalid BLSKey name");
//        }
        encryptedKeyShareHex = encryptBLSKeyShare2Hex(&errStatus, errMsg, _keyShare.c_str());

        if (encryptedKeyShareHex == nullptr) {
            throw RPCException(UNKNOWN_ERROR, "");
        }

        if (errStatus != 0) {
            throw RPCException(errStatus, errMsg);
        }

        result["encryptedKeyShare"] = string(encryptedKeyShareHex);

        writeKeyShare(_keyShareName, encryptedKeyShareHex, index, n , t);

    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    if (encryptedKeyShareHex != nullptr) {
        free(encryptedKeyShareHex);
    }

    return result;
}

Json::Value blsSignMessageHashImpl(const string &keyShareName, const string &messageHash,int t, int n, int signerIndex) {
    Json::Value result;
    result["status"] = -1;
    result["errorMessage"] = "Unknown server error";
    result["signatureShare"] = "";

    char *signature = (char *) calloc(BUF_LEN, 1);

    shared_ptr <string> value = nullptr;

    try {
      if ( !checkName(keyShareName, "BLS_KEY")){
        throw RPCException(INVALID_POLY_NAME, "Invalid BLSKey name");
      }
      string cutHash = messageHash;
      if (cutHash[0] == '0' && (cutHash[1] == 'x'||cutHash[1] == 'X')){
        cutHash.erase(cutHash.begin(), cutHash.begin() + 2);
      }
      while (cutHash[0] == '0'){
        cutHash.erase(cutHash.begin(), cutHash.begin() + 1);
      }

      if ( !checkHex(cutHash)){
        throw RPCException(INVALID_HEX, "Invalid hash");
      }

      value = readFromDb(keyShareName);
    } catch (RPCException _e) {
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
        if (!bls_sign(value->c_str(), messageHash.c_str(), t, n, signerIndex, signature)) {
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


Json::Value importECDSAKeyImpl(const string &key, const string &keyName) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";
    return result;
}


Json::Value generateECDSAKeyImpl() {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";

    spdlog::info("Calling method generateECDSAKey");

    vector<string>keys;

    try {
        keys = gen_ecdsa_key();

        if (keys.size() == 0 ) {
            throw RPCException(UNKNOWN_ERROR, "key was not generated");
        }

        string keyName = "NEK:" + keys.at(2);

        if (DEBUG_PRINT) {
          spdlog::info("write encr key {}", keys.at(0));
          spdlog::info("keyname length is {}", keyName.length());
          spdlog::info("key name generated: {}", keyName);
        }

        writeDataToDB(keyName, keys.at(0));

        result["encryptedKey"] = keys.at(0);
        result["publicKey"] = keys.at(1);
        result["keyName"] = keyName;

    } catch (RPCException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value renameECDSAKeyImpl(const string& KeyName, const string& tempKeyName){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  result["encryptedKey"] = "";

  try {

    string prefix = tempKeyName.substr(0,8);
    if (prefix != "tmp_NEK:") {
     throw RPCException(UNKNOWN_ERROR, "wrong temp key name");
    }
    prefix = KeyName.substr(0,12);
    if (prefix != "NEK_NODE_ID:") {
      throw RPCException(UNKNOWN_ERROR, "wrong key name");
    }
    string postfix = KeyName.substr(12, KeyName.length());
    if (!isStringDec(postfix)){
      throw RPCException(UNKNOWN_ERROR, "wrong key name");
    }

    shared_ptr<string> key_ptr = readFromDb(tempKeyName);
    cerr << "new key name is " << KeyName <<endl;
    writeDataToDB(KeyName, *key_ptr);
    LevelDB::getLevelDb()->deleteTempNEK(tempKeyName);

  } catch (RPCException &_e) {
    cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
  }

  return result;
}


Json::Value ecdsaSignMessageHashImpl(int base, const string &_keyName, const string &messageHash) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["signature_v"] = "";
    result["signature_r"] = "";
    result["signature_s"] = "";

    vector<string> sign_vect(3);

    if (DEBUG_PRINT) {
      spdlog::info("entered ecdsaSignMessageHashImpl {}", messageHash, "length {}", messageHash.length());
    }

    try {

      string cutHash = messageHash;
      if (cutHash[0] == '0' && (cutHash[1] == 'x'||cutHash[1] == 'X')){
        cutHash.erase(cutHash.begin(), cutHash.begin() + 2);
      }
      while (cutHash[0] == '0'){
        cutHash.erase(cutHash.begin(), cutHash.begin() + 1);
      }

      if (DEBUG_PRINT) {
        spdlog::info("Hash handled  {}", cutHash);
      }

      if ( !checkECDSAKeyName(_keyName)){
        throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
      }
      if ( !checkHex(cutHash)){
        throw RPCException(INVALID_HEX, "Invalid hash");
      }
      if ( base <= 0 || base > 32){
        throw RPCException(-22, "Invalid base");
      }

      shared_ptr<string> key_ptr = readFromDb(_keyName,"");

      sign_vect = ecdsa_sign_hash(key_ptr->c_str(), cutHash.c_str(), base);
      if (sign_vect.size() != 3 ){
        throw RPCException(INVALID_ECSDA_SIGNATURE, "Invalid ecdsa signature");
      }

      if (DEBUG_PRINT) {
        spdlog::info("got signature_s  {}", sign_vect.at(2));
      }

      result["signature_v"] = sign_vect.at(0);
      result["signature_r"] = sign_vect.at(1);
      result["signature_s"] = sign_vect.at(2);

    } catch (RPCException &_e) {
        cerr << "err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value getPublicECDSAKeyImpl(const string& keyName){
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["publicKey"] = "";

    spdlog::info("Calling method getPublicECDSAKey");

    string Pkey;

    try {
         if ( !checkECDSAKeyName(keyName)){
           throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
         }
         shared_ptr<string> key_ptr = readFromDb(keyName);
         Pkey = get_ecdsa_pubkey( key_ptr->c_str());
         if (DEBUG_PRINT) {
           spdlog::info("PublicKey {}", Pkey);
           spdlog::info("PublicKey length {}", Pkey.length());
         }
         result["publicKey"] = Pkey;

    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value generateDKGPolyImpl(const string& polyName, int t) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    //result["encryptedPoly"] = "";

    string encrPolyHex;

    try {
      if ( !checkName(polyName, "POLY")){
        throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name, it should be like POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1");
      }
      if ( t <= 0 || t > 32){
        throw RPCException(INVALID_DKG_PARAMS, "Invalid parameter t ");
      }
      encrPolyHex = gen_dkg_poly(t);
      writeDataToDB(polyName, encrPolyHex);

      //result["encryptedPoly"] = encrPolyHex;
    } catch (RPCException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value getVerificationVectorImpl(const string& polyName, int t, int n) {

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";

  vector <vector<string>> verifVector;
  try {
    if ( !checkName(polyName, "POLY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
    }
    if( !check_n_t(t, n)){
      throw RPCException(INVALID_DKG_PARAMS, "Invalid parameters: n or t ");
    }

    shared_ptr<string> encr_poly_ptr = readFromDb(polyName);

    verifVector = get_verif_vect(encr_poly_ptr->c_str(), t, n);
    //cerr << "verif vect size " << verifVector.size() << endl;

    for ( int i = 0; i < t; i++){
      vector<string> cur_coef = verifVector.at(i);
      for ( int j = 0; j < 4; j++ ){
        result["verificationVector"][i][j] = cur_coef.at(j);
      }
    }

  } catch (RPCException &_e) {
    cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["verificationVector"] = "";
  }

  return result;
}

Json::Value getSecretShareImpl(const string& polyName, const Json::Value& publicKeys, int t, int n){
    spdlog::info("enter getSecretShareImpl");
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {
        if (publicKeys.size() != n){
          throw RPCException(INVALID_DKG_PARAMS, "wrong number of public keys");
        }
        if ( !checkName(polyName, "POLY")){
          throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if( !check_n_t(t, n)){
          throw RPCException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
        }

        shared_ptr<string> encr_poly_ptr = readFromDb(polyName);

        vector<string> pubKeys_vect;
        for ( int i = 0; i < n ; i++) {
            std::cerr << "publicKeys " << i << " is " << publicKeys[i].asString() <<std::endl;
            if ( !checkHex(publicKeys[i].asString(), 64)){
              throw RPCException(INVALID_HEX, "Invalid public key");
            }
            pubKeys_vect.push_back(publicKeys[i].asString());
        }

        string s = get_secret_shares(polyName, encr_poly_ptr->c_str(), pubKeys_vect, t, n);
        //cerr << "result is " << s << endl;
        result["secretShare"] = s;

    } catch (RPCException &_e) {
        //cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        result["secretShare"] = "";
    }

    return result;
}

Json::Value dkgVerificationImpl(const string& publicShares, const string& ethKeyName,
                                  const string& SecretShare, int t, int n, int ind){

  spdlog::info("enter dkgVerificationImpl");

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  result["result"] = true;

  try {

    if ( !checkECDSAKeyName(ethKeyName)){
      throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
    }
    if( !check_n_t(t, n) || ind > n || ind < 0){
      throw RPCException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
    }
    if ( !checkHex(SecretShare, SECRET_SHARE_NUM_BYTES)){
      throw RPCException(INVALID_HEX, "Invalid Secret share");
    }
    if (publicShares.length() != 256 * t){
      throw RPCException(INVALID_DKG_PARAMS, "Invalid length of public shares");
    }

    shared_ptr<string> encryptedKeyHex_ptr = readFromDb(ethKeyName);

    if ( !VerifyShares(publicShares.c_str(), SecretShare.c_str(), encryptedKeyHex_ptr->c_str(), t, n, ind )){
      result["result"] = false;
    }

  } catch (RPCException &_e) {
    //cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["result"] = false;
  }

  return result;
}

Json::Value createBLSPrivateKeyImpl(const string & blsKeyName, const string& ethKeyName, const string& polyName, const string & SecretShare, int t, int n){

  spdlog::info("createBLSPrivateKeyImpl entered");

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";

  try {

    if (SecretShare.length() != n * 192){
      spdlog::info("wrong length of secret shares - {}", SecretShare.length());
      spdlog::info("secret shares - {}", SecretShare);
      throw RPCException(INVALID_SECRET_SHARES_LENGTH, "Invalid secret share length");
    }
    if ( !checkECDSAKeyName(ethKeyName)){
      throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
    }
    if ( !checkName(polyName, "POLY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
    }
    if ( !checkName(blsKeyName, "BLS_KEY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid BLS key name");
    }
    if( !check_n_t(t, n)){
      throw RPCException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
    }
    vector<string> sshares_vect;
    if (DEBUG_PRINT) {
      spdlog::info("secret shares from json are - {}", SecretShare);
    }

    shared_ptr<string> encryptedKeyHex_ptr = readFromDb(ethKeyName);

    bool res = CreateBLSShare(blsKeyName, SecretShare.c_str(), encryptedKeyHex_ptr->c_str());
     if (res){
         spdlog::info("BLS KEY SHARE CREATED ");
     }
     else {
       throw RPCException(-122, "Error while creating BLS key share");
     }

     for ( int i = 0; i < n; i++){
       string name = polyName + "_" + to_string(i) + ":";
       LevelDB::getLevelDb() -> deleteDHDKGKey(name);
       string shareG2_name = "shareG2_" + polyName + "_" + to_string(i) + ":";
       LevelDB::getLevelDb() -> deleteKey(shareG2_name);
     }

  } catch (RPCException &_e) {
    //cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;

  }

  return result;
}

Json::Value getBLSPublicKeyShareImpl(const string & blsKeyName){

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {
      if ( !checkName(blsKeyName, "BLS_KEY")){
        throw RPCException(INVALID_POLY_NAME, "Invalid BLSKey name");
      }
      shared_ptr<string> encryptedKeyHex_ptr = readFromDb(blsKeyName);
      if (DEBUG_PRINT) {
        spdlog::info("encr_bls_key_share is {}", *encryptedKeyHex_ptr);
        spdlog::info("length is {}", encryptedKeyHex_ptr->length());
       //cerr << "encr_bls_key_share is " << *encryptedKeyHex_ptr << endl;
       // cerr << "length is " << encryptedKeyHex_ptr->length() << endl;
      }
      vector<string> public_key_vect = GetBLSPubKey(encryptedKeyHex_ptr->c_str());
      for ( uint8_t i = 0; i < 4; i++) {
        result["blsPublicKeyShare"][i] = public_key_vect.at(i);
      }

    } catch (RPCException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    //debug_print();

    return result;
}

Json::Value complaintResponseImpl(const string& polyName, int ind){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  try {
    if ( !checkName(polyName, "POLY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
    }
    string shareG2_name = "shareG2_" + polyName + "_" + to_string(ind) + ":";
    shared_ptr<string> shareG2_ptr = readFromDb(shareG2_name);

    string DHKey = decrypt_DHKey(polyName, ind);

    result["share*G2"] = *shareG2_ptr;
    result["dhKey"] = DHKey;

  } catch (RPCException &_e) {
    cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
  }

  return result;

}

Json::Value multG2Impl(const string& x){
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    try {
        spdlog::info("multG2Impl try ");
        vector<string> xG2_vect = mult_G2(x);
        for ( uint8_t i = 0; i < 4; i++) {
            result["x*G2"][i] = xG2_vect.at(i);
        }

    } catch (RPCException &_e) {
        cerr << " err str " << _e.errString << endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value isPolyExistsImpl(const string& polyName){
    Json::Value result;
    try {
    std::shared_ptr<std::string> poly_str_ptr = LevelDB::getLevelDb()->readString(polyName);
    result["IsExist"] = true;
    result["status"] = 0;
    result["errorMessage"] = "";
    if (poly_str_ptr == nullptr){
        result["IsExist"] = false;
        result["status"] = 0;
        result["errorMessage"] = "";
    }
    } catch (RPCException &_e) {
      std::cerr << " err str " << _e.errString << std::endl;
      result["status"] = _e.status;
      result["errorMessage"] = _e.errString;
      result["IsExist"] = false;
    }

    return result;
}

Json::Value getServerStatusImpl() {

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";

  return result;
}


Json::Value SGXWalletServer::generateDKGPoly(const string& polyName, int t){
  spdlog::info("entered generateDKGPoly");
  lock_guard<recursive_mutex> lock(m);
  return generateDKGPolyImpl(polyName, t);
}

Json::Value SGXWalletServer::getVerificationVector(const string& polyName, int t, int n){
  lock_guard<recursive_mutex> lock(m);
  return getVerificationVectorImpl(polyName, t, n);
}

Json::Value SGXWalletServer::getSecretShare(const string& polyName, const Json::Value& publicKeys, int t, int n){
    lock_guard<recursive_mutex> lock(m);
    return getSecretShareImpl(polyName, publicKeys, t, n);
}

Json::Value  SGXWalletServer::dkgVerification( const string& publicShares, const string& ethKeyName, const string& SecretShare, int t, int n, int index){
  lock_guard<recursive_mutex> lock(m);
  return dkgVerificationImpl(publicShares, ethKeyName, SecretShare, t, n, index);
}

Json::Value SGXWalletServer::createBLSPrivateKey(const string & blsKeyName, const string& ethKeyName, const string& polyName, const string& SecretShare, int t, int n){
  lock_guard<recursive_mutex> lock(m);
  return createBLSPrivateKeyImpl(blsKeyName, ethKeyName, polyName, SecretShare, t, n);
}

Json::Value SGXWalletServer::getBLSPublicKeyShare(const string & blsKeyName){
    lock_guard<recursive_mutex> lock(m);
    return getBLSPublicKeyShareImpl(blsKeyName);
}



Json::Value SGXWalletServer::generateECDSAKey() {
  lock_guard<recursive_mutex> lock(m);
    return generateECDSAKeyImpl();
}

Json::Value SGXWalletServer::renameECDSAKey(const string& KeyName, const string& tempKeyName){
  lock_guard<recursive_mutex> lock(m);
  return renameECDSAKeyImpl(KeyName, tempKeyName);
}

Json::Value SGXWalletServer::getPublicECDSAKey(const string &_keyName) {
  lock_guard<recursive_mutex> lock(m);
  return getPublicECDSAKeyImpl(_keyName);
}


Json::Value SGXWalletServer::ecdsaSignMessageHash(int base, const string &_keyName, const string &messageHash ) {
  lock_guard<recursive_mutex> lock(m);
  spdlog::info("entered ecdsaSignMessageHash");
  if (DEBUG_PRINT) {
    spdlog::info("MessageHash first {}", messageHash);
  }
  return ecdsaSignMessageHashImpl(base,_keyName, messageHash);
}


Json::Value
SGXWalletServer::importBLSKeyShare(const string &_keyShare, const string &_keyShareName, int t, int n,
                                    int index) {
    lock_guard<recursive_mutex> lock(m);
    return importBLSKeyShareImpl(_keyShare, _keyShareName, t, n, index );
}

Json::Value SGXWalletServer::blsSignMessageHash(const string &keyShareName, const string &messageHash, int t, int n,
                                        int signerIndex) {
    lock_guard<recursive_mutex> lock(m);
    return blsSignMessageHashImpl(keyShareName, messageHash, t, n, signerIndex);
}

Json::Value SGXWalletServer::importECDSAKey(const string &key, const string &keyName) {
  lock_guard<recursive_mutex> lock(m);
  return importECDSAKeyImpl(key, keyName);
}

Json::Value SGXWalletServer::complaintResponse(const string& polyName, int ind){
  lock_guard<recursive_mutex> lock(m);
  return complaintResponseImpl(polyName, ind);
}

Json::Value SGXWalletServer::multG2(const string& x){
    lock_guard<recursive_mutex> lock(m);
    return multG2Impl(x);
}

Json::Value SGXWalletServer::isPolyExists(const string& polyName){
    lock_guard<recursive_mutex> lock(m);
    return isPolyExistsImpl(polyName);
}

Json::Value SGXWalletServer::getServerStatus() {
  lock_guard<recursive_mutex> lock(m);
  return getServerStatusImpl();
}

shared_ptr<string> readFromDb(const string & name, const string & prefix) {

  auto dataStr = LevelDB::getLevelDb()->readString(prefix + name);

  if (dataStr == nullptr) {
    throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exist");
  }

  return dataStr;
}

shared_ptr<string> readKeyShare(const string &_keyShareName) {

    auto keyShareStr = LevelDB::getLevelDb()->readString("BLSKEYSHARE:" + _keyShareName);

    if (keyShareStr == nullptr) {
        throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name does not exist");
    }

    return keyShareStr;

}

void writeKeyShare(const string &_keyShareName, const string &value, int index, int n, int t) {

    Json::Value val;
    Json::FastWriter writer;

    val["value"] = value;
    val["t"] = t;
    val["index"] = index;
    val["n'"] = n;

    string json = writer.write(val);

    auto key = "BLSKEYSHARE:" + _keyShareName;

    if (LevelDB::getLevelDb()->readString(_keyShareName) != nullptr) {
        throw RPCException(KEY_SHARE_ALREADY_EXISTS, "Key share with this name already exists");
    }

    LevelDB::getLevelDb()->writeString(key, value);
}

void writeDataToDB(const string & Name, const string &value) {
  Json::Value val;
  Json::FastWriter writer;

  val["value"] = value;
  string json = writer.write(val);

  auto key = Name;

  if (LevelDB::getLevelDb()->readString(Name) != nullptr) {
    spdlog::info("name {}", Name, " already exists");
    throw RPCException(KEY_SHARE_ALREADY_EXISTS, "Data with this name already exists");
  }

  LevelDB::getLevelDb()->writeString(key, value);
  if (DEBUG_PRINT) {
    spdlog::info("{} ", Name, " is written to db ");
  }
}

