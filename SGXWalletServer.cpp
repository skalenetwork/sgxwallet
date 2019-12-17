//
// Created by kladko on 05.09.19.
//


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


//#if __cplusplus < 201412L
//#error expecting C++17 standard
//#endif

//#include <boost/filesystem.hpp>


bool isStringDec( std::string & str){
  auto res = std::find_if_not(str.begin(), str.end(), [](char c)->bool{
    return std::isdigit(c);
  });
  return !str.empty() && res == str.end();
}


SGXWalletServer *s = nullptr;
HttpServer *hs = nullptr;

SGXWalletServer::SGXWalletServer(AbstractServerConnector &connector,
                                 serverVersion_t type)
        : AbstractStubServer(connector, type) {}

void debug_print(){
  std::cout << "HERE ARE YOUR KEYS: " << std::endl;
  class MyVisitor: public LevelDB::KeyVisitor {
  public:
    virtual void visitDBKey(const char* _data){
      std::cout << _data << std::endl;
    }
  };

  MyVisitor v;

  levelDb->visitKeys(&v, 100000000);
}

int init_server() {
  std::string rootCAPath = "cert/rootCA.crt";
  std::string keyCAPath = "cert/rootCA.pem";

  if (access(rootCAPath.c_str(), F_OK) != 0 || access(keyCAPath.c_str(), F_OK) != 0){
    std::cerr << "YOU DO NOT HAVE ROOT CA CERTIFICATE" << std::endl;
    std::cerr << "ROOT CA CERTIFICATE IS GOING TO BE CREATED" << std::endl;

    std::string genRootCACert = "cd cert && ./create_CA";

    if (system(genRootCACert.c_str()) == 0){
      std::cerr << "ROOT CA ERTIFICATE IS SUCCESSFULLY GENERATED" << std::endl;
    }
    else{
      std::cerr << "ROOT CA CERTIFICATE GENERATION FAILED" << std::endl;
      exit(-1);
    }
  }

  std::string certPath = "cert/SGXServerCert.crt";
  std::string keyPath = "cert/SGXServerCert.key";

  if (access(certPath.c_str(), F_OK) != 0 || access(certPath.c_str(), F_OK) != 0){
    std::cerr << "YOU DO NOT HAVE SERVER CERTIFICATE " << std::endl;
    std::cerr << "SERVER CERTIFICATE IS GOING TO BE CREATED" << std::endl;

    std::string genCert = "cd cert && ./create_server_cert";

    if (system(genCert.c_str()) == 0){
       std::cerr << "SERVER CERTIFICATE IS SUCCESSFULLY GENERATED" << std::endl;
    }
    else{
      std::cerr << "SERVER CERTIFICATE GENERATION FAILED" << std::endl;
      exit(-1);
    }
  }

  hs = new HttpServer(1026, certPath, keyPath, 10);
  s = new SGXWalletServer(*hs,
                      JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)

  if (!s->StartListening()) {
    cerr << "Server could not start listening" << endl;
    exit(-1);
  }
  return 0;
}

//int init_server() { //without ssl
//
//  hs = new HttpServer(1028);
//  s = new SGXWalletServer(*hs,
//                          JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
//  if (!s->StartListening()) {
//    cerr << "Server could not start listening" << endl;
//    exit(-1);
//  }
//  return 0;
//}

Json::Value
importBLSKeyShareImpl(const std::string &_keyShare, const std::string &_keyShareName, int t, int n, int index) {
    Json::Value result;

    int errStatus = UNKNOWN_ERROR;
    char *errMsg = (char *) calloc(BUF_LEN, 1);

    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKeyShare"] = "";

    try {
//        if ( !checkName(_keyShare, "BLS_KEY")){
//          throw RPCException(INVALID_POLY_NAME, "Invalid BLSKey name");
//        }
        char *encryptedKeyShareHex = encryptBLSKeyShare2Hex(&errStatus, errMsg, _keyShare.c_str());

        if (encryptedKeyShareHex == nullptr) {
            throw RPCException(UNKNOWN_ERROR, "");
        }

        if (errStatus != 0) {
            throw RPCException(errStatus, errMsg);
        }

        result["encryptedKeyShare"] = encryptedKeyShareHex;

        writeKeyShare(_keyShareName, encryptedKeyShareHex, index, n , t);

    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}

Json::Value blsSignMessageHashImpl(const std::string &keyShareName, const std::string &messageHash,int t, int n, int signerIndex) {
    Json::Value result;
    result["status"] = -1;
    result["errorMessage"] = "Unknown server error";
    result["signatureShare"] = "";

    //int errStatus = UNKNOWN_ERROR;
    //char *errMsg = (char *) calloc(BUF_LEN, 1);
    char *signature = (char *) calloc(BUF_LEN, 1);

    shared_ptr <std::string> value = nullptr;

    try {
      if ( !checkName(keyShareName, "BLS_KEY")){
        throw RPCException(INVALID_POLY_NAME, "Invalid BLSKey name");
      }

      value = readFromDb(keyShareName);
    } catch (RPCException _e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        return result;
    } catch (...) {
        std::exception_ptr p = std::current_exception();
        printf("Exception %s \n", p.__cxa_exception_type()->name());
        result["status"] = -1;
        result["errorMessage"] = "Read key share has thrown exception:";
        return result;
    }

    try {
        if (!sign(value->c_str(), messageHash.c_str(), t, n, signerIndex, signature)) {
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


Json::Value importECDSAKeyImpl(const std::string &key, const std::string &keyName) {
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

    cerr << "Calling method generateECDSAKey"  << endl;

    std::vector<std::string>keys;

    try {
        keys = gen_ecdsa_key();

        if (keys.size() == 0 ) {
            throw RPCException(UNKNOWN_ERROR, "key was not generated");
        }
       // std::cerr << "write encr key" << keys.at(0) << std::endl;

        std::string keyName = "NEK:" + keys.at(2);

        std::cerr << "keyname length is " << keyName.length() << std::endl;
        std::cerr <<"key name generated: " << keyName << std::endl;
        //writeECDSAKey(keyName, keys.at(0));
        writeDataToDB(keyName, keys.at(0));

        result["encryptedKey"] = keys.at(0);
        result["PublicKey"] = keys.at(1);
        result["KeyName"] = keyName;

    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }
    //std::cerr << "in SGXWalletServer encr key x " << keys.at(0) << std::endl;

    return result;
}

Json::Value renameECDSAKeyImpl(const std::string& KeyName, const std::string& tempKeyName){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  result["encryptedKey"] = "";

  try {

    std::string prefix = tempKeyName.substr(0,8);
    if (prefix != "tmp_NEK:") {
     throw RPCException(UNKNOWN_ERROR, "wrong temp key name");
    }
    prefix = KeyName.substr(0,12);
    if (prefix != "NEK_NODE_ID:") {
      throw RPCException(UNKNOWN_ERROR, "wrong key name");
    }
    std::string postfix = KeyName.substr(12, KeyName.length());
    if (!isStringDec(postfix)){
      throw RPCException(UNKNOWN_ERROR, "wrong key name");
    }

    std::shared_ptr<std::string> key_ptr = readFromDb(tempKeyName);
    std::cerr << "new key name is " << KeyName <<std::endl;
    writeDataToDB(KeyName, *key_ptr);
    levelDb->deleteTempNEK(tempKeyName);

  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
  }

  return result;
}


Json::Value ecdsaSignMessageHashImpl(int base, const std::string &_keyName, const std::string &messageHash) {
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["signature_v"] = "";
    result["signature_r"] = "";
    result["signature_s"] = "";

    std::vector<std::string> sign_vect(3);
    std::cerr << "entered ecdsaSignMessageHashImpl" <<  messageHash << "length " << messageHash.length() << std::endl;
    std::string cutHash = messageHash;
    if (cutHash[0] == '0' && (cutHash[1] == 'x'||cutHash[1] == 'X')){
      cutHash.erase(cutHash.begin(), cutHash.begin()+2);
    }
    while (cutHash[0] == '0'){
      cutHash.erase(cutHash.begin(), cutHash.begin()+1);
    }
    std::cerr << "Hash handled " << cutHash << std::endl;
    try {
      if ( !checkECDSAKeyName(_keyName)){
        throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
      }
      if ( !checkHex(cutHash)){
        throw RPCException(INVALID_HEX, "Invalid hash");
      }
      if ( base <= 0 || base > 32){
        throw RPCException(-22, "Invalid base");
      }


       std::shared_ptr<std::string> key_ptr = readFromDb(_keyName,"");
      // std::cerr << "read encr key" << *key_ptr << std::endl;
       sign_vect = ecdsa_sign_hash(key_ptr->c_str(),cutHash.c_str(), base);

      std::cerr << "got signature_s " << sign_vect.at(2) << std::endl;
      result["signature_v"] = sign_vect.at(0);
      result["signature_r"] = sign_vect.at(1);
      result["signature_s"] = sign_vect.at(2);

    } catch (RPCException &_e) {
        std::cerr << "err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }


    return result;
}

Json::Value getPublicECDSAKeyImpl(const std::string& keyName){
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["PublicKey"] = "";

    cerr << "Calling method getPublicECDSAKey"  << endl;


    std::string Pkey;

    try {
         if ( !checkECDSAKeyName(keyName)){
           throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
         }
         std::shared_ptr<std::string> key_ptr = readFromDb(keyName);
         Pkey = get_ecdsa_pubkey( key_ptr->c_str());
         std::cerr << "PublicKey " << Pkey << std::endl;
         std::cerr << "PublicKey length" << Pkey.length() << std::endl;
         result["PublicKey"] = Pkey;

    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    //std::cerr << "in SGXWalletServer encr key x " << keys.at(0) << std::endl;

    return result;
}

Json::Value generateDKGPolyImpl(const std::string& polyName, int t) {
   std::cerr <<  " enter generateDKGPolyImpl" << std::endl;
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    //result["encryptedPoly"] = "";

    std::string encrPolyHex;

    try {
      if ( !checkName(polyName, "POLY")){
        throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
      }
      if ( t <= 0){
        throw RPCException(INVALID_DKG_PARAMS, "Invalid parameters: n or t ");
      }
      encrPolyHex = gen_dkg_poly(t);
      writeDataToDB(polyName, encrPolyHex);
      //writeDKGPoly(polyName, encrPolyHex);
      //result["encryptedPoly"] = encrPolyHex;
    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }



    return result;
}

Json::Value getVerificationVectorImpl(const std::string& polyName, int t, int n) {

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";

  std::vector <std::vector<std::string>> verifVector;
  try {
    if ( !checkName(polyName, "POLY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
    }
    if( !check_n_t(t, n)){
      throw RPCException(INVALID_DKG_PARAMS, "Invalid parameters: n or t ");
    }

    std::shared_ptr<std::string> encr_poly_ptr = readFromDb(polyName);

    verifVector = get_verif_vect(encr_poly_ptr->c_str(), t, n);
    //std::cerr << "verif vect size " << verifVector.size() << std::endl;

    for ( int i = 0; i < t; i++){
      std::vector<std::string> cur_coef = verifVector.at(i);
      for ( int j = 0; j < 4; j++ ){
        result["Verification Vector"][i][j] = cur_coef.at(j);
      }
    }

  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["Verification Vector"] = "";
  }

  return result;
}

Json::Value getSecretShareImpl(const std::string& polyName, const Json::Value& publicKeys, int t, int n){
    std::cerr << " enter getSecretShareImpl" << std::endl;
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {
        if (publicKeys.size() != n){
            result["errorMessage"] = "wrong number of public keys";
            return result;
        }
      if ( !checkName(polyName, "POLY")){
          throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
        }
        if( !check_n_t(t, n)){
          throw RPCException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
        }

        std::shared_ptr<std::string> encr_poly_ptr = readFromDb(polyName);

        std::vector<std::string> pubKeys_vect;
        for ( int i = 0; i < n ; i++) {
            if ( !checkHex(publicKeys[i].asString(), 64)){
              throw RPCException(INVALID_HEX, "Invalid public key");
            }
            pubKeys_vect.push_back(publicKeys[i].asString());
        }

        std::string s = get_secret_shares(polyName, encr_poly_ptr->c_str(), pubKeys_vect, t, n);
        //std::cerr << "result is " << s << std::endl;
        result["SecretShare"] = s;

    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
        result["SecretShare"] = "";
    }

    return result;
}

Json::Value DKGVerificationImpl(const std::string& publicShares, const std::string& EthKeyName,
                                  const std::string& SecretShare, int t, int n, int ind){

  std::cerr << " enter DKGVerificationImpl" << std::endl;

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  result["result"] = true;

  try {

    if ( !checkECDSAKeyName(EthKeyName)){
      throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
    }
    if( !check_n_t(t, n) || ind > n || ind < 0){
      throw RPCException(INVALID_DKG_PARAMS, "Invalid DKG parameters: n or t ");
    }
//    if ( !checkHex(SecretShare, SECRET_SHARE_NUM_BYTES)){
//      throw RPCException(INVALID_HEX, "Invalid Secret share");
//    }

    //std::string keyName = polyName + "_" + std::to_string(ind);
    //std::shared_ptr<std::string> encryptedKeyHex_ptr = readFromDb(EthKeyName, "");
    std::shared_ptr<std::string> encryptedKeyHex_ptr = readFromDb(EthKeyName);


    if ( !VerifyShares(publicShares.c_str(), SecretShare.c_str(), encryptedKeyHex_ptr->c_str(),  t, n, ind )){
      result["result"] = false;
    }


  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["result"] = false;
  }

  return result;
}

Json::Value CreateBLSPrivateKeyImpl(const std::string & BLSKeyName, const std::string& EthKeyName, const std::string& polyName, const std::string & SecretShare, int t, int n){

  std::cerr << "CreateBLSPrivateKeyImpl entered" << std::endl;


  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";

  try {

    if (SecretShare.length() != n * 192){
      std::cerr << "wrong length of secret shares - " << SecretShare.length() << std::endl;
      std::cerr << "secret shares - " << SecretShare << std::endl;
      //result["errorMessage"] = "wrong length of secret shares";
      //return result;
      throw RPCException(INVALID_SECRET_SHARES_LENGTH, "Invalid secret share length");
    }
    if ( !checkECDSAKeyName(EthKeyName)){
      throw RPCException(INVALID_ECDSA_KEY_NAME, "Invalid ECDSA key name");
    }
    if ( !checkName(polyName, "POLY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
    }
    if ( !checkName(BLSKeyName, "BLS_KEY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid BLS key name");
    }
    std::vector<std::string> sshares_vect;
    std::cerr << "sshares from json are " << SecretShare << std::endl;


    std::shared_ptr<std::string> encryptedKeyHex_ptr = readFromDb(EthKeyName);

    bool res = CreateBLSShare(BLSKeyName, SecretShare.c_str(), encryptedKeyHex_ptr->c_str());
     if ( res){
         std::cerr << "BLS KEY SHARE CREATED " << std::endl;

     }
     else {
       throw RPCException(-122, "Error while creating BLS key share");
     }

     for ( int i = 0; i < n; i++){
       std::string name = polyName + "_" + std::to_string(i) + ":";
       levelDb -> deleteDHDKGKey(name);
     }

  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;

  }

  return result;
}

Json::Value GetBLSPublicKeyShareImpl(const std::string & BLSKeyName){

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {
      if ( !checkName(BLSKeyName, "BLS_KEY")){
        throw RPCException(INVALID_POLY_NAME, "Invalid BLSKey name");
      }
      std::shared_ptr<std::string> encryptedKeyHex_ptr = readFromDb(BLSKeyName);
      std::cerr << "encr_bls_key_share is " << *encryptedKeyHex_ptr << std::endl;
      std::cerr << "length is " << encryptedKeyHex_ptr->length()<< std::endl;
      std::vector<std::string> public_key_vect = GetBLSPubKey(encryptedKeyHex_ptr->c_str());
      for ( uint8_t i = 0; i < 4; i++) {
        result["BLSPublicKeyShare"][i] = public_key_vect.at(i);
      }

    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    //debug_print();

    return result;
}

Json::Value ComplaintResponseImpl(const std::string& polyName, int ind){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  try {
    if ( !checkName(polyName, "POLY")){
      throw RPCException(INVALID_POLY_NAME, "Invalid polynomial name");
    }
    std::string shareG2_name = "shareG2_" + polyName + "_" + std::to_string(ind) + ":";
    std::shared_ptr<std::string> shareG2_ptr = readFromDb(shareG2_name);

    std::string DHKey = decrypt_DHKey(polyName, ind);

    result["share*G2"] = *shareG2_ptr;
    result["DHKey"] = DHKey;

  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
  }

  return result;

}

Json::Value MultG2Impl(const std::string& x){
    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    try {
        std::cerr << "MultG2Impl try " << std::endl;
        std::vector<std::string> xG2_vect = mult_G2(x);
        for ( uint8_t i = 0; i < 4; i++) {
            result["x*G2"][i] = xG2_vect.at(i);
        }

    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    return result;
}


Json::Value SGXWalletServer::generateDKGPoly(const std::string& polyName, int t){
  std::cerr << "entered generateDKGPoly" << std::endl;
  lock_guard<recursive_mutex> lock(m);
  return generateDKGPolyImpl(polyName, t);
}

Json::Value SGXWalletServer::getVerificationVector(const std::string& polyName, int t, int n){
  lock_guard<recursive_mutex> lock(m);
  return getVerificationVectorImpl(polyName, t, n);
}

Json::Value SGXWalletServer::getSecretShare(const std::string& polyName, const Json::Value& publicKeys, int t, int n){
    lock_guard<recursive_mutex> lock(m);
    return getSecretShareImpl(polyName, publicKeys, t, n);
}

Json::Value  SGXWalletServer::DKGVerification( const std::string& publicShares, const std::string& EthKeyName, const std::string& SecretShare, int t, int n, int index){
  lock_guard<recursive_mutex> lock(m);
  return DKGVerificationImpl(publicShares, EthKeyName, SecretShare, t, n, index);
}

Json::Value SGXWalletServer::CreateBLSPrivateKey(const std::string & BLSKeyName, const std::string& EthKeyName, const std::string& polyName, const std::string& SecretShare, int t, int n){
  lock_guard<recursive_mutex> lock(m);
  return CreateBLSPrivateKeyImpl(BLSKeyName, EthKeyName, polyName, SecretShare, t, n);
}

Json::Value SGXWalletServer::GetBLSPublicKeyShare(const std::string & BLSKeyName){
    lock_guard<recursive_mutex> lock(m);
    return GetBLSPublicKeyShareImpl(BLSKeyName);
}



Json::Value SGXWalletServer::generateECDSAKey() {
  lock_guard<recursive_mutex> lock(m);
    return generateECDSAKeyImpl();
}

Json::Value SGXWalletServer::renameECDSAKey(const std::string& KeyName, const std::string& tempKeyName){
  lock_guard<recursive_mutex> lock(m);
  return renameECDSAKeyImpl(KeyName, tempKeyName);
}

Json::Value SGXWalletServer::getPublicECDSAKey(const std::string &_keyName) {
  lock_guard<recursive_mutex> lock(m);
  return getPublicECDSAKeyImpl(_keyName);
}


Json::Value SGXWalletServer::ecdsaSignMessageHash(int base, const std::string &_keyName, const std::string &messageHash ) {
  lock_guard<recursive_mutex> lock(m);
  std::cerr << "entered ecdsaSignMessageHash" << std::endl;
  std::cerr << "MessageHash first " << messageHash << std::endl;
  return ecdsaSignMessageHashImpl(base,_keyName, messageHash);
}


Json::Value
SGXWalletServer::importBLSKeyShare(const std::string &_keyShare, const std::string &_keyShareName, int t, int n,
                                    int index) {
    lock_guard<recursive_mutex> lock(m);
    return importBLSKeyShareImpl(_keyShare, _keyShareName, t, n, index );
}

Json::Value SGXWalletServer::blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash, int t, int n,
                                        int signerIndex) {
    lock_guard<recursive_mutex> lock(m);
    return blsSignMessageHashImpl(keyShareName, messageHash, t, n, signerIndex);
}

Json::Value SGXWalletServer::importECDSAKey(const std::string &key, const std::string &keyName) {
  lock_guard<recursive_mutex> lock(m);
  return importECDSAKeyImpl(key, keyName);
}

Json::Value SGXWalletServer::ComplaintResponse(const std::string& polyName, int ind){
  lock_guard<recursive_mutex> lock(m);
  return ComplaintResponseImpl(polyName, ind);
}

Json::Value SGXWalletServer::MultG2(const std::string& x){
    lock_guard<recursive_mutex> lock(m);
    return MultG2Impl(x);
}


shared_ptr<string> readFromDb(const string & name, const string & prefix) {

  auto dataStr = levelDb->readString(prefix + name);

  if (dataStr == nullptr) {
    throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exist");
  }

  return dataStr;
}

shared_ptr<string> readKeyShare(const string &_keyShareName) {

    auto keyShareStr = levelDb->readString("BLSKEYSHARE:" + _keyShareName);

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

    std::string json = writer.write(val);

    auto key = "BLSKEYSHARE:" + _keyShareName;

    if (levelDb->readString(_keyShareName) != nullptr) {
        throw RPCException(KEY_SHARE_ALREADY_EXISTS, "Key share with this name already exists");
    }

    levelDb->writeString(key, value);
}

void writeDataToDB(const string & Name, const string &value) {
  Json::Value val;
  Json::FastWriter writer;

  val["value"] = value;
  std::string json = writer.write(val);

  auto key = Name;

  if (levelDb->readString(Name) != nullptr) {
    std::cerr << "name " << Name << " already exists" << std::endl;
    throw RPCException(KEY_SHARE_ALREADY_EXISTS, "Data with this name already exists");
  }

  levelDb->writeString(key, value);
  std::cerr << Name << " is written to db " << std::endl;
}

