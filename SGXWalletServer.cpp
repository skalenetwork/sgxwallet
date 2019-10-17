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

SGXWalletServer::SGXWalletServer(AbstractServerConnector &connector,
                                 serverVersion_t type)
        : AbstractStubServer(connector, type) {}

  SGXWalletServer *s = nullptr;
  HttpServer *hs = nullptr;

int init_server() {

  hs = new HttpServer(1025);
  s = new SGXWalletServer(*hs,
                      JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)
 
    if (!s->StartListening()) {
      cerr << "Server could not start listening" << endl;
      exit(-1);
  }
  return 0;
}

Json::Value
importBLSKeyShareImpl(int index, const std::string &_keyShare, const std::string &_keyShareName, int n, int t) {
    Json::Value result;

    int errStatus = UNKNOWN_ERROR;
    char *errMsg = (char *) calloc(BUF_LEN, 1);


    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKeyShare"] = "";

    try {

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

Json::Value blsSignMessageHashImpl(const std::string &keyShareName, const std::string &messageHash,int n, int t, int signerIndex) {
    Json::Value result;
    result["status"] = -1;
    result["errorMessage"] = "Unknown server error";
    result["signatureShare"] = "";



    //int errStatus = UNKNOWN_ERROR;
    //char *errMsg = (char *) calloc(BUF_LEN, 1);
    char *signature = (char *) calloc(BUF_LEN, 1);


    shared_ptr <std::string> value = nullptr;


    try {
        value = readKeyShare(keyShareName);
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


Json::Value generateECDSAKeyImpl(const std::string &_keyName) {

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";
    result["encryptedKey"] = "";

    cerr << "Calling method generateECDSAKey"  << endl;


    std::vector<std::string>keys;

    try {
        keys = gen_ecdsa_key();
        if (keys.size() == 0 ) {
            throw RPCException(UNKNOWN_ERROR, "");
        }
       // std::cerr << "write encr key" << keys.at(0) << std::endl;
        writeECDSAKey(_keyName, keys.at(0));
    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    result["encryptedKey"] = keys.at(0);
    result["PublicKey"] = keys.at(1);


    //std::cerr << "in SGXWalletServer encr key x " << keys.at(0) << std::endl;

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
       std::shared_ptr<std::string> key_ptr = readECDSAKey(_keyName);
      // std::cerr << "read encr key" << *key_ptr << std::endl;
       sign_vect = ecdsa_sign_hash(key_ptr->c_str(),cutHash.c_str(), base);
    } catch (RPCException &_e) {
        std::cerr << "err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }
    std::cerr << "got signature_s " << sign_vect.at(2) << std::endl;
    result["signature_v"] = sign_vect.at(0);
    result["signature_r"] = sign_vect.at(1);
    result["signature_s"] = sign_vect.at(2);

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
         std::shared_ptr<std::string> key_ptr = readECDSAKey(keyName);
         Pkey = get_ecdsa_pubkey( key_ptr->c_str());
    } catch (RPCException &_e) {
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }
    std::cerr << "PublicKey" << Pkey << std::endl;
    result["PublicKey"] = Pkey;

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
      encrPolyHex = gen_dkg_poly(t);
      writeDKGPoly(polyName, encrPolyHex);
    } catch (RPCException &_e) {
        std::cerr << " err str " << _e.errString << std::endl;
        result["status"] = _e.status;
        result["errorMessage"] = _e.errString;
    }

    //result["encryptedPoly"] = encrPolyHex;

    return result;
}

Json::Value getVerificationVectorImpl(const std::string& polyName, int n, int t) {

  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";

  std::vector <std::vector<std::string>> verifVector;
  try {
    std::shared_ptr<std::string> encr_poly_ptr = readFromDb(polyName, "DKGPoly:");

    verifVector = get_verif_vect(encr_poly_ptr->c_str(), n, t);
    std::cerr << "verif vect size " << verifVector.size() << std::endl;
  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["Verification Vector"] = "";
  }

  for ( int i = 0; i < t; i++){
    std::vector<std::string> cur_coef = verifVector.at(i);
    string num = std::to_string(i);
    result["Verification Vector"][i][num]["X"]["c0"] = cur_coef.at(0);
    result["Verification Vector"][i][num]["X"]["c1"] = cur_coef.at(1);
    result["Verification Vector"][i][num]["Y"]["c0"] = cur_coef.at(2);
    result["Verification Vector"][i][num]["Y"]["c1"] = cur_coef.at(3);
  }

  return result;
}

Json::Value getSecretShareImpl(const std::string& polyName, const std::string& publicKeys, int n, int t){

    Json::Value result;
    result["status"] = 0;
    result["errorMessage"] = "";

    try {
        std::shared_ptr<std::string> encr_poly_ptr = readFromDb(polyName, "DKGPoly:");
        std::string s = get_secret_shares( encr_poly_ptr->c_str(), publicKeys, n, t);
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

Json::Value SGXWalletServer::generateDKGPoly(const std::string& polyName, int t){
    return generateDKGPolyImpl(polyName, t);
}

Json::Value SGXWalletServer::getVerificationVector(const std::string& polyName, int n, int t){
  return getVerificationVectorImpl(polyName, n, t);
}

Json::Value SGXWalletServer::getSecretShare(const std::string& polyName, const std::string& publicKeys, int n, int t){
    return getSecretShareImpl(polyName, publicKeys, n, t);
}


Json::Value SGXWalletServer::generateECDSAKey(const std::string &_keyName) {
    return generateECDSAKeyImpl(_keyName);
}

Json::Value SGXWalletServer::getPublicECDSAKey(const std::string &_keyName) {
  return getPublicECDSAKeyImpl(_keyName);
}

Json::Value SGXWalletServer::ecdsaSignMessageHash(int base, const std::string &_keyName, const std::string &messageHash ) {
    std::cerr << "entered ecdsaSignMessageHash" << std::endl;
    std::cerr << "MessageHash first " << messageHash << std::endl;
    return ecdsaSignMessageHashImpl(base,_keyName, messageHash);
}


Json::Value
SGXWalletServer::importBLSKeyShare(int index, const std::string &_keyShare, const std::string &_keyShareName, int n,
                                   int t) {
    return importBLSKeyShareImpl(index, _keyShare, _keyShareName, n, t);
}

Json::Value SGXWalletServer::blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash,int n,
                                       int t, int signerIndex) {
    return blsSignMessageHashImpl(keyShareName, messageHash, n,t, signerIndex);
}

Json::Value SGXWalletServer::importECDSAKey(const std::string &key, const std::string &keyName) {
    return importECDSAKeyImpl(key, keyName);
}


shared_ptr<string> readFromDb(const string & name, const string & prefix) {

  auto dataStr = levelDb->readString(prefix + name);

  if (dataStr == nullptr) {
    throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exists");
  }

  return dataStr;
}

shared_ptr<string> readKeyShare(const string &_keyShareName) {

    auto keyShareStr = levelDb->readString("BLSKEYSHARE:" + _keyShareName);

    if (keyShareStr == nullptr) {
        throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key share with this name does not exists");
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
        throw new RPCException(KEY_SHARE_ALREADY_EXISTS, "Key share with this name already exists");
    }

    levelDb->writeString(key, value);
}

shared_ptr <std::string> readECDSAKey(const string &_keyName) {
  auto keyStr = levelDb->readString("ECDSAKEY:" + _keyName);

  if (keyStr == nullptr) {
    throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Key with this name does not exists");
  }

  return keyStr;
}

void writeECDSAKey(const string &_keyName, const string &value) {
    Json::Value val;
    Json::FastWriter writer;

    val["value"] = value;
    std::string json = writer.write(val);

    auto key = "ECDSAKEY:" + _keyName;

    if (levelDb->readString(_keyName) != nullptr) {
        throw new RPCException(KEY_SHARE_ALREADY_EXISTS, "Key with this name already exists");
    }

    levelDb->writeString(key, value);
}

void writeDKGPoly(const string &_polyName, const string &value) {
  Json::Value val;
  Json::FastWriter writer;

  val["value"] = value;
  std::string json = writer.write(val);

  auto key = "DKGPoly:" + _polyName;

  if (levelDb->readString(_polyName) != nullptr) {
    throw new RPCException(KEY_SHARE_ALREADY_EXISTS, "Poly with this name already exists");
  }

  levelDb->writeString(key, value);
}