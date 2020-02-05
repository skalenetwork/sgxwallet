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

    @file DKGCrypto.cpp
    @author Stan Kladko
    @date 2019
*/

#include "DKGCrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"
#include <iostream>

#include <memory>
#include "SGXWalletServer.hpp"
#include "RPCException.h"

//#include <libBLS/libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "spdlog/spdlog.h"
#include "common.h"

vector<string> SplitString(const char* koefs, const char symbol){
  string str(koefs);
  string delim;
  delim.push_back(symbol);
  vector<string> G2_strings;
  size_t prev = 0, pos = 0;
  do
  {
    pos = str.find(delim, prev);
    if (pos == string::npos) pos = str.length();
    string token = str.substr(prev, pos-prev);
    if (!token.empty()) {
      string koef(token.c_str());
      G2_strings.push_back(koef);
    }
    prev = pos + delim.length();
  }
  while (pos < str.length() && prev < str.length());

  return G2_strings;
}

template<class T>
string ConvertToString(T field_elem, int base = 10) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char arr[mpz_sizeinbase (t, base) + 2];

  char * tmp = mpz_get_str(arr, base, t);
  mpz_clear(t);

  string output = tmp;

  return output;
}

string gen_dkg_poly( int _t){
    vector<char> errMsg(1024, 0);
    int err_status = 0;

    vector<uint8_t> encrypted_dkg_secret(DKG_MAX_SEALED_LEN, 0);

    uint32_t enc_len = 0;

    if (!is_aes)
      status = gen_dkg_secret (eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, _t);
    else
      status = gen_dkg_secret_aes (eid, &err_status, errMsg.data(), encrypted_dkg_secret.data(), &enc_len, _t);
    if ( err_status != 0){
        throw RPCException(-666, errMsg.data() ) ;
    }

    if (DEBUG_PRINT) {
      spdlog::info("gen_dkg_secret, status {}", err_status, " err msg ", errMsg.data());
      spdlog::info("in DKGCrypto encr len is {}", enc_len);
    }

    uint64_t length = DKG_MAX_SEALED_LEN;
    if (is_aes){
      length = enc_len;
    }

   //vector<char> hexEncrPoly(DKG_MAX_SEALED_LEN * 2 + 1, 0);//(4*BUF_LEN, 1);

    vector<char> hexEncrPoly(2 * length + 1, 0);
    assert( encrypted_dkg_secret.size() >= length);
    //carray2Hex(encrypted_dkg_secret.data(), DKG_MAX_SEALED_LEN, hexEncrPoly.data());
    carray2Hex(encrypted_dkg_secret.data(), length, hexEncrPoly.data());
    string result(hexEncrPoly.data());

    return result;
}

vector <vector<string>> get_verif_vect(const char* encryptedPolyHex, int t, int n){

  char* errMsg1 = (char*) calloc(1024,1);
  //char errMsg1[BUF_LEN];
  int err_status = 0;

  if (DEBUG_PRINT) {
    // cerr << "got encr poly " << encryptedPolyHex << endl;
    spdlog::info("got encr poly size {}", char_traits<char>::length(encryptedPolyHex));
  }

  char* public_shares = (char*)calloc(10000, 1);
  memset(public_shares, 0, 10000);
 // char public_shares[10000];

  uint64_t enc_len = 0;

  uint8_t* encr_dkg_poly = (uint8_t*) calloc(DKG_MAX_SEALED_LEN * 2, 1);
  memset(encr_dkg_poly, 0, DKG_MAX_SEALED_LEN * 2);
  //uint8_t encr_dkg_poly[DKG_MAX_SEALED_LEN];

  if (!hex2carray2(encryptedPolyHex, &enc_len, encr_dkg_poly, 6100)){
      throw RPCException(INVALID_HEX, "Invalid encryptedPolyHex");
  }

  if (DEBUG_PRINT) {
    //cerr << "hex_encr_poly is " << encryptedPolyHex << std::endl;
    spdlog::info("hex_encr_poly length is {}", strlen(encryptedPolyHex));
    spdlog::info("enc len {}", enc_len);
//    cerr << "encr raw poly: " << endl;
//    for ( int i = 0 ; i < 3050; i++)
//      printf(" %d ", encr_dkg_poly[i] );
  }

  uint32_t len;
  if (!is_aes)
    status = get_public_shares(eid, &err_status, errMsg1, encr_dkg_poly, len, public_shares, t, n);
  else {

    status = get_public_shares_aes(eid, &err_status, errMsg1, encr_dkg_poly, enc_len, public_shares, t, n);
  }
  if ( err_status != 0){
    throw RPCException(-666, errMsg1 );
  }

  if (DEBUG_PRINT) {
    spdlog::info("err msg is {}", errMsg1);

    spdlog::info("public_shares:");
    spdlog::info("{}", public_shares);
//    cerr << "public_shares:" << endl;
//    cerr << public_shares << endl;
    spdlog::info("get_public_shares status: {}", err_status);
    //printf("\nget_public_shares status: %d error %s \n\n", err_status, errMsg1);
  }

  vector <string> G2_strings = SplitString( public_shares, ',');
  vector <vector <string>> pub_shares_vect;
  for ( int i = 0; i < G2_strings.size(); i++){
    vector <string> koef_str = SplitString(G2_strings.at(i).c_str(), ':');
    pub_shares_vect.push_back(koef_str);
  }

  free(errMsg1);
  free(public_shares);
  free(encr_dkg_poly);

  return pub_shares_vect;
}

string get_secret_shares(const string& polyName, const char* encryptedPolyHex, const vector<string>& publicKeys, int t, int n){
  //char* errMsg1 = (char*) calloc(1024,1);
  char errMsg1[BUF_LEN];
  int err_status = 0;
  char hexEncrKey[BUF_LEN];
  memset(hexEncrKey, 0, BUF_LEN);
  uint64_t enc_len = 0;

 // uint8_t* encr_dkg_poly = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);
  uint8_t encr_dkg_poly[DKG_MAX_SEALED_LEN];
  memset(encr_dkg_poly, 0, DKG_MAX_SEALED_LEN);
  if(!hex2carray2(encryptedPolyHex, &enc_len, encr_dkg_poly, 6100)){
      throw RPCException(INVALID_HEX, "Invalid encryptedPolyHex");
  }

  std::cerr << "enc_len is " << enc_len << std::endl;

  if (!is_aes)
    status = set_encrypted_dkg_poly(eid, &err_status, errMsg1, encr_dkg_poly);
  else
    status = set_encrypted_dkg_poly_aes(eid, &err_status, errMsg1, encr_dkg_poly, &enc_len);

  if ( status != SGX_SUCCESS || err_status != 0){
    throw RPCException(-666, errMsg1 );
  }

  string result;
  //char *hexEncrKey = (char *) calloc(2 * BUF_LEN, 1);

  for ( int i = 0; i < n; i++){
    uint8_t encrypted_skey[BUF_LEN];
    memset(encrypted_skey, 0, BUF_LEN);
    uint32_t dec_len;

    char cur_share[193];
    char s_shareG2[320];
    string pub_keyB = publicKeys.at(i);//publicKeys.substr(128*i, 128*i + 128);
//    if (DEBUG_PRINT) {
//      spdlog::info("pub_keyB is {}", pub_keyB);
//    }
    char pubKeyB[129];
    strncpy(pubKeyB, pub_keyB.c_str(), 128);
    pubKeyB[128] = 0;
    if (DEBUG_PRINT) {
      spdlog::info("pubKeyB is {}", pub_keyB);
    }

    if (!is_aes)
      get_encr_sshare(eid, &err_status, errMsg1, encrypted_skey, &dec_len,
                   cur_share, s_shareG2, pubKeyB, t, n, i + 1 );
    else
      get_encr_sshare_aes(eid, &err_status, errMsg1, encrypted_skey, &dec_len,
                      cur_share, s_shareG2, pubKeyB, t, n, i + 1 );
    if (err_status != 0){
      throw RPCException(-666, errMsg1);
    }
    if (DEBUG_PRINT) {
      spdlog::info("cur_share is {}", cur_share);
    }

    result += cur_share;

    //uint32_t enc_len = BUF_LEN;
    if (DEBUG_PRINT) {
      spdlog::info("dec len is {}", dec_len);
    }


    carray2Hex(encrypted_skey, dec_len, hexEncrKey);


    string DHKey_name = "DKG_DH_KEY_" + polyName + "_" + to_string(i) + ":";

    cerr << "hexEncr DH Key: " << hexEncrKey << endl;
    writeDataToDB(DHKey_name, hexEncrKey);

    string shareG2_name = "shareG2_" + polyName + "_" + to_string(i) + ":";
    if (DEBUG_PRINT) {
      spdlog::info("name to write to db is {}", DHKey_name);
      spdlog::info("name to write to db is {}", shareG2_name);
      spdlog::info("s_shareG2: {}", s_shareG2);
    }
    writeDataToDB(shareG2_name, s_shareG2);

    if (DEBUG_PRINT) {
      spdlog::info("errMsg: {}", errMsg1);
      // cerr << "iteration " << i <<" result length is " << result.length() << endl ;
      // cerr << "iteration " << i <<" share length is " << strlen(cur_share) << endl;
      // cerr << "iteration " << i <<" share is " << cur_share << endl;
    }
  }
  //result += '\0';

  //free(encr_dkg_poly);
 // free(errMsg1);
  //free(hexEncrKey);

  return result;
}

bool VerifyShares(const char* publicShares, const char* encr_sshare, const char * encryptedKeyHex, int t, int n, int ind ){
    //char* errMsg1 = (char*) calloc(1024,1);
    char errMsg1[BUF_LEN];
    int err_status = 0;

    uint64_t dec_key_len ;
    uint8_t encr_key[BUF_LEN];
    memset(encr_key, 0, BUF_LEN);
    if (!hex2carray(encryptedKeyHex, &dec_key_len, encr_key)){
        throw RPCException(INVALID_HEX, "Invalid encryptedPolyHex");
    }
    int result;
    if (DEBUG_PRINT) {
      cerr << "encryptedKeyHex " << encryptedKeyHex << endl;
      cerr << "dec_key_len " << dec_key_len << endl;
      cerr << "encr_sshare length is " << strlen(encr_sshare) << endl;
      //cerr << "public shares " << publicShares << endl;
      spdlog::info("publicShares length is {}", char_traits<char>::length(publicShares));
    }
    char pshares[8193];
    memset(pshares, 0, 8193);
    strncpy(pshares, publicShares, strlen(publicShares) );


    if (!is_aes)
      dkg_verification(eid, &err_status, errMsg1, pshares, encr_sshare, encr_key, dec_key_len, t, ind, &result);
    else
      dkg_verification_aes(eid, &err_status, errMsg1, pshares, encr_sshare, encr_key, dec_key_len, t, ind, &result);

    if (result == 2){
      throw RPCException(INVALID_HEX, "Invalid public shares");
    }

    if (DEBUG_PRINT) {
      spdlog::info("errMsg1: {}", errMsg1);
      spdlog::info("result is: {}", result);
    }

    //free(errMsg1);

    return result;
}

bool CreateBLSShare( const string& blsKeyName, const char * s_shares, const char * encryptedKeyHex){
  if (DEBUG_PRINT) {
    spdlog::info("ENTER CreateBLSShare");
  }
 // char* errMsg1 = (char*) calloc(1024,1);
  char errMsg1[BUF_LEN];
  int err_status = 0;

  uint64_t dec_key_len ;
  uint8_t encr_bls_key[BUF_LEN];
  memset(encr_bls_key, 0, BUF_LEN);
  uint8_t encr_key[BUF_LEN];
  memset(encr_key, 0, BUF_LEN);
  if (!hex2carray(encryptedKeyHex, &dec_key_len, encr_key)){
      throw RPCException(INVALID_HEX, "Invalid encryptedKeyHex");
  }

  uint32_t enc_bls_len = 0;

  //cerr << "BEFORE create_bls_key IN ENCLAVE " << endl;
  if (!is_aes)
    create_bls_key(eid, &err_status, errMsg1, s_shares, encr_key, dec_key_len, encr_bls_key, &enc_bls_len);
  else
    create_bls_key_aes(eid, &err_status, errMsg1, s_shares, encr_key, dec_key_len, encr_bls_key, &enc_bls_len);
  //cerr << "AFTER create_bls_key IN ENCLAVE er msg is  " << errMsg1 << endl;
  if ( err_status != 0){
     //spdlog::info("ERROR IN ENCLAVE with status {}", err_status);
     spdlog::error(errMsg1);
     spdlog::error("status {}", err_status);
     throw RPCException(ERROR_IN_ENCLAVE, "Create BLS private key failed in enclave");
  }
  else {
    //char *hexBLSKey = (char *) calloc(2 * BUF_LEN, 1);
    char hexBLSKey[2 * BUF_LEN];

    //cerr << "BEFORE carray2Hex" << endl;
      //cerr << "enc_bls_len " << enc_bls_len << endl;
    carray2Hex(encr_bls_key, enc_bls_len, hexBLSKey);
   // cerr << "BEFORE WRITE BLS KEY TO DB" << endl;
    writeDataToDB(blsKeyName, hexBLSKey);
    if (DEBUG_PRINT) {
      spdlog::info("hexBLSKey length is {}", char_traits<char>::length(hexBLSKey));
      spdlog::info("bls key {}", blsKeyName, " is ", hexBLSKey );
    }
    //free(hexBLSKey);
    return true;
  }

}

vector<string> GetBLSPubKey(const char * encryptedKeyHex){
    //char* errMsg1 = (char*) calloc(1024,1);
    char errMsg1[BUF_LEN];

    int err_status = 0;

    uint64_t dec_key_len ;
    uint8_t encr_bls_key[BUF_LEN];
    uint8_t encr_key[BUF_LEN];
    if (!hex2carray(encryptedKeyHex, &dec_key_len, encr_key)){
        throw RPCException(INVALID_HEX, "Invalid encryptedKeyHex");
    }

    char pub_key[320];
    if (DEBUG_PRINT) {
      spdlog::info("dec_key_len is {}", dec_key_len);
    }

    if (!is_aes)
      get_bls_pub_key(eid, &err_status, errMsg1, encr_key, dec_key_len, pub_key);
    else
      get_bls_pub_key_aes(eid, &err_status, errMsg1, encr_key, dec_key_len, pub_key);
    if ( err_status != 0){
      std::cerr <<  errMsg1 << " status is " << err_status << std::endl;
      throw RPCException(ERROR_IN_ENCLAVE, "Failed to get BLS public key in enclave");
    }
    vector<string> pub_key_vect = SplitString(pub_key, ':');

    if (DEBUG_PRINT) {
      spdlog::info("errMsg1 is {}", errMsg1);
      spdlog::info("pub key is ");
      for (int i = 0; i < 4; i++)
        spdlog::info("{}", pub_key_vect.at(i));
    }
    return pub_key_vect;
}

string decrypt_DHKey(const string& polyName, int ind){

  vector<char> errMsg1(1024,0);
  int err_status = 0;

  string DH_key_name = polyName + "_" + to_string(ind) + ":";
  shared_ptr<string> hexEncrKey_ptr = readFromDb(DH_key_name, "DKG_DH_KEY_");
  if (DEBUG_PRINT) {
    spdlog::info("encr DH key is {}", *hexEncrKey_ptr);
  }

  vector<char> hexEncrKey(2 * BUF_LEN, 0);

  uint64_t DH_enc_len = 0;
  uint8_t encrypted_DHkey[BUF_LEN];
  if (!hex2carray(hexEncrKey_ptr->c_str(), &DH_enc_len, encrypted_DHkey)){
     throw RPCException(INVALID_HEX, "Invalid hexEncrKey");
  }
  if (DEBUG_PRINT) {
    spdlog::info("encr DH key length is {}", DH_enc_len);
    spdlog::info("hex encr DH key length is {}", hexEncrKey_ptr->length());
  }

  char DHKey[ECDSA_SKEY_LEN];

  if ( !is_aes)
    decrypt_key(eid, &err_status, errMsg1.data(), encrypted_DHkey, DH_enc_len, DHKey);
  else
    decrypt_key_aes(eid, &err_status, errMsg1.data(), encrypted_DHkey, DH_enc_len, DHKey);
  if (err_status != 0){
    throw RPCException(/*ERROR_IN_ENCLAVE*/ err_status, "decrypt key failed in enclave");
  }

  return DHKey;
}

vector<string> mult_G2(const string& x){
    vector<string> result(4);
    libff::init_alt_bn128_params();
    libff::alt_bn128_Fr el(x.c_str());
    libff::alt_bn128_G2 elG2 = el * libff::alt_bn128_G2::one();
    elG2.to_affine_coordinates();
    result[0] = ConvertToString(elG2.X.c0);
    result[1] = ConvertToString(elG2.X.c1);
    result[2] = ConvertToString(elG2.Y.c0);
    result[3] = ConvertToString(elG2.Y.c1);
    return result;
}
