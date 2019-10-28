//
// Created by kladko on 10/3/19.
//

#include "DKGCrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"
#include <iostream>

#include <memory>
#include "SGXWalletServer.hpp"

std::vector<std::string> SplitString(const char* koefs, const char symbol){
  std::string str(koefs);
  std::string delim;
  delim.push_back(symbol);
  std::vector<std::string> G2_strings;
  size_t prev = 0, pos = 0;
  do
  {
    pos = str.find(delim, prev);
    if (pos == std::string::npos) pos = str.length();
    std::string token = str.substr(prev, pos-prev);
    if (!token.empty()) {
      std::string koef(token.c_str());
      G2_strings.push_back(koef);
    }
    prev = pos + delim.length();
  }
  while (pos < str.length() && prev < str.length());

  return G2_strings;
}

std::string gen_dkg_poly( int _t){
    char *errMsg = (char *)calloc(1024, 1);
    int err_status = 0;
    uint8_t* encrypted_dkg_secret = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);;

    uint32_t enc_len = 0;

    status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, _t);

    std::cerr << "gen_dkg_secret, status " << err_status << " err msg " << errMsg << std::endl;

 /*   std::cerr << "encr raw poly: " << std::endl;
    for ( int i = 0 ; i < 3050; i++)
      printf(" %d ", encrypted_dkg_secret[i] );*/


    char *hexEncrPoly = (char *) calloc(DKG_MAX_SEALED_LEN * 2 + 1, 1);//(4*BUF_LEN, 1);

    carray2Hex(encrypted_dkg_secret, DKG_MAX_SEALED_LEN, hexEncrPoly);
    std::string result(hexEncrPoly);

    std::cerr << "in DKGCrypto encr len is " << enc_len << std::endl;

    free(errMsg);
    free(encrypted_dkg_secret);
    free(hexEncrPoly);

    return result;
}

std::vector <std::vector<std::string>> get_verif_vect(const char* encryptedPolyHex, int n, int t){

  char* errMsg1 = (char*) calloc(1024,1);
  int err_status = 0;

 // std::cerr << "got encr poly " << encryptedPolyHex << std::endl;
  std::cerr << "got encr poly size " << strlen(encryptedPolyHex) << std::endl;
  char* public_shares = (char*)calloc(10000, 1);

  uint64_t enc_len = 0;

  uint8_t* encr_dkg_poly = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);
  hex2carray2(encryptedPolyHex, &enc_len, encr_dkg_poly, 6100);
  std::cerr << "enc len " << enc_len << std::endl;
  /*std::cerr << "encr raw poly: " << std::endl;
  for ( int i = 0 ; i < 3050; i++)
    printf(" %d ", encr_dkg_poly[i] );*/

  uint32_t len;
  status = get_public_shares(eid, &err_status, errMsg1, encr_dkg_poly, len, public_shares, t, n);
  std::cerr << "err msg " << errMsg1 << std::endl;

  std::cerr << "public_shares:" << std::endl;
  std::cerr << public_shares << std::endl;

  printf("\nget_public_shares status: %d error %s \n\n", err_status, errMsg1);

  std::vector <std::string> G2_strings = SplitString( public_shares, ',');
  std::vector <std::vector <std::string>> pub_shares_vect;
  for ( int i = 0; i < G2_strings.size(); i++){
    std::vector <std::string> koef_str = SplitString(G2_strings.at(i).c_str(), ':');
    pub_shares_vect.push_back(koef_str);
  }

  free(errMsg1);
  free(public_shares);
  free(encr_dkg_poly);

  return pub_shares_vect;
}

std::string get_secret_shares(const std::string& polyName, const char* encryptedPolyHex, const std::string& publicKeys, int n, int t){
  char* errMsg1 = (char*) calloc(1024,1);
  int err_status = 0;

  uint64_t enc_len = 0;

  uint8_t* encr_dkg_poly = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);
  hex2carray2(encryptedPolyHex, &enc_len, encr_dkg_poly, 6100);

  status = set_encrypted_dkg_poly(eid, &err_status, errMsg1, encr_dkg_poly);

  std::string result;
  char *hexEncrKey = (char *) calloc(2 * BUF_LEN, 1);

  for ( int i = 0; i < n; i++){
    uint8_t encrypted_skey[BUF_LEN];
    uint32_t dec_len;

    char cur_share[193];
    std::string pub_keyB = publicKeys.substr(64*i, 64*i + 128);
    char pubKeyB[129];
    strncpy(pubKeyB, pub_keyB.c_str(),129);
    get_encr_sshare(eid, &err_status, errMsg1, encrypted_skey, &dec_len,
                   cur_share, pubKeyB, t, n, i + 1 );

    result += cur_share;

    uint32_t enc_len = BUF_LEN;
    carray2Hex(encrypted_skey, enc_len, hexEncrKey);
    //std::cerr << "hexEncrKey: " << hexEncrKey << std::endl;

    std::string name = "DKG_DH_KEY_" + polyName + "_" + std::to_string(i) + ":";
    //writeDataToDB(name, hexEncrKey);


    //std::cerr << errMsg1 << std::endl << std::endl;
    //std::cerr << "iteration " << i <<" result length is " << result.length() << std::endl ;
    //std::cerr << "iteration " << i <<" share length is " << strlen(cur_share) << std::endl;
    //std::cerr << "iteration " << i <<" share is " << cur_share << std::endl;
  }
  //result += '\0';

  free(encr_dkg_poly);
  free(errMsg1);
  free(hexEncrKey);

  return result;
}

bool VerifyShares(const char* encryptedPolyHex, const char* encr_sshare, const char * encryptedKeyHex, int t, int n, int ind ){
    char* errMsg1 = (char*) calloc(1024,1);
    int err_status = 0;

    uint64_t poly_len = 0;
    uint8_t* encr_dkg_poly = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);
    hex2carray2(encryptedPolyHex, &poly_len, encr_dkg_poly, 6100);

    uint64_t dec_key_len ;
    uint8_t encr_key[BUF_LEN];
    hex2carray(encryptedKeyHex, &dec_key_len, encr_key);
    //std::cerr << "encryptedKeyHex " << encryptedKeyHex << std::endl;
    //std::cerr << "dec_key_len " << dec_key_len << std::endl;

    int result ;
    dkg_verification(eid, &err_status, errMsg1, encr_dkg_poly, encr_sshare, encr_key, dec_key_len, t, ind, &result);

    std::cerr << "errMsg1: " << errMsg1 << std::endl;

    free(errMsg1);
    free(encr_dkg_poly);

    std::cerr << "result is " << result << std::endl;
    return result;
}

bool CreateBLSShare( const char * s_shares, const char * encryptedKeyHex){

  char* errMsg1 = (char*) calloc(1024,1);
  int err_status = 0;

  uint64_t dec_key_len ;
  uint8_t encr_bls_key[BUF_LEN];
  uint8_t encr_key[BUF_LEN];
  hex2carray(encryptedKeyHex, &dec_key_len, encr_key);

  create_bls_key(eid, &err_status, errMsg1, s_shares, encr_key, dec_key_len, encr_bls_key);
  if ( err_status != 0){
     return false;
  }
  else return true;

}