//
// Created by kladko on 10/3/19.
//

#include "DKGCrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"
#include <iostream>

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