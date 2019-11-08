//
// Created by kladko on 9/23/19.
//

#include "ECDSACrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"
#include <iostream>


std::vector<std::string> gen_ecdsa_key(){
  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  uint8_t* encr_pr_key = (uint8_t *)calloc(1024, 1);
  char *pub_key_x = (char *)calloc(1024, 1);
  char *pub_key_y = (char *)calloc(1024, 1);
  uint32_t enc_len = 0;

  status = generate_ecdsa_key(eid, &err_status, errMsg, encr_pr_key, &enc_len, pub_key_x, pub_key_y );
  std::vector<std::string> keys(2);
  std::cerr << "account key is " << errMsg << std::endl;
  char *hexEncrKey = (char *) calloc(2*BUF_LEN, 1);
  carray2Hex(encr_pr_key, enc_len, hexEncrKey);
  keys.at(0) = hexEncrKey;
  keys.at(1) = std::string(pub_key_x) + std::string(pub_key_y);
  //std::cerr << "in ECDSACrypto encr key x " << keys.at(0) << std::endl;
  //std::cerr << "in ECDSACrypto encr_len %d " << enc_len << std::endl;


  free(errMsg);
  free(pub_key_x);
  free(pub_key_y);
  free(encr_pr_key);
  free(hexEncrKey);

  return keys;
}

std::string get_ecdsa_pubkey(const char* encryptedKeyHex){
  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  char *pub_key_x = (char *)calloc(1024, 1);
  char *pub_key_y = (char *)calloc(1024, 1);
  uint64_t enc_len = 0;

  uint8_t encr_pr_key[BUF_LEN];
  hex2carray(encryptedKeyHex, &enc_len, encr_pr_key);

  status = get_public_ecdsa_key(eid, &err_status, errMsg, encr_pr_key, enc_len, pub_key_x, pub_key_y );
  std::string pubKey = std::string(pub_key_x) + std::string(pub_key_y);
  std::cerr << "err str " << errMsg << std::endl;

  free(errMsg);
  free(pub_key_x);
  free(pub_key_y);

  return pubKey;
}

std::vector<std::string> ecdsa_sign_hash(const char* encryptedKeyHex, const char* hashHex, int base){
  std::vector<std::string> signature_vect(3);

  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  char* signature_r = (char*)malloc(1024);
  char* signature_s = (char*)malloc(1024);
  uint8_t signature_v = 0;
  uint64_t dec_len = 0;

  uint8_t encr_key[BUF_LEN];
  hex2carray(encryptedKeyHex, &dec_len, encr_key);

  std::cerr << "encryptedKeyHex: "<< encryptedKeyHex << std::endl;

  std::cerr << "HASH: "<< hashHex << std::endl;

  std::cerr << "encrypted len" << dec_len << std::endl;

  status = ecdsa_sign1(eid, &err_status, errMsg, encr_key, ECDSA_ENCR_LEN, (unsigned char*)hashHex, signature_r, signature_s, &signature_v, base );

  std::cerr << "signature r in  ecdsa_sign_hash "<< signature_r << std::endl;
  std::cerr << "signature s in  ecdsa_sign_hash "<< signature_s << std::endl;

  if ( status != SGX_SUCCESS){
    std::cerr << "failed to sign " << std::endl;
  }
  signature_vect.at(0) = std::to_string(signature_v);
  if ( base == 16) {
    signature_vect.at(1) = "0x" + std::string(signature_r);
    signature_vect.at(2) = "0x" + std::string(signature_s);
  }
  else{
    signature_vect.at(1) = std::string(signature_r);
    signature_vect.at(2) = std::string(signature_s);
  }

  free(errMsg);
  free(signature_r);
  free(signature_s);

  return signature_vect;
}