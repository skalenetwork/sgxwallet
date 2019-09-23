//
// Created by kladko on 9/23/19.
//

#include "ECDSACrypto.h"
#include "sgxwallet.h"

char* gen_ecdsa_key(){
  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  char* encr_pr_key = (char *)calloc(1024, 1);
  char *pub_key_x = (char *)calloc(1024, 1);
  char *pub_key_y = (char *)calloc(1024, 1);
  uint32_t enc_len = 0;

  status = generate_ecdsa_key(eid, &err_status, errMsg, (uint8_t*)encr_pr_key, &enc_len, pub_key_x, pub_key_y );

  return encr_pr_key;
}

std::vector<std::string> ecdsa_sign_hash(const char* encryptedKey, const char* hashHex){
  std::vector<std::string> signature_vect(3);

  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  char* signature_r = (char*)malloc(1024);
  char* signature_s = (char*)malloc(1024);
  char* signature_v = (char*)calloc(4,1);
  uint32_t dec_len = 0;

  status = ecdsa_sign1(eid, &err_status, errMsg, (uint8_t*)encryptedKey, dec_len, (unsigned char*)hashHex, signature_r, signature_s, signature_v );

  signature_vect.at(0) = signature_v;
  signature_vect.at(1) = "0x" + std::string(signature_r);
  signature_vect.at(2) = "0x" + std::string(signature_s);

  return signature_vect;
}