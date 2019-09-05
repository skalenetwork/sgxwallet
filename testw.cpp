/*

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>


#include "BLSCrypto.h"

#define ENCLAVE_NAME "secure_enclave.signed.so"


#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"

void usage() {
  fprintf(stderr, "usage: sgxwallet\n");
  exit(1);
}

sgx_launch_token_t token = {0};
sgx_enclave_id_t eid;
sgx_status_t status;
int updated;


void init_enclave() {

  eid = 0;
  updated = 0;

  unsigned long support;

#ifndef SGX_HW_SIM
  support = get_sgx_support();
  if (!SGX_OK(support)) {
    sgx_support_perror(support);
    exit(1);
  }
#endif

  status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token,
                                     &updated, &eid, 0);

  if (status != SGX_SUCCESS) {
    if (status == SGX_ERROR_ENCLAVE_FILE_ACCESS) {
      fprintf(stderr, "sgx_create_enclave: %s: file not found\n", ENCLAVE_NAME);
      fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
    } else {
      fprintf(stderr, "%s: 0x%04x\n", ENCLAVE_NAME, status);
    }
    exit(1);
  }

  fprintf(stderr, "Enclave launched\n");

  status = tgmp_init(eid);
  if (status != SGX_SUCCESS) {
    fprintf(stderr, "ECALL tgmp_init: 0x%04x\n", status);
    exit(1);
  }

  fprintf(stderr, "libtgmp initialized\n");
}

void init_all() {
    init_enclave();
    init_daemon();
}

TEST_CASE( "BLS sign test", "[bls-sign]" ) {

  init_all();

  const char *key = "4160780231445160889237664391382223604184857153814275770598"
                    "791864649971919844";

  char* keyArray = (char*) calloc(128, 1);

  uint8_t* encryptedKey = (uint8_t*) calloc(1024, 1);

  char* errMsg = (char*) calloc(1024,1);

  strncpy((char *)keyArray, (char*)key, 128);

  int err_status = 0;

  unsigned  int enc_len = 0;

  status = encrypt_key(eid, &err_status, errMsg, keyArray, encryptedKey, &enc_len);

  REQUIRE(status == SGX_SUCCESS);

  printf("Encrypt key completed with status: %d %s \n", err_status, errMsg);
  printf(" Encrypted key len %d\n", enc_len);



  char result[2* BUF_LEN];

  carray2Hex(encryptedKey, enc_len, result);

  uint64_t dec_len = 0;

  uint8_t bin[BUF_LEN];

  REQUIRE(hex2carray(result, &dec_len, bin));

  for (uint64_t i=0; i < dec_len; i++) {
    REQUIRE(bin[i] == encryptedKey[i]);
  }

  REQUIRE(dec_len == enc_len);

  gmp_printf("Result: %s", result);

  gmp_printf("\n Length: %d \n", enc_len);
}



TEST_CASE( "DKG gen test", "[dkg-gen]" ) {

    init_all();

    // put your test here
}

