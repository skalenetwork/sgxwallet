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


#include "sgxwallet.h"
#include "BLSCrypto.h"



void usage() {
  fprintf(stderr, "usage: sgxwallet\n");
  exit(1);
}

sgx_launch_token_t token = {0};

sgx_enclave_id_t eid;
sgx_status_t status;
int updated;

int main(int argc, char *argv[]) {

  int opt;

  while ((opt = getopt(argc, argv, "h")) != -1) {
    switch (opt) {
    case 'h':
    default:
      usage();
    }
  }

  argc -= optind;
  argv += optind;

  if (argc != 0)
    usage();

  init_all();


  const char *key = "4160780231445160889237664391382223604184857153814275770598"
                    "791864649971919844";

  char* keyArray = calloc(128, 1);

  uint8_t* encryptedKey = calloc(1024, 1);

  char* errMsg = calloc(1024,1);

  strncpy((char *)keyArray, (char*)key, 128);

  int err_status = 0;

  unsigned  int enc_len = 0;

  status = encrypt_key(eid, &err_status, errMsg, keyArray, encryptedKey, &enc_len);

  if (status != SGX_SUCCESS) {
    printf("ECALL encrypt_key: 0x%04x\n", status);
    return 1;
  }




  printf("Encrypt key completed with status: %d %s \n", err_status, errMsg);
  printf(" Encrypted key len %d\n", enc_len);



  char result[2* BUF_LEN];

  carray2Hex(encryptedKey, enc_len, result);

  uint64_t dec_len = 0;

  uint8_t bin[BUF_LEN];

  if (!hex2carray(result, &dec_len, bin)) {
    printf("hex2carray returned false");
  }



  for (int i=0; i < dec_len; i++) {
    if (bin[i] != encryptedKey[i]) {
      printf("Hex does not match");
      return 1;
    }
  }


  if (dec_len != enc_len) {
    printf("Dec_len != enc_len %d %d \n", (uint32_t) dec_len, (uint32_t) enc_len);
    return 1;
  }




  gmp_printf("Result: %s", result);

  gmp_printf("\n Length: %d \n", enc_len);

  return 0;
}
