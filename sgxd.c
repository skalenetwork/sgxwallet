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

#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "BLSCrypto.h"

#define ENCLAVE_NAME "secure_enclave.signed.so"

int char2int(char _input) {
  if (_input >= '0' && _input <= '9')
    return _input - '0';
  if (_input >= 'A' && _input <= 'F')
    return _input - 'A' + 10;
  if (_input >= 'a' && _input <= 'f')
    return _input - 'a' + 10;
  return -1;
}



unsigned char *carray2Hex(const uint8_t *d, int _len) {
  unsigned char *hex = malloc(2 * _len);

  static char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  for (int j = 0; j < _len; j++) {
    hex[j * 2] = hexval[((d[j] >> 4) & 0xF)];
    hex[j * 2 + 1] = hexval[(d[j]) & 0x0F];
  }

  return hex;
}


uint8_t* hex2carray(unsigned char * _hex, uint64_t *_bin_len) {

  uint64_t len = strlen((char*)_hex);


  if (len == 0 && len % 2 == 1)
    return  NULL;

  *_bin_len = len / 2;

  uint8_t* bin = malloc(len / 2);

  for (int i = 0; i < len / 2; i++) {
    int high = char2int((char)_hex[i * 2]);
    int low = char2int((char)_hex[i * 2 + 1]);

    if (high < 0 || low < 0) {
      return NULL;
    }

    bin[i] = (uint8_t) (high * 16 + low);
  }

  return bin;
}




void usage() {
  fprintf(stderr, "usage: sgxd\n");
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

  init_daemon();

  init_enclave();



  const char *key = "4160780231445160889237664391382223604184857153814275770598"
                    "791864649971919844";

  unsigned char* keyArray = calloc(128, 1);

  unsigned char* encryptedKey = calloc(1024, 1);

  unsigned char* errMsg = calloc(1024,1);

  strncpy((char *)keyArray, (char*)key, 128);

  int err_status = 0;

  unsigned  int enc_len = 0;

  status = encrypt_key(eid, &err_status, errMsg, keyArray, encryptedKey, &enc_len);

  if (status != SGX_SUCCESS) {
    gmp_printf("ECALL encrypt_key: 0x%04x\n", status);
    return 1;
  }


  gmp_printf("Encrypt key completed with status: %d %s \n", err_status, errMsg);

  unsigned char *result = carray2Hex(encryptedKey, enc_len);

  uint64_t dec_len;

  uint8_t* bin = hex2carray(result, &dec_len);

  if (dec_len != enc_len) {
    return 1;
  }

  for (int i=0; i < dec_len; i++) {
    if (bin[i] != encryptedKey[i])
      return 1;

  }



  gmp_printf("Result: %s", result);

  gmp_printf("\n Length: %d \n", enc_len);

  return 0;
}
