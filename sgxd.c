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

#include <sgx_urts.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "sgx_detect.h"
#include "secure_enclave_u.h"
#include "create_enclave.h"

#define ENCLAVE_NAME "secure_enclave.signed.so"



unsigned char* carray2Hex(const uint8_t *d, int _len) {
  unsigned char* hex = malloc(2 * _len);

  static char hexval[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  for (int j = 0; j < _len; j++) {
    hex[j * 2] = hexval[((d[j] >> 4) & 0xF)];
    hex[j * 2 + 1] = hexval[(d[j]) & 0x0F];
  }

  return hex;
}


int char2int( char _input ) {
  if ( _input >= '0' && _input <= '9' )
    return _input - '0';
  if
      ( _input >= 'A' && _input <= 'F' )
    return _input - 'A' + 10;
  if ( _input >= 'a' && _input <= 'f' )
    return _input - 'a' + 10;
  return -1;
}



void usage () {
	fprintf(stderr, "usage: sgxd\n");
	exit(1);
}

int main (int argc, char *argv[])
{
	sgx_launch_token_t token= { 0 };
	sgx_enclave_id_t eid= 0;
	sgx_status_t status;
	int updated= 0;
	unsigned long support;
	int opt;

	while ( (opt= getopt(argc, argv, "h")) != -1 ) {
		switch (opt) {
		case 'h':
		default:
			usage();
		}
	}

	argc-= optind;
	argv+= optind;

	if ( argc != 0 ) usage();


	/*
	digits= strtoull(argv[0], NULL, 10);
	if ( digits == 0 ) {
		fprintf(stderr, "invalid digit count\n");
		return 1;
	}

	 */

#ifndef SGX_HW_SIM
	support= get_sgx_support();
	if ( ! SGX_OK(support) ) {
		sgx_support_perror(support);
		return 1;
	}
#endif

	status= sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG,
		 &token, &updated, &eid, 0);


	if ( status != SGX_SUCCESS ) {
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) {
			fprintf(stderr, "sgx_create_enclave: %s: file not found\n",
				ENCLAVE_NAME);
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		} else {
			fprintf(stderr, "%s: 0x%04x\n", ENCLAVE_NAME, status);
		}
		return 1;
	}

	fprintf(stderr, "Enclave launched\n");

	status= tgmp_init(eid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL tgmp_init: 0x%04x\n", status);
		return 1;
	}

	fprintf(stderr, "libtgmp initialized\n");


	const char* key = "4160780231445160889237664391382223604184857153814275770598791864649971919844";

	char keyArray[128];

	unsigned char encryptedKey[1024];

	strncpy(keyArray, key, 128);

        int err_status = -2;

        int enc_len = -1;


	status= encrypt_key(eid, &err_status, keyArray, encryptedKey, &enc_len);


	if ( status != SGX_SUCCESS || enc_len < 10 ) {
		fprintf(stderr, "ECALL encrypt_key: 0x%04x\n", status);
		return 1;
	}


	gmp_printf("Encrypt key completed with status: %d \n", err_status);

	unsigned char* result = carray2Hex(encryptedKey, enc_len);

        gmp_printf("Result: %s", result);

        gmp_printf("\n Length: %d \n", enc_len);



	return 0;
}


