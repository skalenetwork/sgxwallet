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
#include "EnclaveGmpTest_u.h"
#include "create_enclave.h"
#include "sgx_detect.h"

#define ENCLAVE_NAME "EnclaveGmpTest.signed.so"

int main (int argc, char *argv[])
{
	sgx_launch_token_t token= { 0 };
	sgx_enclave_id_t eid= 0;
	sgx_status_t status;
	int updated= 0;
	unsigned long support;
	mpz_t a, b, c;
	mpf_t fa, fb, fc;

	if ( argc != 3 ) {
		fprintf(stderr, "usage: sgxgmptest num1 num2\n");
		return 1;
	}

	mpz_init_set_str(a, argv[1], 10);	/* Assume base 10 */
	mpz_init_set_str(b, argv[2], 10);	/* Assume base 10 */
	mpz_init(c);

	mpf_inits(fa, fb, fc, NULL);
	mpf_set_z(fa, a);
	mpf_set_z(fb, b);

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
		fprintf(stderr, "ECALL test_mpz_add: 0x%04x\n", status);
		return 1;
	}

	fprintf(stderr, "libtgmp initialized\n");

	status= e_mpz_add(eid, &c, &a, &b);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL test_mpz_add_ui: 0x%04x\n", status);
		return 1;
	}

	gmp_printf("iadd : %Zd + %Zd = %Zd\n\n", a, b, c);

	status= e_mpz_mul(eid, &c, &a, &b);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL test_mpz_mul: 0x%04x\n", status);
		return 1;
	}

	gmp_printf("imul : %Zd * %Zd = %Zd\n\n", a, b, c);

	status= e_mpz_div(eid, &c, &a, &b);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL test_mpz_div: 0x%04x\n", status);
		return 1;
	}

	gmp_printf("idiv : %Zd / %Zd = %Zd\n\n", a, b, c);

	status= e_mpf_div(eid, &fc, &fa, &fb);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL test_mpz_div: 0x%04x\n", status);
		return 1;
	}

	gmp_printf("fdiv : %Zd / %Zd = %.12Ff\n\n", a, b, fc);

	return 0;
}

