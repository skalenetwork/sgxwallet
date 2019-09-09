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
#include "ServerInit.h"

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


TEST_CASE("BLS key encrypt", "[bls-key-encrypt-decrypt]") {
    {


        init_all();

        const char *key = "4160780231445160889237664391382223604184857153814275770598"
                          "791864649971919844";

        char *keyArray = (char *) calloc(128, 1);
        uint8_t *encryptedKey = (uint8_t *) calloc(1024, 1);


        char *errMsg = (char *) calloc(1024, 1);

        strncpy((char *) keyArray, (char *) key, 128);

        int errStatus = 0;

        unsigned int encryptedLen = 0;

        status = encrypt_key(eid, &errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);

        REQUIRE(status == SGX_SUCCESS);
        REQUIRE(errStatus == 0);

        printf("Encrypt key completed with status: %d %s \n", errStatus, errMsg);
        printf(" Encrypted key len %d\n", encryptedLen);


        char result[2 * BUF_LEN];

        carray2Hex(encryptedKey, encryptedLen, result);

        uint64_t decodedLen = 0;

        uint8_t decoded[BUF_LEN];

        REQUIRE(hex2carray(result, &decodedLen, decoded));

        for (uint64_t i = 0; i < decodedLen; i++) {
            REQUIRE(decoded[i] == encryptedKey[i]);
        }

        REQUIRE(decodedLen == encryptedLen);

        gmp_printf("Result: %s", result);

        gmp_printf("\n Length: %d \n", encryptedLen);

    }
}


TEST_CASE("BLS sign test", "[bls-sign]") {

    init_all();

    const char *key = "4160780231445160889237664391382223604184857153814275770598"
                      "791864649971919844";


    const char *hexHash = "001122334455667788" "001122334455667788" "001122334455667788" "001122334455667788";


    char *keyArray = (char *) calloc(128, 1);

    uint8_t *encryptedKey = (uint8_t *) calloc(1024, 1);

    char *errMsg = (char *) calloc(1024, 1);

    strncpy((char *) keyArray, (char *) key, 128);

    int errStatus = 0;

    unsigned int encryptedLen = 0;

    status = encrypt_key(eid, &errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == 0);


    printf("Encrypt key completed with status: %d %s \n", errStatus, errMsg);
    printf(" Encrypted key len %d\n", encryptedLen);


    char result[2 * BUF_LEN];

    carray2Hex(encryptedKey, encryptedLen, result
    );

    uint64_t dec_len = 0;

    uint8_t bin[BUF_LEN];

    REQUIRE(hex2carray(result, &dec_len, bin)
    );

    for (uint64_t i = 0; i < dec_len; i++) {
        REQUIRE(bin[i] == encryptedKey[i]);
    }

    REQUIRE(dec_len == encryptedLen);

    gmp_printf("Result: %s", result);

    gmp_printf("\n Length: %d \n", encryptedLen);


    char sig[BUF_LEN];

    REQUIRE(sign(result, hexHash, 2, 2, 1, sig));

}


TEST_CASE("DKG gen test", "[dkg-gen]") {

    init_all();

// put your test here
}

