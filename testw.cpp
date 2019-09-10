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

char *encryptKey2Hex(int *errStatus, char *err_string, const char *_key) {
    char *keyArray = (char *) calloc(BUF_LEN, 1);
    uint8_t *encryptedKey = (uint8_t *) calloc(BUF_LEN, 1);
    char *errMsg = (char *) calloc(BUF_LEN, 1);
    strncpy((char *) keyArray, (char *) _key, BUF_LEN);

    *errStatus = -1;

    unsigned int encryptedLen = 0;

    status = encrypt_key(eid, errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        return nullptr;
    }

    if (*errStatus != 0) {
        return nullptr;
    }


    char *result = (char *) calloc(2 * BUF_LEN, 1);

    carray2Hex(encryptedKey, encryptedLen, result);

    return result;
}

char *decryptKeyFromHex(int *errStatus, char *errMsg, const char *_encryptedKey) {


        *errStatus = -1;

        uint64_t decodedLen = 0;

        uint8_t decoded[BUF_LEN];

        if (!(hex2carray(_encryptedKey, &decodedLen, decoded))) {
            return nullptr;
        }

        char *plaintextKey = (char *) calloc(BUF_LEN, 1);

        status = decrypt_key(eid, errStatus, errMsg, decoded, decodedLen, plaintextKey);

        if (status != SGX_SUCCESS) {
            return nullptr;
        }

        if (*errStatus != 0) {
            return nullptr;
        }

    return plaintextKey;

}


#define  TEST_KEY "4160780231445160889237664391382223604184857153814275770598791864649971919844"

void reset_db() {
    REQUIRE(system("rm -rf " WALLETDB_NAME) == 0);
}

char* encryptTestKey() {

    const char *key = TEST_KEY;


    int errStatus = -1;

    char *errMsg = (char *) calloc(BUF_LEN, 1);

    char *encryptedKeyHex = encryptKey2Hex(&errStatus, errMsg, key);

    REQUIRE(encryptedKeyHex != nullptr);
    REQUIRE(errStatus == 0);

    printf("Encrypt key completed with status: %d %s \n", errStatus, errMsg);
    printf("Encrypted key len %d\n", (int) strlen(encryptedKeyHex));
    printf("Encrypted key %s \n", encryptedKeyHex);

    return encryptedKeyHex;
}


TEST_CASE("BLS key encrypt", "[bls-key-encrypt]") {


    init_all();
    char* key = encryptTestKey();
    REQUIRE(key != nullptr);

}


TEST_CASE("BLS key encrypt/decrypt", "[bls-key-encrypt-decrypt]") {
    {


        init_all();

        int errStatus =  -1;
        char* errMsg = (char*) calloc(BUF_LEN, 1);



        char* encryptedKey = encryptTestKey();
        REQUIRE(encryptedKey != nullptr);

        char* plaintextKey = decryptKeyFromHex(&errStatus, errMsg, encryptedKey);

        REQUIRE(errStatus == 0);

        REQUIRE(strcmp(plaintextKey, TEST_KEY) == 0);

        printf("Decrypt key completed with status: %d %s \n", errStatus, errMsg);
        printf("Decrypted key len %d\n", (int) strlen(plaintextKey));
        printf("Decrypted key: %s\n", plaintextKey);


    }
}

TEST_CASE("BLS key import", "[bls-key-import]") {

}


TEST_CASE("BLS sign test", "[bls-sign]") {

    init_all();

    char* encryptedKeyHex = encryptTestKey();

    REQUIRE(encryptedKeyHex != nullptr);


    const char *hexHash = "001122334455667788" "001122334455667788" "001122334455667788" "001122334455667788";

    char* hexHashBuf = (char*) calloc(BUF_LEN, 1);

    strncpy(hexHashBuf,  hexHash, BUF_LEN);



    char sig[BUF_LEN];

    REQUIRE(sign(encryptedKeyHex, hexHashBuf, 2, 2, 1, sig));


    printf("Signature is: %s \n",  sig );



}



TEST_CASE("KeysDB test", "[dkg-gen]") {

    reset_db();
    init_all();

// put your test here
}




TEST_CASE("DKG gen test", "[dkg-gen]") {

    init_all();

// put your test here
}

