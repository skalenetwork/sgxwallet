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
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>



#include <jsonrpccpp/server/connectors/httpserver.h>


#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>

#include <libff/algebra/fields/fp.hpp>

#include <dkg/dkg.h>

#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>
#include <stdio.h>

#include "BLSCrypto.h"
#include "ServerInit.h"


#include "RPCException.h"
#include "LevelDB.h"

#include "SGXWalletServer.hpp"

#include <sgx_tcrypto.h>

#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "catch.hpp"

#include "stubclient.h"

std::string stringFromFr(libff::alt_bn128_Fr& el) {

    mpz_t t;
    mpz_init(t);

    el.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return std::string(tmp);
}


void usage() {
    fprintf(stderr, "usage: sgxwallet\n");
    exit(1);
}

sgx_launch_token_t token = {0};
sgx_enclave_id_t eid;
sgx_status_t status;
int updated;

#define  TEST_BLS_KEY_SHARE "4160780231445160889237664391382223604184857153814275770598791864649971919844"
#define TEST_BLS_KEY_NAME "SCHAIN:17:INDEX:5:KEY:1"

void reset_db() {
    REQUIRE(system("rm -rf " WALLETDB_NAME) == 0);
}

char* encryptTestKey() {

    const char *key = TEST_BLS_KEY_SHARE;


    int errStatus = -1;

    char *errMsg = (char *) calloc(BUF_LEN, 1);

    char *encryptedKeyHex = encryptBLSKeyShare2Hex(&errStatus, errMsg, key);

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

        char* plaintextKey = decryptBLSKeyShareFromHex(&errStatus, errMsg, encryptedKey);

        REQUIRE(errStatus == 0);

        REQUIRE(strcmp(plaintextKey, TEST_BLS_KEY_SHARE) == 0);

        printf("Decrypt key completed with status: %d %s \n", errStatus, errMsg);
        printf("Decrypted key len %d\n", (int) strlen(plaintextKey));
        printf("Decrypted key: %s\n", plaintextKey);


    }
}

TEST_CASE("BLS key import", "[bls-key-import]") {
    reset_db();
    init_all();



    auto result = importBLSKeyShareImpl(1, TEST_BLS_KEY_SHARE, TEST_BLS_KEY_NAME, 2, 2);

    REQUIRE(result["status"] == 0);

    REQUIRE(result["encryptedKeyShare"] != "");

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

TEST_CASE("Server BLS sign test", "[bls-server-sign]") {

    reset_db();

    init_all();

    auto result = importBLSKeyShareImpl(1, TEST_BLS_KEY_SHARE, TEST_BLS_KEY_NAME, 2, 2);

    REQUIRE(result["status"] == 0);

    REQUIRE(result["encryptedKeyShare"] != "");

    const char *hexHash = "001122334455667788" "001122334455667788" "001122334455667788" "001122334455667788";

    REQUIRE_NOTHROW(result = blsSignMessageHashImpl(TEST_BLS_KEY_NAME, hexHash));

    if (result["status"] != 0) {
        printf("Error message: %s", result["errorMessage"].asString().c_str());
    }


    REQUIRE(result["status"] == 0);
    REQUIRE(result["signatureShare"] != "");

    printf("Signature is: %s \n",  result["signatureShare"].asString().c_str());

}

TEST_CASE("KeysDB test", "[keys-db]") {



    reset_db();
    init_all();


    string key = TEST_BLS_KEY_SHARE;
    string value = TEST_BLS_KEY_SHARE;



    REQUIRE_THROWS(readKeyShare(key));


    writeKeyShare(key, value, 1, 2, 1);

    REQUIRE(readKeyShare(key) != nullptr);


// put your test here
}




TEST_CASE( "DKG gen test", "[dkg-gen]" ) {

  init_all();

  uint8_t* encrypted_dkg_secret = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);

  char* errMsg = (char*) calloc(1024,1);
  int err_status = 0;
  uint32_t enc_len = 0;

  status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, 16);
  REQUIRE(status == SGX_SUCCESS);
  printf("gen_dkg_secret completed with status: %d %s \n", err_status, errMsg);
  printf("\n Length: %d \n", enc_len);

  char* secret = (char*)calloc(DKG_MAX_SEALED_LEN, sizeof(char));

  char* errMsg1 = (char*) calloc(1024,1);

  status = decrypt_dkg_secret(eid, &err_status, errMsg1, encrypted_dkg_secret, (uint8_t*)secret, enc_len);
  REQUIRE(status == SGX_SUCCESS);

  printf("\ndecrypt_dkg_secret completed with status: %d %s \n", err_status, errMsg1);
  printf("decrypted secret %s \n\n", secret);

  free(errMsg);
  free(errMsg1);
  free(encrypted_dkg_secret);
  free(secret);

  sgx_destroy_enclave(eid);
}

std::vector<libff::alt_bn128_Fr> SplitStringToFr(const char* koefs, const char symbol){
  std::string str(koefs);
  std::string delim;
  delim.push_back(symbol);
  std::vector<libff::alt_bn128_Fr> tokens;
  size_t prev = 0, pos = 0;
  do
  {
    pos = str.find(delim, prev);
    if (pos == std::string::npos) pos = str.length();
    std::string token = str.substr(prev, pos-prev);
    if (!token.empty()) {
      libff::alt_bn128_Fr koef(token.c_str());
      tokens.push_back(koef);
    }
    prev = pos + delim.length();
  }
  while (pos < str.length() && prev < str.length());

  return tokens;
}

std::vector<std::string> SplitString(const char* koefs, const char symbol){
  libff::init_alt_bn128_params();
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

libff::alt_bn128_G2 VectStringToG2(const std::vector<std::string>& G2_str_vect){
  libff::init_alt_bn128_params();
  libff::alt_bn128_G2 koef = libff::alt_bn128_G2::zero();
  koef.X.c0 = libff::alt_bn128_Fq(G2_str_vect.at(0).c_str());
  koef.X.c1 = libff::alt_bn128_Fq(G2_str_vect.at(1).c_str());
  koef.Y.c0 = libff::alt_bn128_Fq(G2_str_vect.at(2).c_str());
  koef.Y.c1 = libff::alt_bn128_Fq(G2_str_vect.at(3).c_str());
  koef.Z.c0 = libff::alt_bn128_Fq::one();
  koef.Z.c1 = libff::alt_bn128_Fq::zero();

  return koef;
}



 TEST_CASE( "DKG secret shares test", "[dkg-s_shares]" ) {
  libff::init_alt_bn128_params();
  //init_all();
  init_enclave();
  uint8_t* encrypted_dkg_secret = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);

  char* errMsg = (char*) calloc(1024,1);
  int err_status = 0;
  uint32_t enc_len = 0;

  unsigned t = 3, n = 4;

  status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, n);
  REQUIRE(status == SGX_SUCCESS);
  printf("gen_dkg_secret completed with status: %d %s \n", err_status, errMsg);
  printf("\n Length: %d \n", enc_len);

  char* errMsg1 = (char*) calloc(1024,1);

  char colon = ':';
  char* secret_shares = (char*)calloc(DKG_MAX_SEALED_LEN, 1);
  status = get_secret_shares(eid, &err_status, errMsg1, encrypted_dkg_secret, enc_len, secret_shares, t, n);
  REQUIRE(status == SGX_SUCCESS);
  printf("\nget_secret_shares status: %d %s \n", err_status, errMsg1);
  printf("secret shares %s \n\n", secret_shares);

  std::vector <libff::alt_bn128_Fr> s_shares = SplitStringToFr( secret_shares, colon);

  char* secret = (char*)calloc(DKG_MAX_SEALED_LEN, sizeof(char));
  status = decrypt_dkg_secret(eid, &err_status, errMsg1, encrypted_dkg_secret, (uint8_t*)secret, enc_len);
  REQUIRE(status == SGX_SUCCESS);
 // printf("\ndecrypt_dkg_secret completed with status: %d %s \n", err_status, errMsg1);

  signatures::Dkg dkg_obj(t,n);

  std::vector < libff::alt_bn128_Fr> poly = SplitStringToFr((char*)secret, colon);
  std::vector < libff::alt_bn128_Fr> s_shares_dkg = dkg_obj.SecretKeyContribution(SplitStringToFr((char*)secret, colon));
  /*printf("calculated secret: \n");
  for ( int  i = 0; i < s_shares_dkg.size(); i++){
    libff::alt_bn128_Fr cur_share = s_shares_dkg.at(i);
    mpz_t(sshare);
    mpz_init(sshare);
    cur_share.as_bigint().to_mpz(sshare);
    char arr[mpz_sizeinbase (sshare, 10) + 2];
    char* share_str = mpz_get_str(arr, 10, sshare);
    printf(" %s \n", share_str);
    mpz_clear(sshare);
  }*/


  REQUIRE(s_shares == s_shares_dkg);

  free(errMsg);
  free(errMsg1);
  free(encrypted_dkg_secret);
  free(secret_shares);

  sgx_destroy_enclave(eid);
}

TEST_CASE( "DKG public shares test", "[dkg-pub_shares]" ) {

  //init_all();
  init_enclave();
  uint8_t* encrypted_dkg_secret = (uint8_t*) calloc(DKG_MAX_SEALED_LEN, 1);

  char* errMsg = (char*) calloc(1024,1);
  int err_status = 0;
  uint32_t enc_len = 0;

  unsigned t = 3, n = 4;

  status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, n);
  REQUIRE(status == SGX_SUCCESS);
//  printf("gen_dkg_public completed with status: %d %s \n", err_status, errMsg);


  char* errMsg1 = (char*) calloc(1024,1);

  char colon = ':';
  char* public_shares = (char*)calloc(4000, 1);
  status = get_public_shares(eid, &err_status, errMsg1, encrypted_dkg_secret, enc_len, public_shares, t, n);
  REQUIRE(status == SGX_SUCCESS);
  //printf("\nget_public_shares status: %d error %s \n\n", err_status, errMsg1);

  std::vector <std::string> G2_strings = SplitString( public_shares, ',');
  std::vector <libff::alt_bn128_G2> pub_shares_G2;
  for ( int i = 0; i < G2_strings.size(); i++){
    std::vector <std::string> koef_str = SplitString(G2_strings.at(i).c_str(), ':');
    libff::alt_bn128_G2 el = VectStringToG2(koef_str);
   // std::cerr << "pub_share G2 " << i+1 << " : " << std::endl;
   // el.print_coordinates();
    pub_shares_G2.push_back(VectStringToG2(koef_str));
  }

  char* secret = (char*)calloc(DKG_MAX_SEALED_LEN, sizeof(char));
  status = decrypt_dkg_secret(eid, &err_status, errMsg1, encrypted_dkg_secret, (uint8_t*)secret, enc_len);
  REQUIRE(status == SGX_SUCCESS);
  //printf("\ndecrypt_dkg_secret completed with status: %d %s \n", err_status, errMsg1);

  signatures::Dkg dkg_obj(t,n);

  std::vector < libff::alt_bn128_Fr> poly = SplitStringToFr((char*)secret, colon);
  std::vector < libff::alt_bn128_G2> pub_shares_dkg = dkg_obj.VerificationVector(poly);
  /*printf("calculated public shares (X.c0): \n");
  for ( int  i = 0; i < pub_shares_dkg.size(); i++){
    libff::alt_bn128_G2 el = pub_shares_dkg.at(i);
    el.to_affine_coordinates();
    libff::alt_bn128_Fq x_c0_el = el.X.c0;
    mpz_t x_c0;
    mpz_init(x_c0);
    x_c0_el.as_bigint().to_mpz(x_c0);
    char arr[mpz_sizeinbase (x_c0, 10) + 2];
    char* share_str = mpz_get_str(arr, 10, x_c0);
    printf(" %s \n", share_str);
    mpz_clear(x_c0);
  }*/

  bool res = (pub_shares_G2 == pub_shares_dkg);
  REQUIRE( res == true);

  free(errMsg);
  free(errMsg1);
  free(encrypted_dkg_secret);
  free(public_shares);

  sgx_destroy_enclave(eid);
}

TEST_CASE( "DKG drive key test", "[dkg-drive-key]" ) {

  // init_all();
  init_enclave();
  uint8_t *encrypted_key = (uint8_t *) calloc(BUF_LEN, 1);

  char *errMsg = (char *)calloc(1024, 1);
  char *result = (char *)calloc(1024, 1);
  char *pub_key = (char *)calloc(1024, 1);
  int err_status = 0;
  uint32_t enc_len = 0;

  unsigned t = 3, n = 4;

  status = drive_key(eid, &err_status, errMsg, encrypted_key, &enc_len, result,
                     pub_key);

  REQUIRE(status == SGX_SUCCESS);
  printf(" drive_key completed with status: %d %s \n", err_status, errMsg);
}


TEST_CASE("ECDSA keygen and signature test", "[ecdsa_test]") {

  init_enclave();

  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  uint8_t *encr_pr_key = (uint8_t *)calloc(1024, 1);

  char *pub_key_x = (char *)calloc(1024, 1);
  char *pub_key_y = (char *)calloc(1024, 1);
  uint32_t enc_len = 0;

  //printf("before %p\n", pub_key_x);

  status = generate_ecdsa_key(eid, &err_status, errMsg, encr_pr_key, &enc_len, pub_key_x, pub_key_y );
  printf("\nerrMsg %s\n", errMsg );
  REQUIRE(status == SGX_SUCCESS);

  printf("\nwas pub_key_x %s: \n", pub_key_x);
  printf("\nwas pub_key_y %s: \n", pub_key_y);
  /*printf("\nencr priv_key : \n");
  for ( int i = 0; i < 1024 ; i++)
    printf("%u ", encr_pr_key[i]);*/

 // char* hex = "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a";
  char* hex = "0x09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db";
  printf("hash length %d ", strlen(hex));
  char* signature_r = (char *)calloc(1024, 1);
  char* signature_s = (char *)calloc(1024, 1);
  uint8_t signature_v = 0;

  status = ecdsa_sign1(eid, &err_status, errMsg, encr_pr_key, enc_len, (unsigned char*)hex, signature_r, signature_s, &signature_v, 16);
  REQUIRE(status == SGX_SUCCESS);
  printf("\nsignature r : %s  ", signature_r);
  printf("\nsignature s: %s  ", signature_s);
  printf("\nsignature v: %u  ", signature_v);
  printf("\n %s  \n", errMsg);

  free(errMsg);
  sgx_destroy_enclave(eid);
  printf("the end of ecdsa test\n");
}

TEST_CASE("Test test", "[test_test]") {

  init_enclave();

  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  uint8_t *encr_pr_key = (uint8_t *)calloc(1024, 1);

  char *pub_key_x = (char *)calloc(1024, 1);
  char *pub_key_y = (char *)calloc(1024, 1);
  uint32_t enc_len = 0;

  status = generate_ecdsa_key(eid, &err_status, errMsg, encr_pr_key, &enc_len, pub_key_x, pub_key_y );
  //printf("\nerrMsg %s\n", errMsg );
  REQUIRE(status == SGX_SUCCESS);


  //printf("\nwas pub_key_x %s: \n", pub_key_x);
  //printf("\nwas pub_key_y %s: \n", pub_key_y);
  //printf("\nencr priv_key %s: \n");

  //for ( int i = 0; i < 1024 ; i++)
   // printf("%u ", encr_pr_key[i]);

  //printf( "haha");

  //free(errMsg);
  sgx_destroy_enclave(eid);


}

TEST_CASE("get public ECDSA key", "[get_pub_ecdsa_key_test]") {

  //init_all();
  init_enclave();

  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  uint8_t *encr_pr_key = (uint8_t *)calloc(1024, 1);

  char *pub_key_x = (char *)calloc(1024, 1);
  char *pub_key_y = (char *)calloc(1024, 1);
  uint32_t enc_len = 0;

  //printf("before %p\n", pub_key_x);

  status = generate_ecdsa_key(eid, &err_status, errMsg, encr_pr_key, &enc_len, pub_key_x, pub_key_y );
  printf("\nerrMsg %s\n", errMsg );
  REQUIRE(status == SGX_SUCCESS);

  printf("\nwas pub_key_x %s length %d: \n", pub_key_x, strlen(pub_key_x));
  printf("\nwas pub_key_y %s length %d: \n", pub_key_y, strlen(pub_key_y));

  /*printf("\nencr priv_key %s: \n");
  for ( int i = 0; i < 1024 ; i++)
   printf("%u ", encr_pr_key[i]);*/

  char *got_pub_key_x = (char *)calloc(1024, 1);
  char *got_pub_key_y = (char *)calloc(1024, 1);

  status = get_public_ecdsa_key(eid, &err_status, errMsg, encr_pr_key, enc_len, got_pub_key_x,  got_pub_key_y);
  REQUIRE(status == SGX_SUCCESS);
  printf("\nnow pub_key_x %s: \n", got_pub_key_x);
  printf("\nnow pub_key_y %s: \n", got_pub_key_y);
  printf("\n pr key  %s  \n", errMsg);

  free(errMsg);
  sgx_destroy_enclave(eid);
}

#include "stubclient.h"
#include <jsonrpccpp/client/connectors/httpclient.h>

using namespace jsonrpc;
using namespace std;

TEST_CASE("API test", "[api_test]") {
    cerr << "API test started" << endl;
    init_all();

    //HttpServer httpserver(1025);
    //SGXWalletServer s(httpserver,
     //               JSONRPC_SERVER_V1); // hybrid server (json-rpc 1.0 & 2.0)
    // s.StartListening();
    cerr << "Server inited" << endl;
    HttpClient client("http://localhost:1025");
    StubClient c(client, JSONRPC_CLIENT_V2);

    cerr << "Client inited" << endl;

    try {
          // cout << c.generateECDSAKey("known_key1") << endl;
         //cout<<c.getPublicECDSAKey("test_key");
        cout << c.ecdsaSignMessageHash(16, "known_key1","0x09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db" );
    } catch (JsonRpcException &e) {
        cerr << e.what() << endl;
    }

}
