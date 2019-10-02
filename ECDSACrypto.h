//
// Created by kladko on 9/23/19.
//

#ifndef SGXD_ECDSACRYPTO_H
#define SGXD_ECDSACRYPTO_H

#include <vector>
#include <string>



/*#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif*/

std::vector<std::string> gen_ecdsa_key();

std::string get_ecdsa_pubkey(const char* encryptedKeyHex);

std::vector<std::string> ecdsa_sign_hash(const char* encryptedKeyHex, const char* hashHex, int base);


#endif //SGXD_ECDSACRYPTO_H
