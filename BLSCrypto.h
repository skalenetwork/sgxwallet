//
// Created by kladko on 9/2/19.
//

#ifndef SGXD_BLSCRYPTO_H
#define SGXD_BLSCRYPTO_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void init_daemon();

EXTERNC bool sign(char* encryptedKeyHex, char* hashHex, size_t t, size_t n, char* _sig);





#endif //SGXD_BLSCRYPTO_H
