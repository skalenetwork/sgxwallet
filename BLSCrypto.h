//
// Created by kladko on 9/2/19.
//


#ifndef SGXWALLET_BLSCRYPTO_H
#define SGXWALLET_BLSCRYPTO_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void init_all();

EXTERNC void init_daemon();

EXTERNC  void init_enclave();

EXTERNC bool sign(const char* encryptedKeyHex, const char* hashHex, size_t t, size_t n,
        size_t signerIndex, char* _sig);

EXTERNC int char2int(char _input);

EXTERNC void  carray2Hex(const unsigned char *d, int _len, char* _hexArray);
EXTERNC bool hex2carray(const char * _hex, uint64_t  *_bin_len,
                        uint8_t* _bin );
EXTERNC bool hex2carray2(const char * _hex, uint64_t  *_bin_len,
                 uint8_t* _bin, const int _max_length );



EXTERNC  char *encryptBLSKeyShare2Hex(int *errStatus, char *err_string, const char *_key);

EXTERNC char *decryptBLSKeyShareFromHex(int *errStatus, char *errMsg, const char *_encryptedKey);

#endif //SGXWALLET_BLSCRYPTO_H
