//
// Created by kladko on 8/14/19.
//

#ifndef SGXD_BLSUTILS_H
#define SGXD_BLSUTILS_H



#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void import_key(const char* _keyString, char* encryptedKey, uint64_t bufLen);


#endif //SGXD_BLSUTILS_H
