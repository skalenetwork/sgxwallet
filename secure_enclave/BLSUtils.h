//
// Created by kladko on 8/14/19.
//

#ifndef SGXWALLET_BLSUTILS_H
#define SGXWALLET_BLSUTILS_H



#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

EXTERNC void check_key(int *err_status, char *err_string, const char* _keyString);

EXTERNC bool sign(const char *_keyString, const char* _hashXString, const char* _hashYString,
           char* _sig);



EXTERNC int char2int(char _input);

EXTERNC void  carray2Hex(const unsigned char *d, int _len, char* _hexArray);
EXTERNC bool hex2carray(const char * _hex, uint64_t  *_bin_len,
                       uint8_t* _bin );

EXTERNC void init();


#endif //SGXWALLET_BLSUTILS_H
