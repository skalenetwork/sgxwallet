/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file BLSEnclave.cpp
    @author Stan Kladko
    @date 2019
*/

#define GMP_WITH_SGX

#include <string.h>
#include <cstdint>
//#include "../sgxwallet_common.h"
#include "enclave_common.h"


#include "BLSEnclave.h"
#include "../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"
#include "../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

std::string *stringFromKey(libff::alt_bn128_Fr *_key) {

    mpz_t t;
    mpz_init(t);

    _key->as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return new std::string(tmp);
}

std::string *stringFromFq(libff::alt_bn128_Fq *_fq) {

    mpz_t t;
    mpz_init(t);

    _fq->as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return new std::string(tmp);
}

std::string *stringFromG1(libff::alt_bn128_G1 *_g1) {


    _g1->to_affine_coordinates();

    auto sX = stringFromFq(&_g1->X);
    auto sY = stringFromFq(&_g1->Y);

    auto sG1 = new std::string(*sX + ":" + *sY);

    delete (sX);
    delete (sY);

    return sG1;

}


libff::alt_bn128_Fr *keyFromString(const char *_keyStringHex) {
    mpz_t skey;
    mpz_init(skey);
    mpz_set_str(skey, _keyStringHex, 16);

    char skey_dec[mpz_sizeinbase (skey, 10) + 2];
    char * skey_str = mpz_get_str(skey_dec, 10, skey);

    return new libff::alt_bn128_Fr(skey_dec);
}


int inited = 0;

void init() {
    if (inited == 1)
        return;
    inited = 1;
    libff::init_alt_bn128_params();
}

void checkKey(int *errStatus, char *err_string, const char *_keyString) {

    uint64_t keyLen = strnlen(_keyString, MAX_KEY_LENGTH);

    // check that key is zero terminated string

    if (keyLen == MAX_KEY_LENGTH) {
        snprintf(err_string, MAX_ERR_LEN, "keyLen != MAX_KEY_LENGTH");
        return;
    }


    *errStatus = -2;


    if (_keyString == nullptr) {
        snprintf(err_string, BUF_LEN, "Null key");
        return;
    }

    *errStatus = -3;

     //check that key is padded with 0s

    for (int i = keyLen; i < MAX_KEY_LENGTH; i++) {
        if (_keyString[i] != 0) {
            snprintf(err_string, BUF_LEN, "Unpadded key");
        }
    }

//    std::string ks(_keyString);
//
//    // std::string  keyString =
//    // "4160780231445160889237664391382223604184857153814275770598791864649971919844";
//
//    auto key = keyFromString(ks.c_str());
//
//    auto s1 = stringFromKey(key);
//
//    if (s1->compare(ks) != 0) {
//        throw std::exception();
//    }

    *errStatus = 0;

   // return;
}


bool enclave_sign(const char *_keyString, const char *_hashXString, const char *_hashYString,
          char* sig) {


    libff::init_alt_bn128_params();


    auto key = keyFromString(_keyString);

    if (key == nullptr) {
        throw std::exception();
    }

    libff::alt_bn128_Fq hashX(_hashXString);
    libff::alt_bn128_Fq hashY(_hashYString);
    libff::alt_bn128_Fq hashZ = 1;


    libff::alt_bn128_G1 hash(hashX, hashY, hashZ);

    libff::alt_bn128_G1 sign = key->as_bigint() * hash;  // sign

    sign.to_affine_coordinates();



    auto r = stringFromG1(&sign);

    memset(sig, 0, BUF_LEN);



    strncpy(sig, r->c_str(), BUF_LEN);

    delete r;



    return true;


}

void  carray2Hex(const unsigned char *d, int _len, char* _hexArray) {

    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (int j = 0; j < _len; j++) {
        _hexArray[j * 2] = hexval[((d[j] >> 4) & 0xF)];
        _hexArray[j * 2 + 1] = hexval[(d[j]) & 0x0F];
    }

    _hexArray[_len * 2] = 0;

}

int char2int(char _input) {
  if (_input >= '0' && _input <= '9')
    return _input - '0';
  if (_input >= 'A' && _input <= 'F')
    return _input - 'A' + 10;
  if (_input >= 'a' && _input <= 'f')
    return _input - 'a' + 10;
  return -1;
}

bool hex2carray2(const char * _hex, uint64_t  *_bin_len,
                 uint8_t* _bin, const int _max_length ) {

    int len = strnlen(_hex, _max_length);//2 * BUF_LEN);


    if (len == 0 && len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (int i = 0; i < len / 2; i++) {
        int high = char2int((char)_hex[i * 2]);
        int low = char2int((char)_hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        _bin[i] = (unsigned char) (high * 16 + low);
    }

    return true;

}

bool hex2carray(const char * _hex, uint64_t  *_bin_len,
                uint8_t* _bin ) {

  int len = strnlen(_hex, 2 * BUF_LEN);


  if (len == 0 && len % 2 == 1)
    return false;

  *_bin_len = len / 2;

  for (int i = 0; i < len / 2; i++) {
    int high = char2int((char)_hex[i * 2]);
    int low = char2int((char)_hex[i * 2 + 1]);

    if (high < 0 || low < 0) {
      return false;
    }

    _bin[i] = (unsigned char) (high * 16 + low);
  }

  return true;

}


