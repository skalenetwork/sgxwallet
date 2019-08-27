//
// Created by kladko on 8/14/19.
//

#define GMP_WITH_SGX
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "BLSUtils.h"


std::string* stringFromKey(libff::alt_bn128_Fr* _key) {

    mpz_t t;
    mpz_init(t);

    _key->as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase (t, 10) + 2];

    char * tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return new std::string(tmp);

}


libff::alt_bn128_Fr* keyFromString(std::string& _keyString) {

    return new libff::alt_bn128_Fr(_keyString.c_str());

}




void import_key(const char* _keyString, char* encryptedKey, uint64_t bufLen) {

    if (encryptedKey == nullptr && bufLen < 100)
      throw std::exception();

    if (_keyString == nullptr)
        throw std::exception();

    std::string ks(_keyString);

    //std::string  keyString = "4160780231445160889237664391382223604184857153814275770598791864649971919844";

    auto key1 = keyFromString(ks);

    auto s1 = stringFromKey(key1);

    auto key2 = keyFromString(*s1);

    auto s2 = stringFromKey(key2);

    if (s1->compare(*s2) != 0)
        throw std::exception();


  if (s2->size() == 0)
    throw std::exception();

    if (s2->size() >= 100)
      throw std::exception();

    strncpy(encryptedKey, s2->c_str(), 100);

}
