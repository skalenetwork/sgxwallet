//
// Created by kladko on 8/14/19.
//

#define GMP_WITH_SGX
#include "BLSUtils.h"
#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

std::string *stringFromKey(libff::alt_bn128_Fr *_key) {

  mpz_t t;
  mpz_init(t);

  _key->as_bigint().to_mpz(t);

  char arr[mpz_sizeinbase(t, 10) + 2];

  char *tmp = mpz_get_str(arr, 10, t);
  mpz_clear(t);

  return new std::string(tmp);
}

libff::alt_bn128_Fr *keyFromString(std::string &_keyString) {

  return new libff::alt_bn128_Fr(_keyString.c_str());
}

bool check_key(const char *_keyString) {

  libff::init_alt_bn128_params();

  if (_keyString == nullptr)
    return false;

  std::string ks(_keyString);

  // std::string  keyString =
  // "4160780231445160889237664391382223604184857153814275770598791864649971919844";

  auto key = keyFromString(ks);

  auto s1 = stringFromKey(key);

  if (s1->compare(ks) != 0)
    return false;

  if (s1->size() < 10)
    return false;

  if (s1->size() >= 100)
    return false;

  return true;
}
