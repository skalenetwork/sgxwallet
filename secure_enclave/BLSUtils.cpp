//
// Created by kladko on 8/14/19.
//

#define GMP_WITH_SGX
#include <string.h>
#include <cstdint>
#include "../sgxwallet_common.h"


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

std::string *stringFromFq(libff::alt_bn128_Fq*_fq) {

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

  auto sG1 = new std::string(*sX + ":" +  *sY);

  delete(sX);
  delete(sY);

  return sG1;

}





libff::alt_bn128_Fr *keyFromString(const char* _keyString) {

  return new libff::alt_bn128_Fr(_keyString);
}

bool check_key(const char *_keyString) {

  libff::init_alt_bn128_params();

  if (_keyString == nullptr)
    return false;

  std::string ks(_keyString);

  // std::string  keyString =
  // "4160780231445160889237664391382223604184857153814275770598791864649971919844";

  auto key = keyFromString(ks.c_str());

  auto s1 = stringFromKey(key);

  if (s1->compare(ks) != 0)
    return false;

  if (s1->size() < 10)
    return false;

  if (s1->size() >= 100)
    return false;

  return true;
}



bool sign(const char *_keyString, const char* _hashXString, const char* _hashYString,
       char sig[BUF_LEN]) {

         auto key = keyFromString(_keyString);

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




