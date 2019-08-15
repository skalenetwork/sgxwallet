//
// Created by kladko on 8/14/19.
//

#define GMP_WITH_SGX
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"
#include "BLSUtils.h"

void import_key() {

  auto private_key = new libff::alt_bn128_Fr("4160780231445160889237664391382223604184857153814275770598791864649971919844");


    mpz_t t;
    mpz_init(t);

    private_key->as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase (t, 10) + 2];

    char * tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    std::string output = tmp;

}
