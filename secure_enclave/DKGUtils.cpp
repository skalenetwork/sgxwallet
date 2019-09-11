//
// Created by kladko on 9/5/19.
//
#include "DKGUtils.h"


#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../trusted_libff/libff/algebra/fields/fp.hpp>


#include "../sgxwallet_common.h"
#include <cstdio>
#include <stdio.h>

#include <mbusafecrt.h>


std::string stringFromFr(libff::alt_bn128_Fr& _el) {

    mpz_t t;
    mpz_init(t);

    _el.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return std::string(tmp);
}

void gen_dkg_poly( char* secret/*[BUF_LEN]*/, unsigned len, unsigned _t ){
    libff::init_alt_bn128_params();
    std::string result;
    for (size_t i = 0; i < _t; ++i) {
        libff::alt_bn128_Fr cur_coef = libff::alt_bn128_Fr::random_element();

        while (i == _t - 1 && cur_coef == libff::alt_bn128_Fr::zero()) {
            cur_coef = libff::alt_bn128_Fr::random_element();
        }
       result = stringFromFr(cur_coef);
       result += ":";
    }

    strncpy(secret, result.c_str(), result.length());
    len = _t*33;//result.length();
}