//
// Created by kladko on 9/5/19.
//
#include "DKGUtils.h"


#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../trusted_libff/libff/algebra/fields/fp.hpp>


#include "../sgxwallet_common.h"
#include <cstdio>
#include <stdio.h>


std::string stringFromFr(libff::alt_bn128_Fr& _el) {

    mpz_t t;
    mpz_init(t);

    _el.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return std::string(tmp);
}

std::vector<libff::alt_bn128_Fr> SplitString(const std::string& str, const std::string& delim){
    std::vector<libff::alt_bn128_Fr> tokens;
    size_t prev = 0, pos = 0;
    do
    {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos-prev);
        if (!token.empty()) {
            libff::alt_bn128_Fr koef(token.c_str());
            tokens.push_back(koef);
        }
        prev = pos + delim.length();
    }
    while (pos < str.length() && prev < str.length());

    return tokens;
}

void gen_dkg_poly( char* secret/*[BUF_LEN]*/, unsigned _t ){
    libff::init_alt_bn128_params();
    std::string result;
    for (size_t i = 0; i < _t; ++i) {
        libff::alt_bn128_Fr cur_coef = libff::alt_bn128_Fr::random_element();

        while (i == _t - 1 && cur_coef == libff::alt_bn128_Fr::zero()) {
            cur_coef = libff::alt_bn128_Fr::random_element();
        }
       result += stringFromFr(cur_coef);
       result += ":";
    }
    strncpy(secret, result.c_str(), result.length());
}

