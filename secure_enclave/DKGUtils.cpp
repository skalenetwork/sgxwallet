//
// Created by kladko on 9/5/19.
//
#include "DKGUtils.h"


#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../trusted_libff/libff/algebra/fields/fp.hpp>

#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>


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

template<class T>
std::string ConvertToString(T field_elem) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char arr[mpz_sizeinbase (t, 10) + 2];

  char * tmp = mpz_get_str(arr, 10, t);
  mpz_clear(t);

  std::string output = tmp;

  return output;
}

std::vector<libff::alt_bn128_Fr> SplitStringToFr(const char* koefs, const char* symbol){
    std::string str(koefs);
    std::string delim(symbol);
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

libff::alt_bn128_Fr PolynomialValue(const std::vector<libff::alt_bn128_Fr>& pol, libff::alt_bn128_Fr point, unsigned _t) {

  libff::alt_bn128_Fr value = libff::alt_bn128_Fr::zero();

  libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();
  for (size_t i = 0; i < _t; ++i) {
    if (i == _t - 1 && pol[i] == libff::alt_bn128_Fr::zero()) {
      throw std::runtime_error("Error, incorrect degree of a polynomial");
    }
    value += pol[i] * pow;
    pow *= point;
  }

  return value;
}

void calc_secret_shares(const char* decrypted_koefs, char * secret_shares,
    unsigned _t, unsigned _n) {
  // calculate for each node a list of secret values that will be used for verification
  std::string result;
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, &symbol);
  for (size_t i = 0; i < _n; ++i) {
    libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(i + 1), _t);
    result += stringFromFr(secret_share);
    result += ":";
  }
  strncpy(secret_shares, result.c_str(), result.length());
}

void calc_public_shares(const char* decrypted_koefs, char * public_shares,
                        unsigned _t) {
  // calculate for each node a list of public shares
  std::string result;
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, &symbol);
  for (size_t i = 0; i < _t; ++i) {
    libff::alt_bn128_G2 pub_share =  poly.at(i) * libff::alt_bn128_G2::one();
    pub_share.to_affine_coordinates();
    result += ConvertToString(pub_share.X.c0);
    result += ":";
    result += ConvertToString(pub_share.X.c1);
    result += ":";
    result += ConvertToString(pub_share.Y.c0);
    result += ":";
    result += ConvertToString(pub_share.Y.c1);
    result += ",";
  }
  strncpy(public_shares, result.c_str(), result.length());
}


