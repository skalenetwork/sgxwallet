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
std::string ConvertToString(T field_elem, int base = 10) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char arr[mpz_sizeinbase (t, base) + 2];

  char * tmp = mpz_get_str(arr, base, t);
  mpz_clear(t);

  std::string output = tmp;

  return output;
}

std::vector<libff::alt_bn128_Fr> SplitStringToFr(const char* koefs, const char symbol){
    std::string str(koefs);
    std::string delim;
    delim.push_back(symbol);
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

void gen_dkg_poly( char* secret, unsigned _t ){
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
    strncpy(secret, result.c_str(), result.length() + 1);
}

libff::alt_bn128_Fr PolynomialValue(const std::vector<libff::alt_bn128_Fr>& pol, libff::alt_bn128_Fr point, unsigned _t) {

  libff::alt_bn128_Fr value = libff::alt_bn128_Fr::zero();

  libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();
  for (size_t i = 0; i < _t; ++i) {
    if (i == _t - 1 && pol[i] == libff::alt_bn128_Fr::zero()) {
        //snprintf(err_string, BUF_LEN,"sgx_unseal_data failed with status
    }
    value += pol[i] * pow;
    pow *= point;
  }

  return value;
}

void calc_secret_shares(const char* decrypted_koefs, char * secret_shares,      // calculates secret shares in base 10 to a string secret_shares,
    unsigned _t, unsigned _n) {                                                 // separated by ":"
  // calculate for each node a list of secret values that will be used for verification
  std::string result;
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, symbol);
    for (size_t i = 0; i < _n; ++i) {
    libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(i + 1), _t);
    result += ConvertToString(secret_share);//stringFromFr(secret_share);
    result += ":";
  }
  strncpy(secret_shares, result.c_str(), result.length() + 1);
  //strncpy(secret_shares, decrypted_koefs, 3650);
}

void calc_secret_share(const char* decrypted_koefs, char * s_share,
                        unsigned _t, unsigned _n, unsigned ind) {

  libff::init_alt_bn128_params();
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, symbol);

  libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(ind), _t);
  std::string cur_share = ConvertToString(secret_share, 16);//stringFromFr(secret_share);
  int n_zeroes = 64 - cur_share.size();
  cur_share.insert(0, n_zeroes, '0');

  strncpy(s_share, cur_share.c_str(), cur_share.length() + 1);

}

void calc_public_shares(const char* decrypted_koefs, char * public_shares,
                        unsigned _t) {
  libff::init_alt_bn128_params();
  // calculate for each node a list of public shares
  std::string result;
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, symbol);
  for (size_t i = 0; i < _t; ++i) {
    libff::alt_bn128_G2 pub_share = poly.at(i) * libff::alt_bn128_G2::one() ;
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

int Verification (char * decrypted_koefs, mpz_t decr_secret_share, int _t, int ind ){

  libff::init_alt_bn128_params();
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, symbol);
  std::vector<libff::alt_bn128_G2> pub_shares;
  for (size_t i = 0; i < _t; ++i) {
    libff::alt_bn128_G2 pub_share = poly.at(i) * libff::alt_bn128_G2::one();
    pub_shares.push_back(pub_share);
  }

  libff::alt_bn128_G2 val = libff::alt_bn128_G2::zero();
   for (int i = 0; i < _t; ++i) {
    val = val + power(libff::alt_bn128_Fr(ind + 1), i) * pub_shares[i];
  }

  char arr[mpz_sizeinbase (decr_secret_share, 10) + 2];
  char * tmp = mpz_get_str(arr, 10, decr_secret_share);
  libff::alt_bn128_Fr sshare(tmp);

  //strncpy(decrypted_koefs, ConvertToString(val.X.c0).c_str(), 1024);

  libff::alt_bn128_G2  val2 = sshare * libff::alt_bn128_G2::one();
  strncpy(decrypted_koefs, ConvertToString(val2.X.c0).c_str(), 1024);

  return (val == sshare * libff::alt_bn128_G2::one());
}


