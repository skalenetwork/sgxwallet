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

    @file DKGUtils.cpp
    @author Stan Kladko
    @date 2019
*/

#include "DKGUtils.h"

#ifdef USER_SPACE
#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../trusted_libff/libff/algebra/fields/fp.hpp>

#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>

#include "EnclaveConstants.h"
#include <cstdio>
#include <stdio.h>

#include "DHDkg.h"

using namespace std;

string stringFromFr(libff::alt_bn128_Fr& _el) {

    mpz_t t;
    mpz_init(t);

    _el.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase(t, 10) + 2];

    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return string(tmp);
}

template<class T> string ConvertToString(T field_elem, int base = 10) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char arr[mpz_sizeinbase (t, base) + 2];

  char * tmp = mpz_get_str(arr, base, t);
  mpz_clear(t);

  string output = tmp;

  return output;
}

string ConvertG2ToString(const libff::alt_bn128_G2 & elem, int base = 10, string delim = ":"){
  string result;
  result += ConvertToString(elem.X.c0);
  result += delim;
  result += ConvertToString(elem.X.c1);
  result += delim;
  result += ConvertToString(elem.Y.c0);
  result += delim;
  result += ConvertToString(elem.Y.c1);

  return result;
}

vector<libff::alt_bn128_Fr> SplitStringToFr(const char* coeffs, const char symbol){
    string str(coeffs);
    string delim;
    delim.push_back(symbol);
    vector<libff::alt_bn128_Fr> tokens;
    size_t prev = 0, pos = 0;
    do
    {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos-prev);
        if (!token.empty()) {
            libff::alt_bn128_Fr coeff(token.c_str());
            tokens.push_back(coeff);
        }
        prev = pos + delim.length();
    }
    while (pos < str.length() && prev < str.length());

    return tokens;
}

int gen_dkg_poly( char* secret, unsigned _t ){
  libff::init_alt_bn128_params();
  string result;
  for (size_t i = 0; i < _t; ++i) {
     libff::alt_bn128_Fr cur_coef = libff::alt_bn128_Fr::random_element();

     while (i == _t - 1 && cur_coef == libff::alt_bn128_Fr::zero()) {
       cur_coef = libff::alt_bn128_Fr::random_element();
     }
     result += stringFromFr(cur_coef);
     result += ":";
  }
  strncpy(secret, result.c_str(), result.length() + 1);

  if (strlen(secret) == 0) {
    return 1;
  }

  return 0;
}

libff::alt_bn128_Fr PolynomialValue(const vector<libff::alt_bn128_Fr>& pol, libff::alt_bn128_Fr point, unsigned _t) {
  libff::alt_bn128_Fr value = libff::alt_bn128_Fr::zero();

  libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();
  for (unsigned i = 0; i < pol.size(); ++i) {
     value += pol[i] * pow;
     pow *= point;
  }

  return value;
}

void calc_secret_shares(const char* decrypted_coeffs, char * secret_shares,      // calculates secret shares in base 10 to a string secret_shares,
    unsigned _t, unsigned _n) {                                                 // separated by ":"
  // calculate for each node a list of secret values that will be used for verification
  string result;
  char symbol = ':';
  vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_coeffs, symbol);

    for (size_t i = 0; i < _n; ++i) {
    libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(i + 1), _t);
    result += ConvertToString(secret_share);//stringFromFr(secret_share);
    result += ":";
  }
  strncpy(secret_shares, result.c_str(), result.length() + 1);
}

int calc_secret_share(const char* decrypted_coeffs, char * s_share,
                        unsigned _t, unsigned _n, unsigned ind) {
  libff::init_alt_bn128_params();
  char symbol = ':';
  vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_coeffs, symbol);
  if ( poly.size() != _t){
    return 1;
  }

  libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(ind), _t);
  string cur_share = ConvertToString(secret_share, 16);
  int n_zeroes = 64 - cur_share.size();
  cur_share.insert(0, n_zeroes, '0');

  strncpy(s_share, cur_share.c_str(), cur_share.length() + 1);
  return 0;
}

void calc_secret_shareG2_old(const char* decrypted_coeffs, char * s_shareG2,
                                            unsigned _t, unsigned ind) {
  libff::init_alt_bn128_params();
  char symbol = ':';
  vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_coeffs, symbol);

  libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(ind), _t);

  libff::alt_bn128_G2 secret_shareG2 = secret_share * libff::alt_bn128_G2::one();

  string secret_shareG2_str = ConvertG2ToString(secret_shareG2);

  strncpy(s_shareG2, secret_shareG2_str.c_str(), secret_shareG2_str.length() + 1);
}

int calc_secret_shareG2(const char* s_share, char * s_shareG2){
  libff::init_alt_bn128_params();

  mpz_t share;
  mpz_init(share);
  if (mpz_set_str(share, s_share, 16) == -1){
    mpz_clear(share);
    return 1;
  }

  char arr[mpz_sizeinbase (share, 10) + 2];
  char * share_str = mpz_get_str(arr, 10, share);

  libff::alt_bn128_Fr secret_share(share_str);

  libff::alt_bn128_G2 secret_shareG2 = secret_share * libff::alt_bn128_G2::one();

  secret_shareG2.to_affine_coordinates();

  string secret_shareG2_str = ConvertG2ToString(secret_shareG2);

  strncpy(s_shareG2, secret_shareG2_str.c_str(), secret_shareG2_str.length() + 1);

  mpz_clear(share);

  return 0;
}

int calc_public_shares(const char* decrypted_coeffs, char * public_shares,
                        unsigned _t) {
  libff::init_alt_bn128_params();
  // calculate for each node a list of public shares
  string result;
  char symbol = ':';
  vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_coeffs, symbol);
  if (poly.size() != _t){
    return 1;
  }
  for (size_t i = 0; i < _t; ++i) {
    libff::alt_bn128_G2 pub_share = poly.at(i) * libff::alt_bn128_G2::one() ;
    pub_share.to_affine_coordinates();
    string pub_share_str = ConvertG2ToString(pub_share);
    result += pub_share_str + ",";
  }
  strncpy(public_shares, result.c_str(), result.length());
  return 0;
}

string ConvertHexToDec(string hex_str){
  mpz_t dec;
  mpz_init(dec);

  if (mpz_set_str(dec, hex_str.c_str(), 16) == -1){
    mpz_clear(dec);
    return "false";
  }

  char arr[mpz_sizeinbase (dec, 10) + 2];
  char * result = mpz_get_str(arr, 10, dec);

  mpz_clear(dec);

  return result;
}

int Verification ( char * public_shares, mpz_t decr_secret_share, int _t, int ind ) {
  string pub_shares_str = public_shares;
  libff::init_alt_bn128_params();

  vector<libff::alt_bn128_G2> pub_shares;
  uint64_t share_length = 256;
  uint8_t coord_length = 64;

  for (size_t i = 0; i < _t; ++i) {
    libff::alt_bn128_G2 pub_share;

    uint64_t pos0 = share_length * i;
    string x_c0_str = ConvertHexToDec(pub_shares_str.substr(pos0, coord_length));
    string x_c1_str = ConvertHexToDec(pub_shares_str.substr(pos0 + coord_length, coord_length));
    string y_c0_str = ConvertHexToDec(pub_shares_str.substr(pos0 + 2 * coord_length, coord_length));
    string y_c1_str = ConvertHexToDec(pub_shares_str.substr(pos0 + 3 * coord_length, coord_length));
    if (x_c0_str == "false" || x_c1_str == "false" || y_c0_str == "false" || y_c1_str == "false"){
      return 2;
    }
    pub_share.X.c0 = libff::alt_bn128_Fq(x_c0_str.c_str());
    pub_share.X.c1 = libff::alt_bn128_Fq(x_c1_str.c_str());
    pub_share.Y.c0 = libff::alt_bn128_Fq(y_c0_str.c_str());
    pub_share.Y.c1 = libff::alt_bn128_Fq(y_c1_str.c_str());
    pub_share.Z = libff::alt_bn128_Fq2::one();

    pub_shares.push_back(pub_share);
  }

  libff::alt_bn128_G2 val = libff::alt_bn128_G2::zero();
   for (int i = 0; i < _t; ++i) {
    val = val + power(libff::alt_bn128_Fr(ind + 1), i) * pub_shares[i];
   }

  char arr[mpz_sizeinbase (decr_secret_share, 10) + 2];
  char * tmp = mpz_get_str(arr, 10, decr_secret_share);

  libff::alt_bn128_Fr sshare(tmp);

  libff::alt_bn128_G2  val2 = sshare * libff::alt_bn128_G2::one();

  memset(public_shares, 0, strlen(public_shares));
  strncpy(public_shares, tmp, strlen(tmp));

  val.to_affine_coordinates();
  val2.to_affine_coordinates();
  strncpy(public_shares, ConvertToString(val.X.c0).c_str(), ConvertToString(val.X.c0).length());
  strncpy(public_shares + ConvertToString(val.X.c0).length(), ":", 1);
  strncpy(public_shares + ConvertToString(val.X.c0).length() + 1, ConvertToString(val2.X.c0).c_str(), ConvertToString(val2.X.c0).length());

  return (val == sshare * libff::alt_bn128_G2::one());
}

int calc_bls_public_key(char* skey_hex, char* pub_key){
  libff::init_alt_bn128_params();

  mpz_t skey;
  mpz_init(skey);
  if (mpz_set_str(skey, skey_hex, 16) == -1) {
    mpz_clear(skey);
    return 1;
  }

  char skey_dec[mpz_sizeinbase (skey, 10) + 2];
  mpz_get_str(skey_dec, 10, skey);

  libff::alt_bn128_Fr bls_skey(skey_dec);

  libff::alt_bn128_G2 public_key = bls_skey * libff::alt_bn128_G2::one();
  public_key.to_affine_coordinates();

  string result = ConvertG2ToString(public_key);

  strncpy(pub_key, result.c_str(), result.length());

  mpz_clear(skey);

  return 0;
}




