//
// Created by kladko on 9/5/19.
//
#include "DKGUtils.h"

#include <sgx_tgmp.h>
#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../trusted_libff/libff/algebra/fields/fp.hpp>

#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>


#include "../sgxwallet_common.h"
#include <cstdio>
#include <stdio.h>

#include "DH_dkg.h"





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

std::string ConvertG2ToString(const libff::alt_bn128_G2 & elem, int base = 10, std::string delim = ":"){
  std::string result;
  result += ConvertToString(elem.X.c0);
  result += delim;
  result += ConvertToString(elem.X.c1);
  result += delim;
  result += ConvertToString(elem.Y.c0);
  result += delim;
  result += ConvertToString(elem.Y.c1);

  return result;
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

void calc_secret_shareG2(const char* decrypted_koefs, char * s_shareG2,
                                            unsigned _t, unsigned ind){
  libff::init_alt_bn128_params();
  char symbol = ':';
  std::vector<libff::alt_bn128_Fr> poly =  SplitStringToFr(decrypted_koefs, symbol);

  libff::alt_bn128_Fr secret_share = PolynomialValue(poly, libff::alt_bn128_Fr(ind), _t);

  libff::alt_bn128_G2 secret_shareG2 = secret_share * libff::alt_bn128_G2::one();

  std::string secret_shareG2_str = ConvertG2ToString(secret_shareG2);

  strncpy(s_shareG2, secret_shareG2_str.c_str(), secret_shareG2_str.length());
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
    std::string pub_share_str = ConvertG2ToString(pub_share);
    result += pub_share_str + ",";
  }
  strncpy(public_shares, result.c_str(), result.length());
}

//extern "C" int __gmpz_set_str (mpz_ptr, const char *, int);
std::string ConvertHexToDec(std::string hex_str){
  mpz_t dec;
  mpz_init(dec);

  mpz_set_str(dec, hex_str.c_str(), 16);

  char arr[mpz_sizeinbase (dec, 10) + 2];
  char * result = mpz_get_str(arr, 10, dec);

  mpz_clear(dec);

  return result;
}

int Verification ( char * public_shares, mpz_t decr_secret_share, int _t, int ind ){

  std::string pub_shares_str = public_shares;
  libff::init_alt_bn128_params();

  std::vector<libff::alt_bn128_G2> pub_shares;
  uint64_t share_length = 256;
  uint8_t coord_length = 64;

  for (size_t i = 0; i < _t; ++i) {
    libff::alt_bn128_G2 pub_share;

    uint64_t pos0 = share_length * i;
    pub_share.X.c0 = libff::alt_bn128_Fq(ConvertHexToDec(pub_shares_str.substr(pos0, coord_length)).c_str());
    pub_share.X.c1 = libff::alt_bn128_Fq(ConvertHexToDec(pub_shares_str.substr(pos0 + coord_length, coord_length)).c_str());
    pub_share.Y.c0 = libff::alt_bn128_Fq(ConvertHexToDec(pub_shares_str.substr(pos0 + 2 * coord_length, coord_length)).c_str());
    pub_share.Y.c1 = libff::alt_bn128_Fq(ConvertHexToDec(pub_shares_str.substr(pos0 + 3 * coord_length, coord_length)).c_str());

    pub_share.Z = libff::alt_bn128_Fq2::one();


    //for ( int j = 0; j < 4; j++) {
      //uint64_t pos0 = share_length * j;
      //std::string coord = ConvertHexToDec(pub_shares_str.substr(pos0 + j * coord_length, coord_length));
//      if ( i == 0) {
//        memset(public_shares, 0, strlen(public_shares));
//    std::string coord = ConvertToString(pub_share.Y.c1);
//    strncpy(public_shares, coord.c_str(), coord.length());
//  }
    //}

    pub_shares.push_back(pub_share);
  }

  libff::alt_bn128_G2 val = libff::alt_bn128_G2::zero();
   for (int i = 0; i < _t; ++i) {
    val = val + power(libff::alt_bn128_Fr(ind + 1), i) * pub_shares[i];
  }

  char arr[mpz_sizeinbase (decr_secret_share, 10) + 2];
  char * tmp = mpz_get_str(arr, 10, decr_secret_share);
  libff::alt_bn128_Fr sshare(tmp);






 // strncpy(public_shares, tmp, strlen(tmp));
//  std::string res = ConvertHexToDec("fe43567238abcdef98760");
//  strncpy(public_shares, res.c_str(), res.length());

  libff::alt_bn128_G2  val2 = sshare * libff::alt_bn128_G2::one();

    memset(public_shares, 0, strlen(public_shares));
   strncpy(public_shares, ConvertToString(val2.X.c0).c_str(), ConvertToString(val2.X.c0).length());
   strncpy(public_shares + ConvertToString(val2.X.c0).length(), ":", 1);
  strncpy(public_shares + ConvertToString(val2.X.c0).length() + 1, ConvertToString(val2.X.c1).c_str(), 77);



  val.to_affine_coordinates();
  val2.to_affine_coordinates();
//  strncpy(public_shares + strlen(tmp), ":", 1);
//  strncpy(public_shares + 77 + 1, ConvertToString(val.X.c0).c_str(), 77);
//  strncpy(public_shares + 77 + 78, ":", 1);
//  strncpy(public_shares + 77 + 79, ConvertToString(val2.X.c0).c_str(), 77);
  /*strncpy(public_shares + 77 + 77 + 79, "\n", 1);
  strncpy(public_shares + 144 + 79, ConvertToString(val2.X.c0).c_str(), 77);
  strncpy(public_shares + 144 + 78, ":", 1);
  strncpy(public_shares + 144 + 77, ConvertToString(val2.X.c1).c_str(), 77);*/



  return (val == sshare * libff::alt_bn128_G2::one());

}

void calc_bls_public_key(char* skey, char* pub_key){
  libff::alt_bn128_Fr bls_skey(skey);

  libff::alt_bn128_G2 public_key = bls_skey * libff::alt_bn128_G2::one();
  public_key.to_affine_coordinates();

  std::string result = ConvertG2ToString(public_key);

  strncpy(pub_key, result.c_str(), result.length());
}




