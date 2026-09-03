/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#include "tests/TestSupport.h"

#include <ctime>
#include <gmp.h>

using namespace std;

default_random_engine TestSupport::randGen((unsigned int)time(0));

string TestSupport::stringFromFr(libBLS::algebra::FrScalar &el,
                                 libBLS::algebra::Base base) {
  return el.toString(base);
}

string TestSupport::convertDecToHex(const string &dec, int numBytes) {
  mpz_t num;
  mpz_init(num);
  mpz_set_str(num, dec.c_str(), 10);
  vector<char> tmp(mpz_sizeinbase(num, 16) + 2, 0);
  char *hex = mpz_get_str(tmp.data(), 16, num);
  string result = hex;
  int n_zeroes = numBytes * 2 - result.length();
  result.insert(0, n_zeroes, '0');
  mpz_clear(num);
  return result;
}

vector<libBLS::algebra::FrScalar>
TestSupport::splitStringToFr(const char *coeffs, const char symbol) {
  string str(coeffs);
  string delim;
  delim.push_back(symbol);
  vector<libBLS::algebra::FrScalar> tokens;
  size_t prev = 0, pos = 0;
  do {
    pos = str.find(delim, prev);
    if (pos == string::npos)
      pos = str.length();
    string token = str.substr(prev, pos - prev);
    if (!token.empty()) {
      libBLS::algebra::FrScalar coeff(libBLS::algebra::FrScalar::fromString(
          token, libBLS::algebra::Base::DEC));
      tokens.push_back(coeff);
    }
    prev = pos + delim.length();
  } while (pos < str.length() && prev < str.length());

  return tokens;
}

libBLS::algebra::G2Point
TestSupport::vectStringToG2(const vector<string> &G2_str_vect) {
  libBLS::algebra::G2Point coeff = libBLS::algebra::G2Point::identity();
  coeff.setZC0(libBLS::algebra::FqElement::one());
  coeff.setZC1(libBLS::algebra::FqElement::zero());

  coeff.setXC0(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(0), libBLS::algebra::Base::DEC));
  coeff.setXC1(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(1), libBLS::algebra::Base::DEC));
  coeff.setYC0(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(2), libBLS::algebra::Base::DEC));
  coeff.setYC1(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(3), libBLS::algebra::Base::DEC));

  return coeff;
}
