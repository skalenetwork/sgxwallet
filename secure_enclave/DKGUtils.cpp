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
#include <sgx_tgmp.h>
#endif

#include "DHDkg.h"
#include "EnclaveCommon.h"
#include "EnclaveConstants.h"
#include "MclUtils.h"
#include <cstdio>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

// --- Helper Constants for Generator ---
static const char *G2_X0_DEC = "10857046999023057135944570762232829481370756359"
                               "578518086990519993285655852781";
static const char *G2_X1_DEC = "11559732032986387107991004021392285783925812861"
                               "821192530917403151452391805634";
static const char *G2_Y0_DEC = "84956539231234314176049732474892724384181905872"
                               "63600148770280649306958101930";
static const char *G2_Y1_DEC = "40823678758634336813322034031454355683168513275"
                               "93401208105741076214120093531";

// Alt-Bn128 (BN254) Fr field order (used by MCL with BN_SNARK1 curve)
static const char *ALT_BN128_R_DEC = "21888242871839275222246405745257275088548"
                                     "364400416034343698204186575808495617";

G2 getG2Generator() {
  G2 P;
  bool b = false;
  P.x.a.setStr(&b, G2_X0_DEC, 10);
  P.x.b.setStr(&b, G2_X1_DEC, 10);
  P.y.a.setStr(&b, G2_Y0_DEC, 10);
  P.y.b.setStr(&b, G2_Y1_DEC, 10);
  P.z.clear();
  P.z.a = 1;
  if (!b)
    LOG_ERROR("Failed to init G2 generator");
  return P;
}

/// Reduces a string representing an integer in the given base mod
/// ALT_BN128_R_DEC and returns the result as a decimal string (similar to
/// libBLS reduce_mod)
string reduce_mod_fr(const char *s, int base) {
  mcl::Vint z;
  bool b = false;
  // Parse the input (arbitrary precision); if it fails, z remains zero
  z.setStr(&b, s, base);

  if (!b) {
    return "";
  }

  mcl::Vint modulus;
  modulus.setStr(&b, ALT_BN128_R_DEC, 10);

  z %= modulus;

  // Return canonical decimal string
  char buf[1024];
  size_t len = z.getStr(buf, sizeof(buf), 10);
  return len ? string(buf) : string("0");
}

/// Helper to set Fr from string with automatic modular reduction if needed
/// Similar to libBLS::trySettingFieldWithString() pattern
/// Returns true on success, false on failure
bool trySettingFrFromString(Fr &fr, const char *str, int base) {
  bool b = false;
  fr.setStr(&b, str, base);

  if (b) {
    return true; // Success - value was in range
  }

  // Value exceeds field order - need to reduce mod r
  // NOTE: libff also reduced these values (through Montgomery arithmetic)
  // We need to ensure this produces the same result as libff
  LOG_INFO(
      "trySettingFrFromString: initial setStr failed, attempting reduction");
  LOG_INFO("reduce_mod_fr: input=");
  LOG_INFO(str);

  string reduced = reduce_mod_fr(str, base);

  if (reduced.empty()) {
    LOG_ERROR("trySettingFrFromString: reduction failed");
    return false;
  }

  LOG_INFO("reduce_mod_fr: output=");
  LOG_INFO(reduced.c_str());

  // Try setting with reduced value (now in decimal)
  b = false;
  fr.setStr(&b, reduced.c_str(), 10);

  return b;
}

string stringFromFr(const Fr &_el) {
  string ret = "";
  try {
    char buf[1024];
    size_t len = _el.getStr(buf, sizeof(buf), 10);
    if (len > 0)
      ret = string(buf);
  } catch (...) {
    LOG_ERROR("stringFromFr failed");
  }
  return ret;
}

// Replicate ConvertToString logic using getStr
template <class T> string ConvertToString(const T &field_elem, int base = 10) {
  string ret;
  try {
    char buf[1024];
    size_t len = field_elem.getStr(buf, sizeof(buf), base);
    if (len > 0)
      ret = string(buf);
  } catch (...) {
    LOG_ERROR("ConvertToString failed");
  }
  return ret;
}

string ConvertG2ToString(const G2 &elem, int base = 10,
                         const string &delim = ":") {
  string result = "";
  try {
    G2 P = elem;
    P.normalize();
    result += ConvertToString(P.x.a, base);
    result += delim;
    result += ConvertToString(P.x.b, base);
    result += delim;
    result += ConvertToString(P.y.a, base);
    result += delim;
    result += ConvertToString(P.y.b, base);
    return result;
  } catch (...) {
    LOG_ERROR("ConvertG2ToString failed");
    return result;
  }
}

// ConvertG1ToString: X:Y
string ConvertG1ToString(const G1 &elem, int base = 10,
                         const string &delim = ":") {
  string result = "";
  try {
    G1 P = elem;
    P.normalize();
    result += ConvertToString(P.x, base);
    result += delim;
    result += ConvertToString(P.y, base);
    return result;
  } catch (...) {
    return result;
  }
}

G1 stringToG1(const char *elem) {
  G1 result;
  result.clear();
  try {
    string str(elem);
    size_t pos = str.find(":");
    if (pos == string::npos)
      return result;
    bool b = false;
    // setStr needs char array, using string substr
    Fp x;
    x.setStr(&b, str.substr(0, pos).c_str(), 10);
    Fp y;
    y.setStr(&b, str.substr(pos + 1).c_str(), 10);
    if (b)
      result.set(&b, x, y);
  } catch (...) {
    LOG_ERROR("stringToG1 failed");
  }
  return result;
}

vector<Fr> SplitStringToFr(const char *coeffs, const char symbol) {
  vector<Fr> result;
  string str(coeffs);
  CHECK_ARG_CLEAN(coeffs);
  try {
    stringstream ss(str);
    string segment;
    while (getline(ss, segment, symbol)) {
      if (segment.empty())
        continue;
      Fr fr;
      bool b = false;
      fr.setStr(&b, segment.c_str(), 10);
      if (b)
        result.push_back(fr);
    }
  } catch (...) {
    LOG_ERROR("SplitStringToFr failed");
  }
clean:
  return result;
}

static int gen_dkg_poly_impl(char *secret, unsigned _t,
                             std::optional<Fr> freeCoefficient) {
  int status = 1;
  string result;
  CHECK_ARG_CLEAN(secret);
  try {
    for (size_t i = 0; i < _t; ++i) {
      Fr cur_coef;
      if (i == 0 && freeCoefficient.has_value()) {
        cur_coef = *freeCoefficient;
      } else {
        do {
          setRandomFr(cur_coef);
        } while (i == _t - 1 && cur_coef.isZero());
      }
      result += stringFromFr(cur_coef);
      result += ":";
    }
    strncpy(secret, result.c_str(), result.length() + 1);
    if (strlen(secret) == 0)
      return status;
    status = 0;
  } catch (...) {
    LOG_ERROR("gen_dkg_poly failed");
  }
clean:
  return status;
}

int gen_dkg_poly(char *secret, unsigned _t) {
  return gen_dkg_poly_impl(secret, _t, std::nullopt);
}

int gen_dkg_poly_with_free_coef(char *secret, unsigned _t,
                                const char *free_coef_hex) {
  if (free_coef_hex == nullptr || free_coef_hex[0] == '\0') {
    return gen_dkg_poly_impl(secret, _t, std::nullopt);
  }
  Fr freeCoef;
  bool b = false;
  freeCoef.setStr(&b, free_coef_hex, 16);
  if (!b) {
    LOG_ERROR("gen_dkg_poly_with_free_coef: failed to parse free_coef_hex");
    return 1;
  }
  return gen_dkg_poly_impl(secret, _t, freeCoef);
}

Fr PolynomialValue(const vector<Fr> &pol, Fr point, unsigned _t) {
  Fr result = 0;
  try {
    Fr pow = 1;
    for (unsigned i = 0; i < pol.size(); ++i) {
      result += pol.at(i) * pow;
      pow *= point;
    }
  } catch (...) {
    LOG_ERROR("PolynomialValue exception");
  }
  return result;
}

void calc_secret_shares(const char *decrypted_coeffs, char *secret_shares,
                        unsigned _t, unsigned _n) {
  string result;
  char symbol = ':';
  CHECK_ARG_CLEAN(decrypted_coeffs);
  CHECK_ARG_CLEAN(secret_shares);
  CHECK_ARG_CLEAN(_n > 0);
  CHECK_ARG_CLEAN(_t <= _n);

  try {
    vector<Fr> poly = SplitStringToFr(decrypted_coeffs, symbol);
    for (size_t i = 0; i < _n; ++i) {
      Fr secret_share = PolynomialValue(poly, Fr(i + 1), _t);
      result += ConvertToString(secret_share);
      result += ":";
    }
    strncpy(secret_shares, result.c_str(), result.length() + 1);
  } catch (...) {
    LOG_ERROR("calc_secret_shares exception");
  }
clean:;
}

int calc_secret_share(const char *decrypted_coeffs, char *s_share, unsigned _t,
                      unsigned _n, unsigned ind) {
  int result = 1;
  CHECK_ARG_CLEAN(decrypted_coeffs);
  CHECK_ARG_CLEAN(s_share);
  try {
    vector<Fr> poly = SplitStringToFr(decrypted_coeffs, ':');
    if (poly.size() != _t)
      return result;
    Fr secret_share = PolynomialValue(poly, Fr(ind), _t);
    // Output base 16, padded to 64 chars
    string cur_share = ConvertToString(secret_share, 16);
    int n_zeroes = 64 - (int)cur_share.size();
    if (n_zeroes > 0)
      cur_share.insert(0, n_zeroes, '0');
    strncpy(s_share, cur_share.c_str(), cur_share.length() + 1);
    result = 0;
  } catch (...) {
    LOG_ERROR("calc_secret_share exception");
  }
clean:
  return result;
}

int calc_secret_shareG2(const char *s_share, char *s_shareG2) {
  int result = 1;
  CHECK_ARG_CLEAN(s_share);
  CHECK_ARG_CLEAN(s_shareG2);
  try {
    Fr secret_share;
    bool b = false;
    secret_share.setStr(&b, s_share, 16);
    if (!b)
      goto clean;

    G2 secret_shareG2;
    G2 generator = getG2Generator();
    G2::mul(secret_shareG2, generator, secret_share);

    string str = ConvertG2ToString(secret_shareG2);
    strncpy(s_shareG2, str.c_str(), str.length() + 1);
    result = 0;
  } catch (...) {
    LOG_ERROR("calc_secret_shareG2 exception");
  }
clean:
  return result;
}

int calc_public_shares(const char *decrypted_coeffs, char *public_shares,
                       unsigned _t) {
  int ret = 1;
  string result;
  CHECK_ARG_CLEAN(decrypted_coeffs);
  CHECK_ARG_CLEAN(public_shares);
  try {
    vector<Fr> poly = SplitStringToFr(decrypted_coeffs, ':');
    if (poly.size() != _t)
      return ret;
    G2 generator = getG2Generator();
    for (size_t i = 0; i < _t; ++i) {
      G2 pub_share;
      G2::mul(pub_share, generator, poly.at(i));
      result += ConvertG2ToString(pub_share) + ",";
    }
    strncpy(public_shares, result.c_str(), result.length());
    ret = 0;
  } catch (...) {
    ret = 2;
  }
clean:
  return ret;
}

int Verification(const char *public_shares, mpz_t decr_secret_share, int _t,
                 int ind) {
  string pub_shares_str = public_shares;
  vector<G2> pub_shares_vec;
  uint64_t share_length = 256;
  uint8_t coord_length = 64;
  int ret = 0;
  CHECK_ARG_CLEAN(public_shares);

  try {
    for (int i = 0; i < _t; i++) {
      uint64_t pos0 = share_length * i;
      if (pos0 + 3 * coord_length >= pub_shares_str.size()) {
        ret = 2;
        return ret;
      }
      string sX0 = pub_shares_str.substr(pos0, coord_length);
      string sX1 = pub_shares_str.substr(pos0 + coord_length, coord_length);
      string sY0 = pub_shares_str.substr(pos0 + 2 * coord_length, coord_length);
      string sY1 = pub_shares_str.substr(pos0 + 3 * coord_length, coord_length);

      G2 pub_share;
      bool b = false;
      pub_share.x.a.setStr(&b, sX0.c_str(), 16);
      pub_share.x.b.setStr(&b, sX1.c_str(), 16);
      pub_share.y.a.setStr(&b, sY0.c_str(), 16);
      pub_share.y.b.setStr(&b, sY1.c_str(), 16);
      pub_share.z.clear();
      pub_share.z.a = 1;

      if (!b || !pub_share.isValid()) {
        ret = 3;
        return ret;
      }
      pub_shares_vec.push_back(pub_share);
    }

    G2 val;
    val.clear();
    for (int i = 0; i < _t; ++i) {
      Fr power_val;
      mcl::bn::Fr::pow(power_val, Fr(ind + 1), i);
      G2 tmp;
      G2::mul(tmp, pub_shares_vec.at(i), power_val);
      val = val + tmp;
    }

    // Handle secret share using mpz for compatibility with argument type
    SAFE_CHAR_BUF(arr, ENCLAVE_BUF_LEN);
    char *tmp = mpz_get_str(arr, 10, decr_secret_share);
    Fr sshare;
    bool b = false;
    sshare.setStr(&b, tmp, 10);

    G2 val2;
    G2 generator = getG2Generator();
    G2::mul(val2, generator, sshare);

    val.normalize();
    val2.normalize();

    ret = (val == val2);

  } catch (...) {
    ret = 0;
  }
clean:
  return ret;
}

int calc_bls_public_key(char *skey_hex, char *pub_key) {
  int ret = 1;
  CHECK_ARG_CLEAN(skey_hex);
  CHECK_ARG_CLEAN(pub_key);
  try {
    Fr bls_skey;

    // Use helper that handles modular reduction if needed
    if (!trySettingFrFromString(bls_skey, skey_hex, 16)) {
      LOG_ERROR("calc_bls_public_key: trySettingFrFromString failed");
      return 1;
    }

    G2 generator = getG2Generator();
    if (!generator.isValid()) {
      LOG_ERROR("calc_bls_public_key: G2 generator invalid!");
      return 1;
    }

    G2 public_key;
    G2::mul(public_key, generator, bls_skey);

    if (!public_key.isValid()) {
      LOG_ERROR("calc_bls_public_key: result public_key invalid!");
      return 1;
    }

    string result = ConvertG2ToString(public_key);
    if (result.empty()) {
      LOG_ERROR("calc_bls_public_key: ConvertG2ToString returned empty");
      return 1;
    }
    strncpy(pub_key, result.c_str(), result.length());
    return 0;
  } catch (...) {
    LOG_ERROR("calc_bls_public_key: caught exception");
    return 1;
  }
clean:
  return ret;
}
