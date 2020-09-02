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

    @file ServerDataChecker.cpp
    @author Stan Kladko
    @date 2019
*/

#include <vector>
#include "ServerDataChecker.h"
#include <gmp.h>

#include <iostream>

#include "third_party/spdlog/spdlog.h"
#include "common.h"

vector<string> SplitString(const string& str, const string& delim = ":"){
    vector<string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return tokens;
}

bool checkECDSAKeyName(const string& keyName) {
  vector<string> parts = SplitString(keyName);
  if (parts.size() != 2) {
    spdlog::info("ECDSAKeyName num parts != 2");
    return false;
  }
  if (parts.at(0) != "NEK") {
      spdlog::info("key doesn't start from NEK");
      return false;
  }
  if ( parts.at(1).length() > 64 || parts.at(1).length() < 1){
      spdlog::info("wrong key length");
      return false;
  }

  mpz_t num;
  mpz_init(num);
  if ( mpz_set_str(num, parts.at(1).c_str(), 16) == -1){
    mpz_clear(num);
    return false;
  }
  mpz_clear(num);

  return true;
}

bool checkHex(const string& hex, const uint32_t sizeInBytes){
  if ( hex.length() > sizeInBytes * 2 || hex.length() == 0){
    spdlog::error("key is too long or zero - ", hex.length());
    return false;
  }

  mpz_t num;
  mpz_init(num);

  if (mpz_set_str(num, hex.c_str(), 16) == -1) {
    spdlog::error("key is not hex {}", hex);
    mpz_clear(num);
    return false;
  }
  mpz_clear(num);

  return true;
}

bool checkName (const string& Name, const string& prefix){
    vector<string> parts = SplitString(Name);
    if ( parts.size() != 7) {
        spdlog::info("parts.size() != 7");
        return false;
    }
    if ( parts.at(0) != prefix ) {
        spdlog::info("parts.at(0) != prefix");
        return false;
    }
    if ( parts.at(1) != "SCHAIN_ID"){
        spdlog::info("parts.at(1) != SCHAIN_ID");
        return false;
    }
    if ( parts.at(3) != "NODE_ID"){
        spdlog::info("parts.at(3) != Node_ID");
        return false;
    }
    if ( parts.at(5) != "DKG_ID"){
        spdlog::info("parts.at(1) != DKG_ID");
        return false;
    }

    if ( parts.at(2).length() > 78 || parts.at(2).length() < 1){
        spdlog::info("parts.at(2).length() > 78");
        return false;
    }
    if (parts.at(4).length() > 5 || parts.at(4).length() < 1){
        spdlog::info("parts.at(4).length() > 5");
        return false;
    }
    if ( parts.at(6).length() > 78 || parts.at(6).length() < 1){
        spdlog::info("parts.at(6).length() > 78");
        return false;
    }

    mpz_t num;
    mpz_init(num);

    if ( mpz_set_str(num, parts.at(2).c_str(), 10) == -1) {
        mpz_clear(num);
        spdlog::info("parts.at(2) is not decimal number");
        return false;
    }
    mpz_clear(num);
    mpz_init(num);

    if ( mpz_set_str(num, parts.at(4).c_str(), 10) == -1){
        mpz_clear(num);
        spdlog::info("parts.at(4) is not decimal number");
        return false;
    }
    mpz_clear(num);
    mpz_init(num);

    if ( mpz_set_str(num, parts.at(6).c_str(),10) == -1){
        mpz_clear(num);
        spdlog::info("parts.at(6) is not decimal number");
        return false;
    }
    mpz_clear(num);

    return true;
}

bool check_n_t ( const int t, const int n){
  if (t > n){
    return false;
  }

  if ( t == 0 || n == 0){
    return false;
  }

  if (n > 32){
    return false;
  }

  if ( t < 0 || n < 0){
    return false;
  }

  return true;
}
