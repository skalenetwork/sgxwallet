//
// Created by kladko on 11/19/19.
//

#include <vector>
#include "ServerDataChecker.h"
#include <gmp.h>

#include <iostream>

std::vector<std::string> SplitString(const std::string& str, const std::string& delim = ":"){
    std::vector<std::string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return tokens;
}

bool checkECDSAKeyName(const std::string& keyName) {
  std::vector<std::string> parts = SplitString(keyName);
  if (parts.size() != 2) {
    std::cerr << "num parts != 2" << std::endl;
    return false;
  }
  if (parts.at(0) != "NEK") {
      std::cerr << "key doesn't start from NEK" << std::endl;
      return false;
  }
  if ( parts.at(1).length() > 64 || parts.at(1).length() < 1){
      std::cerr << "wrong key length" << std::endl;
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

bool checkHex(const std::string& hex, const uint32_t sizeInBytes){
  if ( hex.length() > sizeInBytes * 2 || hex.length() == 0){
    return false;
  }

  mpz_t num;
  mpz_init(num);

  if ( mpz_set_str(num, hex.c_str(), 16) == -1){
    mpz_clear(num);
    return false;
  }
  mpz_clear(num);

  return true;
}

bool checkName (const std::string& Name, const std::string& prefix){
    std::vector<std::string> parts = SplitString(Name);
    if ( parts.size() != 7) {
        std::cerr << "parts.size() != 7" << std::endl;
        return false;
    }
    if ( parts.at(0) != prefix ) {
        std::cerr << "parts.at(0) != prefix" << std::endl;
        return false;
    }
    if ( parts.at(1) != "SCHAIN_ID"){
        std::cerr << "parts.at(1) != SCHAIN_ID" << std::endl;
        return false;
    }
    if ( parts.at(3) != "NODE_ID"){
        std::cerr << "parts.at(3) != Node_ID" << std::endl;
        return false;
    }
    if ( parts.at(5) != "DKG_ID"){
        std::cerr << "parts.at(1) != DKG_ID" << std::endl;
        return false;
    }

    if ( parts.at(2).length() > 78 || parts.at(2).length() < 1){
        std::cerr << "parts.at(2).length() > 78" << std::endl;
        return false;
    }
    if (parts.at(4).length() > 5 || parts.at(4).length() < 1){
        std::cerr << "parts.at(4).length() > 5" << std::endl;
        return false;
    }
    if ( parts.at(6).length() > 78 || parts.at(6).length() < 1){
        std::cerr << "parts.at(6).length() > 78" << std::endl;
        return false;
    }

    mpz_t num;
    mpz_init(num);

    if ( mpz_set_str(num, parts.at(2).c_str(), 10) == -1){
        mpz_clear(num);
        std::cerr << "parts.at(2) not num" << std::endl;
        return false;
    }
    mpz_clear(num);
    mpz_init(num);

    if ( mpz_set_str(num, parts.at(4).c_str(), 10) == -1){
        mpz_clear(num);
        std::cerr << "parts.at(4) not num" << std::endl;
        return false;
    }
    mpz_clear(num);
    mpz_init(num);

    if ( mpz_set_str(num, parts.at(6).c_str(),10) == -1){
        mpz_clear(num);
        std::cerr << "parts.at(6) not num" << std::endl;
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

  if ( t < 0 || n < 0){
    return false;
  }

  return true;
}