#include "hex_utils.h"
#include <gmp.h>
#include <vector>

std::string convertDecToHex(const std::string &dec, int numBytes) {
  mpz_t num;
  mpz_init(num);
  mpz_set_str(num, dec.c_str(), 10);
  std::vector<char> tmp(mpz_sizeinbase(num, 16) + 2, 0);
  char *hex = mpz_get_str(tmp.data(), 16, num);
  std::string result = hex;
  int n_zeroes = numBytes * 2 - result.length();
  result.insert(0, n_zeroes, '0');
  mpz_clear(num);
  return result;
}
