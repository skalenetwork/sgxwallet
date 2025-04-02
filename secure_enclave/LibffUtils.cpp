#include "LibffUtils.h"


bool isG2(const libff::alt_bn128_G2 &point) {
    return !point.is_zero() && point.is_well_formed() &&
           libff::alt_bn128_G2::order() * point == libff::alt_bn128_G2::zero();
  }