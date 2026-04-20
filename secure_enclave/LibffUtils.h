#ifndef LIBFFUTILS_H
#define LIBFFUTILS_H

#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <../SCIPR/libff/algebra/fields/fp.hpp>

#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>

bool isG2(const libff::alt_bn128_G2 &point);

#endif