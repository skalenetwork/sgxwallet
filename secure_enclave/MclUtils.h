#ifndef MCL_UTILS_H
#define MCL_UTILS_H

// SGX Configuration for MCL
#define MCL_DONT_USE_XBYAK 1

#define MCL_STANDALONE 1
#if !defined(MCL_SIZEOF_UNIT)
#define MCL_SIZEOF_UNIT 8
#endif
#if !defined(MCL_FP_BIT)
#define MCL_FP_BIT 256
#endif
#if !defined(MCL_FR_BIT)
#define MCL_FR_BIT 256
#endif

#include <string>
#include <vector>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wconversion"
#include <mcl/bn.hpp>
#pragma GCC diagnostic pop

// Namespace aliases for easier migration
using Fr = mcl::bn::Fr;
using Fp = mcl::bn::Fp;
using Fp2 = mcl::bn::Fp2;
using G1 = mcl::bn::G1;
using G2 = mcl::bn::G2;

// Helper functions
bool isG2(const G2 &point);

// Exponentiation helper
Fr power(const Fr &base, long exp);

// Generate random Fr element using SGX's hardware RNG directly
// (bypasses MCL's RandGen which has static initialization issues in SGX)
void setRandomFr(Fr &fr);

// Initialization wrapper
void initMcl();

#endif // MCL_UTILS_H
