/** @file
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <../trusted_libff/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libff {

void alt_bn128_pp::init_public_params()
{
    init_alt_bn128_params();
}


alt_bn128_G1_precomp alt_bn128_pp::precompute_G1(const alt_bn128_G1 &P)
{
    return alt_bn128_precompute_G1(P);
}

alt_bn128_G2_precomp alt_bn128_pp::precompute_G2(const alt_bn128_G2 &Q)
{
    return alt_bn128_precompute_G2(Q);
}


} // libff
