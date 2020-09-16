/** @file
*****************************************************************************
* @author     This file is part of libff, developed by SCIPR Lab
*             and contributors (see AUTHORS).
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef ALT_BN128_PP_HPP_
#define ALT_BN128_PP_HPP_
#include "alt_bn128_g1.hpp"
#include "alt_bn128_init.hpp"
#include "../public_params.hpp"

namespace libff {

class alt_bn128_pp {
public:
    typedef alt_bn128_Fr Fp_type;
    typedef alt_bn128_G1 G1_type;
    typedef alt_bn128_G2 G2_type;
        typedef alt_bn128_Fq Fq_type;

    static const bool has_affine_pairing = false;

    static void init_public_params();

};

} // libff

#endif // ALT_BN128_PP_HPP_
