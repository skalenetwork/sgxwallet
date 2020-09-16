/** @file
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include "alt_bn128_g1.hpp"
#include "alt_bn128_g2.hpp"
#include "alt_bn128_init.hpp"

#include "../../../../secure_enclave/EnclaveCommon.h"

namespace libff {

bigint<alt_bn128_r_limbs> alt_bn128_modulus_r;
bigint<alt_bn128_q_limbs> alt_bn128_modulus_q;

alt_bn128_Fq alt_bn128_coeff_b;
alt_bn128_Fq2 alt_bn128_twist;
alt_bn128_Fq2 alt_bn128_twist_coeff_b;
alt_bn128_Fq alt_bn128_twist_mul_by_b_c0;
alt_bn128_Fq alt_bn128_twist_mul_by_b_c1;
alt_bn128_Fq2 alt_bn128_twist_mul_by_q_X;
alt_bn128_Fq2 alt_bn128_twist_mul_by_q_Y;

bigint<alt_bn128_q_limbs> alt_bn128_ate_loop_count;
bool alt_bn128_ate_is_loop_count_neg;
bigint<12*alt_bn128_q_limbs> alt_bn128_final_exponent;
bigint<alt_bn128_q_limbs> alt_bn128_final_exponent_z;
bool alt_bn128_final_exponent_is_z_neg;

void init_alt_bn128_params()
{
    typedef bigint<alt_bn128_r_limbs> bigint_r;
    typedef bigint<alt_bn128_q_limbs> bigint_q;

    assert(sizeof(mp_limb_t) == 8 || sizeof(mp_limb_t) == 4); // Montgomery assumes this

    /* parameters for scalar field Fr */

    alt_bn128_modulus_r = bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    assert(alt_bn128_Fr::modulus_is_valid());
    if (sizeof(mp_limb_t) == 8)
    {
        alt_bn128_Fr::Rsquared = bigint_r("944936681149208446651664254269745548490766851729442924617792859073125903783");
        alt_bn128_Fr::Rcubed = bigint_r("5866548545943845227489894872040244720403868105578784105281690076696998248512");
        alt_bn128_Fr::inv = 0xc2e1f593efffffff;
    }
    if (sizeof(mp_limb_t) == 4)
    {
        alt_bn128_Fr::Rsquared = bigint_r("944936681149208446651664254269745548490766851729442924617792859073125903783");
        alt_bn128_Fr::Rcubed = bigint_r("5866548545943845227489894872040244720403868105578784105281690076696998248512");
        alt_bn128_Fr::inv = 0xefffffff;
    }
    LOG_INFO("HERE1\n");
    alt_bn128_Fr::num_bits = 254;
    LOG_INFO("HERE2\n");
    alt_bn128_Fr::euler = bigint_r("10944121435919637611123202872628637544274182200208017171849102093287904247808");
    alt_bn128_Fr::s = 28;
    LOG_INFO("HERE3\n");
    alt_bn128_Fr::t = bigint_r("81540058820840996586704275553141814055101440848469862132140264610111");
    LOG_INFO("HERE4\n");
    alt_bn128_Fr::t_minus_1_over_2 = bigint_r("40770029410420498293352137776570907027550720424234931066070132305055");
    LOG_INFO("HERE5\n");
    alt_bn128_Fr::multiplicative_generator = alt_bn128_Fr("5");
    LOG_INFO("HERE6\n");
    alt_bn128_Fr::root_of_unity = alt_bn128_Fr("19103219067921713944291392827692070036145651957329286315305642004821462161904");
    LOG_INFO("HERE7\n");
    alt_bn128_Fr::nqr = alt_bn128_Fr("5");
    LOG_INFO("HERE8\n");
    alt_bn128_Fr::nqr_to_t = alt_bn128_Fr("19103219067921713944291392827692070036145651957329286315305642004821462161904");

    /* parameters for base field Fq */

    alt_bn128_modulus_q = bigint_q("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    assert(alt_bn128_Fq::modulus_is_valid());
    if (sizeof(mp_limb_t) == 8)
    {
        alt_bn128_Fq::Rsquared = bigint_q("3096616502983703923843567936837374451735540968419076528771170197431451843209");
        alt_bn128_Fq::Rcubed = bigint_q("14921786541159648185948152738563080959093619838510245177710943249661917737183");
        alt_bn128_Fq::inv = 0x87d20782e4866389;
    }
    if (sizeof(mp_limb_t) == 4)
    {
        alt_bn128_Fq::Rsquared = bigint_q("3096616502983703923843567936837374451735540968419076528771170197431451843209");
        alt_bn128_Fq::Rcubed = bigint_q("14921786541159648185948152738563080959093619838510245177710943249661917737183");
        alt_bn128_Fq::inv = 0xe4866389;
    }
    alt_bn128_Fq::num_bits = 254;
    alt_bn128_Fq::euler = bigint_q("10944121435919637611123202872628637544348155578648911831344518947322613104291");
    alt_bn128_Fq::s = 1;
    alt_bn128_Fq::t = bigint_q("10944121435919637611123202872628637544348155578648911831344518947322613104291");
    alt_bn128_Fq::t_minus_1_over_2 = bigint_q("5472060717959818805561601436314318772174077789324455915672259473661306552145");
    alt_bn128_Fq::multiplicative_generator = alt_bn128_Fq("3");
    alt_bn128_Fq::root_of_unity = alt_bn128_Fq("21888242871839275222246405745257275088696311157297823662689037894645226208582");
    alt_bn128_Fq::nqr = alt_bn128_Fq("3");
    alt_bn128_Fq::nqr_to_t = alt_bn128_Fq("21888242871839275222246405745257275088696311157297823662689037894645226208582");

    /* parameters for twist field Fq2 */
    alt_bn128_Fq2::euler = bigint<2*alt_bn128_q_limbs>("239547588008311421220994022608339370399626158265550411218223901127035046843189118723920525909718935985594116157406550130918127817069793474323196511433944");
    alt_bn128_Fq2::s = 4;
    alt_bn128_Fq2::t = bigint<2*alt_bn128_q_limbs>("29943448501038927652624252826042421299953269783193801402277987640879380855398639840490065738714866998199264519675818766364765977133724184290399563929243");
    alt_bn128_Fq2::t_minus_1_over_2 = bigint<2*alt_bn128_q_limbs>("14971724250519463826312126413021210649976634891596900701138993820439690427699319920245032869357433499099632259837909383182382988566862092145199781964621");
    alt_bn128_Fq2::non_residue = alt_bn128_Fq("21888242871839275222246405745257275088696311157297823662689037894645226208582");
    alt_bn128_Fq2::nqr = alt_bn128_Fq2(alt_bn128_Fq("2"),alt_bn128_Fq("1"));
    alt_bn128_Fq2::nqr_to_t = alt_bn128_Fq2(alt_bn128_Fq("5033503716262624267312492558379982687175200734934877598599011485707452665730"),alt_bn128_Fq("314498342015008975724433667930697407966947188435857772134235984660852259084"));
    alt_bn128_Fq2::Frobenius_coeffs_c1[0] = alt_bn128_Fq("1");
    alt_bn128_Fq2::Frobenius_coeffs_c1[1] = alt_bn128_Fq("21888242871839275222246405745257275088696311157297823662689037894645226208582");

    /* choice of short Weierstrass curve and its twist */

    alt_bn128_coeff_b = alt_bn128_Fq("3");
    alt_bn128_twist = alt_bn128_Fq2(alt_bn128_Fq("9"), alt_bn128_Fq("1"));
    alt_bn128_twist_coeff_b = alt_bn128_coeff_b * alt_bn128_twist.inverse();
    alt_bn128_twist_mul_by_b_c0 = alt_bn128_coeff_b * alt_bn128_Fq2::non_residue;
    alt_bn128_twist_mul_by_b_c1 = alt_bn128_coeff_b * alt_bn128_Fq2::non_residue;

    /* choice of group G1 */
    alt_bn128_G1::G1_zero = alt_bn128_G1(alt_bn128_Fq::zero(),
                                     alt_bn128_Fq::one(),
                                     alt_bn128_Fq::zero());
    alt_bn128_G1::G1_one = alt_bn128_G1(alt_bn128_Fq("1"),
                                    alt_bn128_Fq("2"),
                                    alt_bn128_Fq::one());

    alt_bn128_G2::G2_zero = alt_bn128_G2(alt_bn128_Fq2::zero(),
                                         alt_bn128_Fq2::one(),
                                         alt_bn128_Fq2::zero());

    alt_bn128_G2::G2_one = alt_bn128_G2(alt_bn128_Fq2(alt_bn128_Fq("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                                                      alt_bn128_Fq("11559732032986387107991004021392285783925812861821192530917403151452391805634")),
                                        alt_bn128_Fq2(alt_bn128_Fq("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                                                      alt_bn128_Fq("4082367875863433681332203403145435568316851327593401208105741076214120093531")),
                                        alt_bn128_Fq2::one());

}
} // libff
