/** @file
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <../SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_init.hpp>

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
    alt_bn128_Fr::num_bits = 254;
    alt_bn128_Fr::euler = bigint_r("10944121435919637611123202872628637544274182200208017171849102093287904247808");
    alt_bn128_Fr::s = 28;
    alt_bn128_Fr::t = bigint_r("81540058820840996586704275553141814055101440848469862132140264610111");
    alt_bn128_Fr::t_minus_1_over_2 = bigint_r("40770029410420498293352137776570907027550720424234931066070132305055");
    alt_bn128_Fr::multiplicative_generator = alt_bn128_Fr("5");
    alt_bn128_Fr::root_of_unity = alt_bn128_Fr("19103219067921713944291392827692070036145651957329286315305642004821462161904");
    alt_bn128_Fr::nqr = alt_bn128_Fr("5");
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
    alt_bn128_G1::wnaf_window_table.resize(0);
    alt_bn128_G1::wnaf_window_table.push_back(11);
    alt_bn128_G1::wnaf_window_table.push_back(24);
    alt_bn128_G1::wnaf_window_table.push_back(60);
    alt_bn128_G1::wnaf_window_table.push_back(127);

    alt_bn128_G1::fixed_base_exp_window_table.resize(0);
    // window 1 is unbeaten in [-inf, 4.99]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(1);
    // window 2 is unbeaten in [4.99, 10.99]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(5);
    // window 3 is unbeaten in [10.99, 32.29]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(11);
    // window 4 is unbeaten in [32.29, 55.23]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(32);
    // window 5 is unbeaten in [55.23, 162.03]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(55);
    // window 6 is unbeaten in [162.03, 360.15]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(162);
    // window 7 is unbeaten in [360.15, 815.44]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(360);
    // window 8 is unbeaten in [815.44, 2373.07]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(815);
    // window 9 is unbeaten in [2373.07, 6977.75]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(2373);
    // window 10 is unbeaten in [6977.75, 7122.23]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(6978);
    // window 11 is unbeaten in [7122.23, 57818.46]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(7122);
    // window 12 is never the best
    alt_bn128_G1::fixed_base_exp_window_table.push_back(0);
    // window 13 is unbeaten in [57818.46, 169679.14]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(57818);
    // window 14 is never the best
    alt_bn128_G1::fixed_base_exp_window_table.push_back(0);
    // window 15 is unbeaten in [169679.14, 439758.91]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(169679);
    // window 16 is unbeaten in [439758.91, 936073.41]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(439759);
    // window 17 is unbeaten in [936073.41, 4666554.74]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(936073);
    // window 18 is never the best
    alt_bn128_G1::fixed_base_exp_window_table.push_back(0);
    // window 19 is unbeaten in [4666554.74, 7580404.42]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(4666555);
    // window 20 is unbeaten in [7580404.42, 34552892.20]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(7580404);
    // window 21 is never the best
    alt_bn128_G1::fixed_base_exp_window_table.push_back(0);
    // window 22 is unbeaten in [34552892.20, inf]
    alt_bn128_G1::fixed_base_exp_window_table.push_back(34552892);

    alt_bn128_G2::G2_zero = alt_bn128_G2(alt_bn128_Fq2::zero(),
                                         alt_bn128_Fq2::one(),
                                         alt_bn128_Fq2::zero());

    alt_bn128_G2::G2_one = alt_bn128_G2(alt_bn128_Fq2(alt_bn128_Fq("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                                                      alt_bn128_Fq("11559732032986387107991004021392285783925812861821192530917403151452391805634")),
                                        alt_bn128_Fq2(alt_bn128_Fq("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                                                      alt_bn128_Fq("4082367875863433681332203403145435568316851327593401208105741076214120093531")),
                                        alt_bn128_Fq2::one());


    /* pairing parameters */

    alt_bn128_ate_loop_count = bigint_q("29793968203157093288");
    alt_bn128_ate_is_loop_count_neg = false;
    alt_bn128_final_exponent = bigint<12*alt_bn128_q_limbs>("552484233613224096312617126783173147097382103762957654188882734314196910839907541213974502761540629817009608548654680343627701153829446747810907373256841551006201639677726139946029199968412598804882391702273019083653272047566316584365559776493027495458238373902875937659943504873220554161550525926302303331747463515644711876653177129578303191095900909191624817826566688241804408081892785725967931714097716709526092261278071952560171111444072049229123565057483750161460024353346284167282452756217662335528813519139808291170539072125381230815729071544861602750936964829313608137325426383735122175229541155376346436093930287402089517426973178917569713384748081827255472576937471496195752727188261435633271238710131736096299798168852925540549342330775279877006784354801422249722573783561685179618816480037695005515426162362431072245638324744480");
    alt_bn128_final_exponent_z = bigint_q("4965661367192848881");
    alt_bn128_final_exponent_is_z_neg = false;

}
} // libff
