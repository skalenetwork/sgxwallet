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

    @file numbertheory.c
    @author Stan Kladko
    @date 2019
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef USER_SPACE
#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#include "NumberTheory.h"

/*Calculate R = a^k mod P, using repeated square-and-multiply algorithm
 *Handbook of applied cryptography: Algorithm 2.143. */
void number_theory_exp_modp(mpz_t R, mpz_t a, mpz_t k, mpz_t P)
{
	mpz_powm(R, a, k, P);
}

/*Calculate R = a^k mod P, wraps around number_theory_exp_modp() */
void number_theory_exp_modp_ui(mpz_t R, mpz_t a, unsigned long int k, mpz_t P)
{
	mpz_powm_ui(R, a, k, P);
}

/*Calculate the multiplicative inverse of a mod p, using the extended euclidean algorithm
 *http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm*/
void number_theory_inverse(mpz_t R, mpz_t A, mpz_t P)
{
	mpz_invert(R, A, P);
}

/*Calculates the legendre symbol of a and p
 *Handbook of applied cryptography: Fact 2.146 */
int number_theory_legendre(mpz_t a, mpz_t p)
{

	return mpz_legendre(a, p);
}

