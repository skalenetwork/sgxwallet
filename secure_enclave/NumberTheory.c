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
#include <../tgmp-build/include/sgx_tgmp.h>
#include <stdbool.h>
#include "NumberTheory.h"

/*Calculate R = a^k mod P, using repeated square-and-multiply algorithm
 *Handbook of applied cryptography: Algorithm 2.143. */
void number_theory_exp_modp(mpz_t R, mpz_t a, mpz_t k, mpz_t P)
{
#if EXTERNAL_NUMBER_THEORY_IMPLEMENTATION
	//Do this using gmp number theory implementation
	mpz_powm(R, a, k, P);
#else
	//Variable A and b 
	mpz_t A;mpz_init(A);
	mpz_t b;mpz_init(b);
	int i; //Illiterator
	int t = mpz_sizeinbase(k, 2); //Set t = bit length

	//Temporary variables
	mpz_t t1; mpz_init(t1);
	mpz_t t2; mpz_init(t2);

	//Set b = 1
	mpz_set_ui(b, 1);
	
	//If k = 0, return b; if not run through the bit loop
	if(mpz_sgn(k))
	{
		//Set A = a
		mpz_set(A, a);

		//If k_0 = 1
		if(mpz_tstbit(k,0))
			mpz_set(b,a);

		for(i = 1; i < t; i++)
		{
			//Set A = A² mod P
			mpz_set(t1, A);
			mpz_mul(t2, t1, A);
			mpz_mod(A, t2, P);

			//If k_i = 1
			if(mpz_tstbit(k,i))
			{
				//Set b = A * b mod P
				mpz_mul(t1, A, b);
				mpz_mod(b, t1, P);
			}
		}
	}
	//Return b
	mpz_set(R, b);

	//Clear variables
	mpz_clear(A);
	mpz_clear(b);
	mpz_clear(t1);	
	mpz_clear(t2);
#endif
}

/*Calculate R = a^k mod P, wraps around number_theory_exp_modp() */
void number_theory_exp_modp_ui(mpz_t R, mpz_t a, unsigned long int k, mpz_t P)
{
#if EXTERNAL_NUMBER_THEORY_IMPLEMENTATION
	//Do this using gmp number theory implementation
	mpz_powm_ui(R, a, k, P);
#else
	mpz_t K;

	//Initialize and set a once
	mpz_init_set_ui(K, k);

	//Calculate exponentiation
	number_theory_exp_modp(R, a, K, P);

	//Release memory
	mpz_clear(K);
#endif
}

/*Calculates R² mod P = a, the squareroot of a mod P
 *Handbook of applied cryptography: Algorithm 3.36, 3.37 and 3.34 */
void number_theory_squareroot_modp(mpz_t R, mpz_t a, mpz_t P)
{
	//Calculate the legendre symbol
	int legendre = number_theory_legendre(a, P);

	//Initialize temporary variables
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);
	mpz_t t3;mpz_init(t3);
	mpz_t t4;mpz_init(t4);
	mpz_t t5;mpz_init(t5);

	//Is a a quadratic nonresidue?
	if(legendre == -1)
	{
		//Set R = 0
		mpz_set_ui(R, 0);
	}else{
		//If P mod 4 = 3
		mpz_mod_ui(t1, P, 4);
		if(mpz_cmp_ui(t1, 3) == 0)	//Algorithm 3.36, a specialization of algorithm 3.34
		{
			//Calculate R = a^((P+1)/4)
			mpz_add_ui(t1, P, 1);	//t1 = P - 1
			mpz_divexact_ui(t3, t1, 4);//t3 = t1 / 4
			number_theory_exp_modp(R, a, t3, P); //R = a^t3 mod P
		}else{						//Algorithm 3.37, a specialization of algorithm 3.34
			//If P mod 8 = 5
			mpz_mod_ui(t1, P, 8);
			if(mpz_cmp_ui(t1, 5) == 0)
			{
				//Initialize d
				mpz_t d;mpz_init(d);

				//Calculate d = a^((P-1)/4)
				mpz_sub_ui(t1, P, 1);	//t1 = P - 1
				mpz_divexact_ui(t3, t1, 4);//t3 = t1 / 4
				number_theory_exp_modp(d, a, t3, P); //d = a^t3 mod P
				//If d = 1
				if(mpz_cmp_ui(d, 1) == 0)
				{
					//Calculate R = a^((P+3)/8)
					mpz_add_ui(t1, P, 3);	//t1 = P - 3
					mpz_divexact_ui(t3, t1, 8);//t3 = t1 / 8
					number_theory_exp_modp(R, a, t3, P); //R = a^t3 mod P
				}else{
					//If d = P - 1
					mpz_sub_ui(t1, P, 1);
					if(mpz_cmp(d, t1) == 0){
						//Calculate R = 2a*(4a)^((P-5)/8)
						mpz_mul_ui(t1, a, 4);	//t1 = 4*a
						mpz_mod(t4, t1, P);		//t4 = t1 mod P
						mpz_sub_ui(t1, P, 5);	//t1 = P - 5
						mpz_divexact_ui(t3, t1, 8);//t3 = t1 / 8
						number_theory_exp_modp(t1, t4, t3, P); //t1 = (t4)^t3 mod P
						mpz_mul_ui(t2, a, 2);	//t2 = 2*a
						mpz_mod(t3, t2, P);		//t3 = t2 mod P
						mpz_mul(t2, t1, t3);	//t2 = t1*t2
						mpz_mod(R, t2, P);		//R = t2 mod P
					}
				}

				//Clear d
				mpz_clear(d);
			}else{					//Algorithm 3.34
				//Select b random quadratic nonresidue
				mpz_t b; mpz_init(b);
				gmp_randstate_t rstate; //Initialize random algorithm
				gmp_randinit_default(rstate);
				do
					mpz_urandomm(b, rstate, P);
				while(number_theory_legendre(b, P) != -1);
				gmp_randclear(rstate);

				//Find s and t, such as p-1 = 2^s*t, where t is odd
				mpz_sub_ui(t1, P, 1);	//t1 = p-1
				unsigned long int s = mpz_scan1(t1, 0);
				/* Scans the binary representation of t1 for 1 from behind, this gives us the
				 * number of times t1 can be devided with 2 before it gives an odd. This bit
				 * manipulation ought to be faster than repeated division by 2.
				 * Example:
				 * prime = 113		binary = 1110001 
				 * prime - 1 = 112	binary = 1110000
				 * 112 / 2^4 = 7, 7 is odd.
				 */
				mpz_ui_pow_ui(t2, 2, s);//t2 = 2^s
				mpz_t t; mpz_init(t);
				mpz_divexact(t, t1, t2);//t = t1 / t2
				
				//Computation of a^-1 mod p
				mpz_t a_inv; mpz_init(a_inv);
				number_theory_inverse(a_inv, a, P);

				//Initialize variable for c and d
				mpz_t c;mpz_init(c);
				mpz_t d;mpz_init(d);

				//Set c = b^t mod p
				number_theory_exp_modp(c, b, t, P);

				//Set R = a^((t+1)/2) mod p
				mpz_add_ui(t1, t, 1);					//t1 = t+1
				mpz_divexact_ui(t2, t1, 2);				//t2 = t1 / 2
				number_theory_exp_modp(R , a, t2, P);	//R = a^t2 mod p

				unsigned long int i;
				for(i = 1; i < s; i++)
				{
					//Set d = (R²*a_inv)^(2^(s-i-1)) mod p
					number_theory_exp_modp_ui(t1, R, 2, P);	//t1 = R²
					mpz_mul(t2, t1, a_inv);		//t2 = t1 * a_inv
					mpz_mod(t5, t2, P);			//t5 = t2 mod p
					mpz_set_ui(t1, s-i-1);	 	//t1 = s-i-1
					mpz_set_ui(t2, 2); 			//t2 = 2
					number_theory_exp_modp(t3, t2, t1, P);	//t3 = t2^t1 mod p
					number_theory_exp_modp(d , t5, t3, P);	//d = t5^t3 mod p

					//If d-(-1) mod p == 0, since d<p then we can use P-1 == d instead
					mpz_sub_ui(t1, P, 1);
					if(mpz_cmp(d, t1) == 0)
					{
						//Set R = R*c mod p
						mpz_mul(t1, R, c);	//t1 = R*c
						mpz_mod(R, t1, P);	//R = t1 mod p
					}

					//Set c = c² mod p
					number_theory_exp_modp_ui(t1, c, 2, P);	//t1 = c² mod p
					mpz_set(c, t1);				//c = t1
				}

				//Clear variables
				mpz_clear(b);
				mpz_clear(t);
				mpz_clear(a_inv);
				mpz_clear(c);
				mpz_clear(d);
			}
		}
	}

	//TODO: implement algorithm 3.39
/*Algorithm 3.39 requires operations on the polynomial field Fx over F, and polynomial exponentiation, thus polynomial multiplication and reduction. According to Handbook of applied cryptography this algorithm should be faster than 3.34, when s in p-1 = 2^s*t, where t is odd, is large. But I've decided to settle with the two specializations of 3.34 and algorithm 3.34.*/

	//Clear variables
	mpz_clear(t1);
	mpz_clear(t2);
	mpz_clear(t3);
	mpz_clear(t4);
	mpz_clear(t5);
}

/*Calculate the multiplicative inverse of a mod p, using the extended euclidean algorithm
 *Handbook of applied cryptography: Algorithm 2.107
 *http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm*/
void number_theory_inverse(mpz_t R, mpz_t A, mpz_t P)
{
#if EXTERNAL_NUMBER_THEORY_IMPLEMENTATION
	//Do this using gmp number theory implementation
	mpz_invert(R, A, P);
#else
	//Initialize variables
	mpz_t a;mpz_init(a);
	mpz_t b;mpz_init(b);
	mpz_t q;mpz_init(q);
	mpz_t r;mpz_init(r);
	mpz_t x;mpz_init(x);
	mpz_t lastx;mpz_init(lastx);
	mpz_t y;mpz_init(y);
	mpz_t lasty;mpz_init(lasty);
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);

	//Copy b, since we don't want to alter P or A
	mpz_set(b, P);
	mpz_set(a, A);

	//Set variables
	mpz_set_ui(x, 0);
	mpz_set_ui(y, 1);
	mpz_set_ui(lastx, 1);
	mpz_set_ui(lasty, 0);

	//while b != 0
	while(mpz_sgn(b) != 0)
	{
		//r = a mod b;
		mpz_mod(r, a, b);

		//q = (a - r)/b
		mpz_sub(t1, a, r);
		mpz_divexact(q,t1,b);

		//Set a = b
		mpz_set(a, b);

		//temp := x
		//x := lastx-quotient*x
		//lastx := temp
		mpz_set(t1, x);
		mpz_mul(t2, q, x);
		mpz_sub(x, lastx, t2);
		mpz_mod(lastx, t1, P);//We must keep it mod p, so why not just do it where instead of using set

		//temp := y
		//y := lasty-quotient*y
		//lasty := temp
		mpz_set(t1, y);
		mpz_mul(t2, q, y);
		mpz_sub(y, lasty, t2);
		mpz_mod(lasty, t1, P);//We must keep it mod p, so why not just do it where instead of using set

		//Set b = r
		mpz_set(b, r);	
	}
	/*d = a, greatest common divisitor
	 *lastx = x
	 *lasty = y
	 *in d = a*x+b*y
	 *Thus x is the multiplicative inverse of a mod b
	 *if d = 1, since otherwise there's no mulitplicative inverse.
	 *But when b is a prime, a must be coprime thus d=1
	 */

	//Set the result
	mpz_set(R, lastx);

	//Clear variables
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(r);
	mpz_clear(q);
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(lastx);
	mpz_clear(lasty);
	mpz_clear(t1);
	mpz_clear(t2);
#endif
}

/*Calculates the legendre symbol of a and p
 *Handbook of applied cryptography: Fact 2.146 */
int number_theory_legendre(mpz_t a, mpz_t p)
{
#if EXTERNAL_NUMBER_THEORY_IMPLEMENTATION
	//Do this using gmp number theory implementation
	return mpz_legendre(a, p);
#else
	//Initializing variables
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);
	mpz_t t3;mpz_init(t3);

	//Legendre = a ^ ((p-1)/2) mod p
	mpz_sub_ui(t1, p,1);	//t1 = p - 1
	mpz_set_ui(t2, 2);		//t2 = 2
	mpz_divexact(t3,t1,t2);	//t3 = t1 / 2
	number_theory_exp_modp(t2,a,t3,p);	//t2 = a^t3 mod p

	//Store return value, so we can release memory
	int value;

	/*Exponentiation modulo a prime, can't give a negativ number, hence -1 can't be the result however if -1 was suppose to be the result, the result must be p-1, therefore we shall check if t2 == t1 since t1 is still p-1
	 */
	if(mpz_cmp(t1,t2) == 0)
		value = -1;
	else
		value =  mpz_get_si(t2);

	//Clear variables
	mpz_clear(t1);
	mpz_clear(t2);
	mpz_clear(t3);

	//Return
	return value;
#endif
}

