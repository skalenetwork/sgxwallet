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

    @file point.c
    @author Stan Kladko
    @date 2019
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#ifdef USER_SPACE
#include <gmp.h>
#else
#include <../tgmp-build/include/sgx_tgmp.h>
#endif

#include "NumberTheory.h"

#include "DomainParameters.h"
#include "Point.h"
/*Initialize a point*/
point point_init()
{
	point p;
	p = calloc(sizeof(struct point_s), 1);
	mpz_init(p->x);
	mpz_init(p->y);
	p->infinity = false;
	return p;
}

/*Set point to be a infinity*/
void point_at_infinity(point p)
{
	p->infinity = true;
}

/*Print point to standart output stream*/


/*Set a point from another point*/
void point_set(point R, point P)
{
	//Copy the point
	mpz_set(R->x, P->x);
	mpz_set(R->y, P->y);

	//Including infinity settings
	R->infinity = P->infinity;
}

/*Set point from strings of a base from 2-62*/
int point_set_str(point p, const  char *x, const char *y, int base)
{
	if (mpz_set_str(p->x, x, base) != 0 || mpz_set_str(p->y, y, base) != 0) {
        return 1;
    }

    return 0;
}

/*Set point from hexadecimal strings*/
int point_set_hex(point p, const char *x, const char *y)
{
	return point_set_str(p,x,y,16);
}

/*Set point from decimal unsigned long ints*/
void point_set_ui(point p, unsigned long int x, unsigned long int y)
{
	mpz_set_ui(p->x, x);
	mpz_set_ui(p->y, y);
}

/*Make R a copy of P*/
void point_copy(point R, point P)
{
	//Same as point set
	point_set(R, P);
}

/*Addition of point P + Q = result*/
void point_addition(point result, point P, point Q, domain_parameters curve)
{
	//If Q is at infinity, set result to P
	if(Q->infinity)
	{
		point_set(result, P);

	//If P is at infinity set result to be Q
	}else if(P->infinity){
		point_set(result, Q);

	//If the points are the same use point doubling
	}else if(point_cmp(P,Q))
	{
		point_doubling(result, Q, curve);
	}else{
		//Calculate the inverse point
		point iQ = point_init();
		point_inverse(iQ, Q, curve);
		bool is_inverse = point_cmp(iQ,P);
		point_clear(iQ);

		//If it is the inverse
		if(is_inverse)
		{
			//result must be point at infinity
			point_at_infinity(result);
		}else{
			//Initialize slope variable
			mpz_t s;mpz_init(s);
			//Initialize temporary variables
			mpz_t t1;mpz_init(t1);
			mpz_t t2;mpz_init(t2);
			mpz_t t3;mpz_init(t3);
			mpz_t t4;mpz_init(t4);
			mpz_t t5;mpz_init(t5);
		/*
		Modulo algebra rules:
		(b1 + b2) mod  n = (b2 mod n) + (b1 mod n) mod n
		(b1 * b2) mod  n = (b2 mod n) * (b1 mod n) mod n
		*/

			//Calculate slope
			//s = (Py - Qy)/(Px-Qx) mod p
			mpz_sub(t1, P->y, Q->y);
			mpz_sub(t2, P->x, Q->x);
			//Using Modulo to stay within the group!
			number_theory_inverse(t3, t2, curve->p); //Handle errors
			mpz_mul(t4, t1, t3);
			mpz_mod(s, t4, curve->p);

			//Calculate Rx using algorithm shown to the right of the commands
			//Rx = s² - Px - Qx = (s² mod p) - (Px mod p) - (Qx mod p) mod p
			number_theory_exp_modp_ui(t1, s, 2, curve->p);	//t1 = s² mod p
			mpz_mod(t2, P->x, curve->p);		//t2 = Px mod p
			mpz_mod(t3, Q->x, curve->p);		//t3 = Qx mod p
			mpz_sub(t4, t1, t2);				//t4 = t1 - t2
			mpz_sub(t5, t4, t3);				//t5 = t4 - t3
			mpz_mod(result->x, t5, curve->p);	//R->x = t5 mod p

			//Calculate Ry using algorithm shown to the right of the commands
			//Ry = s(Px-Rx) - Py mod p
			mpz_sub(t1, P->x, result->x);		//t1 = Px - Rx
			mpz_mul(t2, s, t1);					//t2 = s*t1
			mpz_sub(t3, t2, P->y);				//t3 = t2 - Py
			mpz_mod(result->y, t3, curve->p);	//Ry = t3 mod p

			//Clear variables, release memory
			mpz_clear(t1);
			mpz_clear(t2);
			mpz_clear(t3);
			mpz_clear(t4);
			mpz_clear(t5);
			mpz_clear(s);
		}	
	}
}

/*Set R to the additive inverse of P, in the curve curve*/
void point_inverse(point R, point P, domain_parameters curve)
{
	//If at infinity
	if(P->infinity)
	{
		R->infinity = true;
	}else{
		//Set Rx = Px
		mpz_set(R->x, P->x);

		//Set Ry = -Py mod p = p - Ry (Since, Ry < p and Ry is positive)
		mpz_sub(R->y, curve->p, P->y);
	}
}

/*Set point R = 2P*/
void point_doubling(point R, point P, domain_parameters curve)
{
	//If at infinity
	if(P->infinity)
	{
		R->infinity = true;
	}else{
		//Initialize slope variable
		mpz_t s;mpz_init(s);
		//Initialize temporary variables
		mpz_t t1;mpz_init(t1);
		mpz_t t2;mpz_init(t2);
		mpz_t t3;mpz_init(t3);
		mpz_t t4;mpz_init(t4);
		mpz_t t5;mpz_init(t5);

		//Calculate slope
		//s = (3*Px² + a) / (2*Py) mod p
		number_theory_exp_modp_ui(t1, P->x, 2, curve->p);	//t1 = Px² mod p
		mpz_mul_ui(t2, t1, 3);				//t2 = 3 * t1
		mpz_mod(t3, t2, curve->p);			//t3 = t2 mod p
		mpz_add(t4, t3, curve->a);			//t4 = t3 + a
		mpz_mod(t5, t4, curve->p);			//t5 = t4 mod p

		mpz_mul_ui(t1, P->y, 2);			//t1 = 2*Py
		number_theory_inverse(t2, t1, curve->p);		//t2 = t1^-1 mod p
		mpz_mul(t1, t5, t2);				//t1 = t5 * t2
		mpz_mod(s, t1, curve->p);			//s = t1 mod p

		//Calculate Rx
		//Rx = s² - 2*Px mod p
		number_theory_exp_modp_ui(t1, s, 2, curve->p);//t1 = s² mod p
		mpz_mul_ui(t2, P->x, 2);		//t2 = Px*2
		mpz_mod(t3, t2, curve->p);		//t3 = t2 mod p
		mpz_sub(t4, t1, t3);			//t4 = t1 - t3
		mpz_mod(R->x, t4, curve->p);	//Rx = t4 mod p

		//Calculate Ry using algorithm shown to the right of the commands
		//Ry = s(Px-Rx) - Py mod p
		mpz_sub(t1, P->x, R->x);			//t1 = Px - Rx
		mpz_mul(t2, s, t1);					//t2 = s*t1
		mpz_sub(t3, t2, P->y);				//t3 = t2 - Py
		mpz_mod(R->y, t3, curve->p);	//Ry = t3 mod p

		//Clear variables, release memory
		mpz_clear(t1);
		mpz_clear(t2);
		mpz_clear(t3);
		mpz_clear(t4);
		mpz_clear(t5);
		mpz_clear(s);
	}
}

/*Compare two points return 1 if not the same, returns 0 if they are the same*/
bool point_cmp(point P, point Q)
{
	//If at infinity
	if(P->infinity && Q->infinity)
		return true;
	else if(P->infinity || Q->infinity)
		return false;
	else
		return !mpz_cmp(P->x,Q->x) && !mpz_cmp(P->y,Q->y);
}

/*Perform scalar multiplication to P, with the factor multiplier, over the curve curve*/
void point_multiplication(point R, mpz_t multiplier, point P, domain_parameters curve)
{
	//If at infinity R is also at infinity
	if(P->infinity)
	{
		R->infinity = true;
	}else{
		//Initializing variables
		point x = point_init();
		point_copy(x, P);
		point t = point_init();
		point_copy(t, x);

		//Set R = point at infinity
		point_at_infinity(R);

/*
Loops through the integer bit per bit, if a bit is 1 then x is added to the result. Looping through the multiplier in this manner allows us to use as many point doubling operations as possible. No reason to say 5P=P+P+P+P+P, when you might as well just use 5P=2(2P)+P.
This is not the most effecient method of point multiplication, but it's faster than P+P+P+... which is not computational feasiable.
*/
		int bits = mpz_sizeinbase(multiplier, 2);
		long int bit = 0;
		while(bit <= bits)
		{
			if(mpz_tstbit(multiplier, bit))
			{
				point_addition(t, x, R, curve);
				point_copy(R, t);
			}
			point_doubling(t, x, curve);
			point_copy(x, t);
			bit++;
		}

		//Release temporary variables
		point_clear(x);
		point_clear(t);
	}
}

/*Decompress a point from hexadecimal representation
 *This function is implemented as specified in SEC 1: Elliptic Curve Cryptography, section 2.3.4.*/
void point_decompress(point P, char* zPoint, domain_parameters curve)
{
	//Initialiser variabler
	mpz_t x;mpz_init(x);
	mpz_t a;mpz_init(a);
	mpz_t b;mpz_init(b);
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);
	mpz_t t3;mpz_init(t3);
	mpz_t t4;mpz_init(t4);

	//Get x coordinate
	mpz_set_str(x, zPoint + 2, 16);

	//alpha = x^3+a*x+b mod p
	number_theory_exp_modp_ui(t1, x, 3, curve->p);//t1 = x^3 mod p
	mpz_mul(t3, x, curve->a);		//t3 = a*x
	mpz_mod(t2, t3, curve->p);		//t2 = t3 mod p
	mpz_add(t3, t1, t2);			//t3 = t1 + t2
	mpz_add(t4, t3, curve->b);		//t4 = t3 + b
	mpz_mod(a, t4, curve->p);		//a = t4 mod p

	//beta = sqrt(alpha) mod p
	number_theory_squareroot_modp(b, a, curve->p);

	//Get y mod 2 from input
	mpz_set_ui(t2, zPoint[1] == '2' ? 0 : 1);

	//Set x
	mpz_set(P->x, x);

	//t2 = beta mod p
	mpz_mod_ui(t1, b, 2);
	if(mpz_cmp(t1, t2))
		mpz_set(P->y, b);	//y = beta
	else
		mpz_sub(P->y, curve->p, b);//y = p -beta

	//Release variables
	mpz_clear(x);
	mpz_clear(a);
	mpz_clear(b);
	mpz_clear(t1);
	mpz_clear(t2);
	mpz_clear(t3);
	mpz_clear(t4);
}

/*Compress a point to hexadecimal string
 *This function is implemented as specified in SEC 1: Elliptic Curve Cryptography, section 2.3.3.*/
char* point_compress(point P)
{
	//Point should not be at infinity
	assert(!P->infinity);

	//Reserve memory
	int l = mpz_sizeinbase(P->x, 16) + 2;
	char* result = (char*)calloc(l + 1, 1);
	result[l] = '\0';
	mpz_t t1;mpz_init(t1);

	//Add x coordinat in hex to result
	mpz_get_str(result +2, 16, P->x);

	//Determine if it's odd or even
	mpz_mod_ui(t1, P->y, 2);
	if(mpz_cmp_ui(t1, 0))
		strncpy(result, "02", 2);
	else
		strncpy(result, "03", 2);

	mpz_clear(t1);

	return result;
}

/*Release point*/
void point_clear(point p)
{
	mpz_clear(p->x);
	mpz_clear(p->y);
	free(p);
}

