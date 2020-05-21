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

    @file point.h
    @author Stan Kladko
    @date 2019
*/


#ifndef SGXWALLET_POINT_H
#define SGXWALLET_POINT_H




#include "DomainParameters.h"

/*Initialize a point*/
EXTERNC point point_init();

/*Release point*/
EXTERNC void point_clear(point p);

/*Set point to be a infinity*/
EXTERNC void point_at_infinity(point p);

/*Set R to the additive inverse of P, in the curve curve*/
EXTERNC void point_inverse(point R, point P, domain_parameters curve);

/*Print point to standart output stream*/
EXTERNC void point_print(point p);

/*Set point from hexadecimal strings*/
EXTERNC void point_set_hex(point p, const char *x, const char *y);

/*Set point from decimal unsigned long ints*/
EXTERNC void point_set_ui(point p, unsigned long int x, unsigned long int y);

/*Addition of point P + Q = result*/
EXTERNC void point_addition(point result, point P, point Q, domain_parameters curve);

/*Set point R = 2P*/
EXTERNC void point_doubling(point R, point P, domain_parameters curve);

/*Perform scalar multiplication to P, with the factor multiplier, over the curve curve*/
EXTERNC void point_multiplication(point R, mpz_t multiplier, point P, domain_parameters curve);

/*Set point from strings of a base from 2-62*/
EXTERNC void point_set_str(point p, const char *x, const char *y, int base);

/*Compare two points return 1 if not the same, returns 0 if they are the same*/
EXTERNC bool point_cmp(point P, point Q);

/*Decompress a point from hexadecimal representation
 *This function is implemented as specified in SEC 1: Elliptic Curve Cryptography, section 2.3.4.*/
EXTERNC void point_decompress(point P, char* zPoint, domain_parameters curve);

/*Compress a point to hexadecimal string
 *This function is implemented as specified in SEC 1: Elliptic Curve Cryptography, section 2.3.3.*/
EXTERNC char* point_compress(point P);

/*Make R a copy of P*/
EXTERNC void point_copy(point R, point P);

/*Set a point from another point*/
EXTERNC void point_set(point R, point P);

#endif