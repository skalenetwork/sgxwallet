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

    @file signature.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_SIGNATURE_H
#define SGXWALLET_SIGNATURE_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

/*Type for representing a signature*/
struct signature_s
{
	mpz_t r;
	mpz_t s;
	unsigned int v;
};

typedef struct signature_s* signature;

/*Initialize a signature*/
EXTERNC signature signature_init();

/*Set signature from strings of a base from 2-62*/
EXTERNC int signature_set_str(signature sig, const char *r, const char *s, int base);

/*Set signature from hexadecimal strings*/
EXTERNC int signature_set_hex(signature sig, const char *r, const char *s);

/*Set signature from decimal unsigned long ints*/
EXTERNC void signature_set_ui(signature sig, unsigned long int r, unsigned long int s);

/*Print signature to standart output stream*/
EXTERNC void signature_print(signature sig);

/*Make R a copy of P*/
EXTERNC void signature_copy(signature R, signature sig);

/*Compare two signatures return 1 if not the same, returns 0 if they are the same*/
EXTERNC bool signature_cmp(signature sig1, signature sig2);

/*Release signature*/
EXTERNC void signature_free(signature sig);

/*Generates a public key for a private key*/
EXTERNC void signature_extract_public_key(point public_key, mpz_t private_key, domain_parameters curve);

/*Generate signature for a message*/
EXTERNC void signature_sign(signature sig, mpz_t message, mpz_t private_key, domain_parameters curve);

/*Verify the integrity of a message using it's signature*/
EXTERNC bool signature_verify(mpz_t message, signature sig, point public_key, domain_parameters curve);

#endif
