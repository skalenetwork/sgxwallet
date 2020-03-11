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

/*Type for representing a signature*/
struct signature_s
{
	mpz_t r;
	mpz_t s;
	unsigned int v;
};

typedef struct signature_s* signature;

/*Initialize a signature*/
signature signature_init();

/*Set signature from strings of a base from 2-62*/
void signature_set_str(signature sig, char *r, char *s, int base);

/*Set signature from hexadecimal strings*/
void signature_set_hex(signature sig, char *r, char *s);

/*Set signature from decimal unsigned long ints*/
void signature_set_ui(signature sig, unsigned long int r, unsigned long int s);

/*Print signature to standart output stream*/
void signature_print(signature sig);

/*Make R a copy of P*/
void signature_copy(signature R, signature sig);

/*Compare two signatures return 1 if not the same, returns 0 if they are the same*/
bool signature_cmp(signature sig1, signature sig2);

/*Release signature*/
void signature_free(signature sig);

/*Generates a public key for a private key*/
void signature_extract_public_key(point public_key, mpz_t private_key, domain_parameters curve);

/*Generate signature for a message*/
void signature_sign(signature sig, mpz_t message, mpz_t private_key, domain_parameters curve);

/*Verify the integrity of a message using it's signature*/
bool signature_verify(mpz_t message, signature sig, point public_key, domain_parameters curve);


