//
// Created by kladko on 9/5/19.
//

#ifndef SGXD_DKGUTILS_H
#define SGXD_DKGUTILS_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#include <sgx_tgmp.h>

EXTERNC void gen_dkg_poly( char* secret, unsigned _t);

EXTERNC void calc_secret_shares(const char* decrypted_koefs, char * secret_shares,
                        unsigned _t, unsigned _n);

EXTERNC void calc_secret_share(const char* decrypted_koefs, char * s_share,
                               unsigned _t, unsigned _n, unsigned ind);

EXTERNC void calc_public_shares(const char* decrypted_koefs, char * public_shares,
                        unsigned _t);

EXTERNC int Verification (char * decrypted_koefs, mpz_t decr_secret_share, int _t, int ind );

#endif //SGXD_DKGUTILS_H

