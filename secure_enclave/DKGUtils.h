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

EXTERNC void gen_dkg_poly( char* secret, unsigned _t);

EXTERNC void calc_secret_shares(const char* decrypted_koefs, char * secret_shares,
                        unsigned _t, unsigned _n);
EXTERNC void calc_public_shares(const char* decrypted_koefs, char * public_shares,
                        unsigned _t);

#endif //SGXD_DKGUTILS_H

