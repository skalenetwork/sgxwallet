//
// Created by kladko on 10/3/19.
//

#ifndef SGXD_DKGCRYPTO_H
#define SGXD_DKGCRYPTO_H

#include <string>
#include <vector>

std::string gen_dkg_poly( int _t);

std::vector <std::vector<std::string>> get_verif_vect(const char* encryptedPolyHex, int n, int t);

std::vector<std::string> SplitString(const char* koefs, const char symbol);

std::string get_secret_shares(const std::string& polyName, const char* encryptedPolyHex, const std::vector<std::string>& publicKeys, int n, int t);

bool VerifyShares(const char* publicShares, const char* encr_sshare, const char * encryptedKeyHex,  int t, int n, int ind);

std::pair<std::string, std::string> response_to_complaint(const std::string& polyName, const char* encryptedPolyHex, int n, int t, int ind);

bool CreateBLSShare( const std::string& BLSKeyName, const char * s_shares, const char * encryptedKeyHex);

std::vector<std::string> GetBLSPubKey(const char * encryptedKeyHex);


#endif //SGXD_DKGCRYPTO_H
