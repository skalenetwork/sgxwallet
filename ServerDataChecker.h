//
// Created by kladko on 11/19/19.
//

#ifndef SGXD_SERVERDATACHECKER_H
#define SGXD_SERVERDATACHECKER_H

#include <string>

bool checkECDSAKeyName(const std::string& keyName);

bool checkHex(const std::string& hash, const uint32_t sizeInBytes = 32);

bool checkPolyName (const std::string& polyName);

bool checkName (const std::string& Name, const std::string& prefix);

bool check_n_t ( const int t, const int n);

#endif // SGXD_SERVERDATACHECKER_H
