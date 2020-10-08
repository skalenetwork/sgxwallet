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

    @file TestUtils.h
    @author Stan Kladko
    @date 2020
*/

#ifndef SGXWALLET_TESTUTILS_H
#define SGXWALLET_TESTUTILS_H

#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include "sgxwallet_common.h"
#include "third_party/intel/create_enclave.h"
#include "secure_enclave_u.h"
#include "third_party/intel/sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>
#include <stdio.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <sgx_tcrypto.h>
#include "stubclient.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "abstractstubserver.h"

using namespace std;

using namespace jsonrpc;

class TestUtils {

public:
    static default_random_engine randGen;

    static string stringFromFr(libff::alt_bn128_Fr &el);

    static string convertDecToHex(string dec, int numBytes = 32);

    static void genTestKeys();

    static void resetDB();

    static shared_ptr<string> encryptTestKey();

    static vector <libff::alt_bn128_Fr> splitStringToFr(const char *coeffs, const char symbol);

    static vector <string> splitStringTest(const char *coeffs, const char symbol);

    static libff::alt_bn128_G2 vectStringToG2(const vector <string> &G2_str_vect);

    static void sendRPCRequest();

    static void destroyEnclave();

    static void doDKG(StubClient &c, int n, int t,
                                 vector<string>& _ecdsaKeyNames, vector<string>& _blsKeyNames,
                                 int schainID, int dkgID);
};

int sessionKeyRecoverDH(const char *skey_str, const char *sshare, char *common_key);

int xorDecryptDH(char *key, const char *cypher, char *message);

#endif //SGXWALLET_TESTW_H
