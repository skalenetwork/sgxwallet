//
// Created by kladko on 06.05.20.
//

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
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
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

#endif //SGXWALLET_TESTW_H
