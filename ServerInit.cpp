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

    @file ServerInit.cpp
    @author Stan Kladko
    @date 2019
*/

#include <memory>


#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"

#include "bls.h"


#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "BLSPrivateKeyShareSGX.h"


#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>

#include "sgxwallet.h"

#include "LevelDB.h"

#include "SGXWalletServer.h"

#include "BLSCrypto.h"
#include "ServerInit.h"

#include <iostream>





void init_daemon() {

    libff::init_alt_bn128_params();

    static std::string dbName("./" WALLETDB_NAME);


    levelDb = new LevelDB(dbName);

}



void init_enclave() {

    eid = 0;
    updated = 0;

    unsigned long support;

#ifndef SGX_HW_SIM
    support = get_sgx_support();
    if (!SGX_OK(support)) {
        sgx_support_perror(support);
        exit(1);
    }
#endif

    std::cerr << "SGX_DEBUG_FLAG = " << SGX_DEBUG_FLAG << std::endl;

    status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token,
                                       &updated, &eid, 0);

    if (status != SGX_SUCCESS) {
        if (status == SGX_ERROR_ENCLAVE_FILE_ACCESS) {
            fprintf(stderr, "sgx_create_enclave: %s: file not found\n", ENCLAVE_NAME);
            fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
        } else {
            fprintf(stderr, "%s: 0x%04x\n", ENCLAVE_NAME, status);
        }
        exit(1);
    }

    fprintf(stderr, "Enclave launched\n");

    status = tgmp_init(eid);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "ECALL tgmp_init: 0x%04x\n", status);
        exit(1);
    }

    fprintf(stderr, "libtgmp initialized\n");
}


int sgxServerInited = 0;

void init_all() {



    if (sgxServerInited == 1)
        return;

    sgxServerInited = 1;

    init_server();
    init_enclave();
    std::cerr << "enclave inited" << std::endl;
    init_daemon();
}
