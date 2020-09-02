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
#include <iostream>

#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"
#include <libff/common/profiling.hpp>
#include "bls.h"
#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>

#include "third_party/spdlog/spdlog.h"
#include <gmp.h>
#include <sgx_urts.h>


#include "BLSPrivateKeyShareSGX.h"
#include "sgxwallet_common.h"
#include "third_party/intel/create_enclave.h"
#include "secure_enclave_u.h"
#include "third_party/intel/sgx_detect.h"
#include "sgxwallet.h"
#include "LevelDB.h"
#include "SGXWalletServer.h"
#include "SGXRegistrationServer.h"
#include "SEKManager.h"
#include "CSRManagerServer.h"
#include "BLSCrypto.h"
#include "ServerInit.h"
#include "SGXException.h"
#include "SGXWalletServer.hpp"

void initUserSpace() {

    libff::inhibit_profiling_counters = true;

    libff::init_alt_bn128_params();

    LevelDB::initDataFolderAndDBs();
}

void initEnclave(uint32_t _logLevel) {
    eid = 0;
    updated = 0;

#ifndef SGX_HW_SIM
    unsigned long support;
    support = get_sgx_support();
    if (!SGX_OK(support)) {
        sgx_support_perror(support);
        exit(1);
    }
#endif

    spdlog::info("SGX_DEBUG_FLAG = {}", SGX_DEBUG_FLAG);

    status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token,
                                       &updated, &eid, 0);

    if (status != SGX_SUCCESS) {
        if (status == SGX_ERROR_ENCLAVE_FILE_ACCESS) {
            spdlog::error("sgx_create_enclave: {}: file not found", ENCLAVE_NAME);
            spdlog::error("Did you forget to set LD_LIBRARY_PATH?");
        } else {
            spdlog::error("sgx_create_enclave_search failed {} {}", ENCLAVE_NAME, status);
        }
        exit(1);
    }

    spdlog::info("Enclave created and started successfully");

    status = trustedEnclaveInit(eid, _logLevel);
    if (status != SGX_SUCCESS) {
        spdlog::error("trustedEnclaveInit failed: {}", status);
        exit(1);
    }

    spdlog::info("Enclave libtgmp library and logging initialized successfully");
}


void initAll(uint32_t _logLevel, bool _checkCert, bool _autoSign) {

    static atomic<bool> sgxServerInited(false);
    static mutex initMutex;

    lock_guard <mutex> lock(initMutex);

    if (sgxServerInited)
        return;

    try {

        cout << "Running sgxwallet version:" << SGXWalletServer::getVersion() << endl;

        CHECK_STATE(sgxServerInited != 1)
        sgxServerInited = 1;
        initEnclave(_logLevel);
        initUserSpace();
        initSEK();

        if (useHTTPS) {
            SGXWalletServer::initHttpsServer(_checkCert);
            SGXRegistrationServer::initRegistrationServer(_autoSign);
            CSRManagerServer::initCSRManagerServer();
        } else {
            SGXWalletServer::initHttpServer();
        }
        sgxServerInited = true;
    } catch (SGXException &_e) {
        spdlog::error(_e.getMessage());
    } catch (exception &_e) {
        spdlog::error(_e.what());
    }
    catch (...) {
        exception_ptr p = current_exception();
        printf("Exception %s \n", p.__cxa_exception_type()->name());
        spdlog::error("Unknown exception");
    }
};
