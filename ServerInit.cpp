//
// Created by kladko on 9/2/19.
//
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

#include "SGXWalletServer.h"

#include "BLSCrypto.h"
#include "ServerInit.h"


void init_all() {
    init_server();
    init_enclave();
    init_daemon();
}