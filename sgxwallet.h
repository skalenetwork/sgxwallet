//
// Created by kladko on 9/3/19.
//

#ifndef SGXWALLET_SGXWALLET_H
#define SGXWALLET_SGXWALLET_H


#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>

extern sgx_enclave_id_t eid;
extern int updated;
extern sgx_launch_token_t token;
extern sgx_status_t status;

#define ENCLAVE_NAME "secure_enclave.signed.so"



#endif //SGXWALLET_SGXWALLET_H
