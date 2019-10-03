//
// Created by kladko on 10/3/19.
//

#include "DKGCrypto.h"
#include "BLSCrypto.h"
#include "sgxwallet.h"
#include <iostream>

std::string gen_dkg_poly( int _t){
    char *errMsg = (char *)calloc(1024, 1);
    int err_status = 0;
    uint8_t* encrypted_dkg_secret = (uint8_t *)calloc(2000, 1);

    uint32_t enc_len = 0;

    status = gen_dkg_secret (eid, &err_status, errMsg, encrypted_dkg_secret, &enc_len, _t);

    char *hexEncrPoly = (char *) calloc(4*BUF_LEN, 1);
    carray2Hex(encrypted_dkg_secret, enc_len, hexEncrPoly);
    std::string result(hexEncrPoly);

    //std::cerr << "in DKGCrypto encr key x " <<  << std::endl;

    free(errMsg);
    free(encrypted_dkg_secret);
    free(hexEncrPoly);

    return result;
}