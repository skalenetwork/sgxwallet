//
// Created by kladko on 9/2/19.
//

#include "BLSCrypto.h"


#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"

#include "bls.h"

extern "C" void init_bls() {

  libff::init_alt_bn128_params();

}

class BLSCrypto {



};
