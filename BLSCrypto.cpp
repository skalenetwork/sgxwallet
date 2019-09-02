//
// Created by kladko on 9/2/19.
//

#include "BLSCrypto.h"


#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"

#include "bls.h"


#include "leveldb/db.h"


extern "C" void init_daemon() {

  libff::init_alt_bn128_params();

  // Set up database connection information and open database
  leveldb::DB* db;
  leveldb::Options options;
  options.create_if_missing = true;

  leveldb::Status status = leveldb::DB::Open(options, "./keysdb", &db);


}

class BLSCrypto {



};
