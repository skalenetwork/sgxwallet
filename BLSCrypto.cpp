//
// Created by kladko on 9/2/19.
//
#include <memory>

#include "BLSCrypto.h"


#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"

#include "bls.h"


#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "BLSPrivateKeyShareSGX.h"


extern "C" void init_daemon() {

  libff::init_alt_bn128_params();

  // Set up database connection information and open database
  leveldb::DB* db;
  leveldb::Options options;
  options.create_if_missing = true;

  leveldb::Status status = leveldb::DB::Open(options, "./keysdb", &db);


}



bool sign(char* encryptedKeyHex, char* hashHex, size_t t, size_t n, char* _sig) {


  auto keyStr = std::make_shared<std::string>(encryptedKeyHex);


  auto keyShare = std::make_shared<BLSPrivateKeyShareSGX>(keyStr, t, n);

  return true;

}


