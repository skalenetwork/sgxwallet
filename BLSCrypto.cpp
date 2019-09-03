//
// Created by kladko on 9/2/19.
//
#include <memory>


#include "libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"

#include "bls.h"


#include "leveldb/db.h"
#include <jsonrpccpp/server/connectors/httpserver.h>
#include "BLSPrivateKeyShareSGX.h"

#include "sgxd_common.h"

#include "BLSCrypto.h"


extern "C" void init_daemon() {

  libff::init_alt_bn128_params();

  // Set up database connection information and open database
  leveldb::DB* db;
  leveldb::Options options;
  options.create_if_missing = true;

  leveldb::Status status = leveldb::DB::Open(options, "./keysdb", &db);


}



bool sign(char* _encryptedKeyHex, char* _hashHex, size_t _t, size_t _n, size_t _signerIndex,
    char* _sig) {


  auto keyStr = std::make_shared<std::string>(_encryptedKeyHex);

  auto hash = std::make_shared<std::array<uint8_t, 32>>();

  uint64_t binLen;

  hex2carray(_hashHex, &binLen, hash->data());



  auto keyShare = std::make_shared<BLSPrivateKeyShareSGX>(keyStr, _t, _n);

  auto sigShare = keyShare->signWithHelperSGX(hash, _signerIndex);

  return true;

}


