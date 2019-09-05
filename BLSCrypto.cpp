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



#include "BLSCrypto.h"

int char2int(char _input) {
  if (_input >= '0' && _input <= '9')
    return _input - '0';
  if (_input >= 'A' && _input <= 'F')
    return _input - 'A' + 10;
  if (_input >= 'a' && _input <= 'f')
    return _input - 'a' + 10;
  return -1;
}



void  carray2Hex(const unsigned char *d, int _len, char* _hexArray) {

  char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  for (int j = 0; j < _len; j++) {
    _hexArray[j * 2] = hexval[((d[j] >> 4) & 0xF)];
    _hexArray[j * 2 + 1] = hexval[(d[j]) & 0x0F];
  }

  _hexArray[_len * 2] = 0;

}


bool hex2carray(const char * _hex, uint64_t  *_bin_len,
                uint8_t* _bin ) {

  int len = strnlen(_hex, 2 * BUF_LEN);


  if (len == 0 && len % 2 == 1)
    return false;

  *_bin_len = len / 2;

  for (int i = 0; i < len / 2; i++) {
    int high = char2int((char)_hex[i * 2]);
    int low = char2int((char)_hex[i * 2 + 1]);

    if (high < 0 || low < 0) {
      return false;
    }

    _bin[i] = (unsigned char) (high * 16 + low);
  }

  return true;

}


void init_daemon() {

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


