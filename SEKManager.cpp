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

    @file SEKManager.cpp
    @author Stan Kladko
    @date 2019
*/

#include "SEKManager.h"
#include "RPCException.h"
#include "BLSCrypto.h"
#include "LevelDB.h"

#include <iostream>

#include "sgxwallet_common.h"
#include "common.h"
#include "sgxwallet.h"

void generate_SEK(){

  vector<char> errMsg(1024,0);
  int err_status = 0;
  vector<uint8_t> encr_SEK(1024, 0);
  uint32_t enc_len = 0;

  status = generate_SEK(eid, &err_status, errMsg.data(), encr_SEK.data(), &enc_len);
  if ( err_status != 0 ){
    cerr << "RPCException thrown" << endl;
    throw RPCException(-666, errMsg.data()) ;
  }

  vector<char> hexEncrKey(2*enc_len + 1, 0);

  carray2Hex(encr_SEK.data(), enc_len, hexEncrKey.data());

  cerr << "key is " << errMsg.data() << endl;

  LevelDB::getLevelDb()->writeDataUnique("SEK", hexEncrKey.data());

}

void setSEK(std::shared_ptr<std::string> hex_encr_SEK){
  vector<char> errMsg(1024,0);
  int err_status = 0;
  //vector<uint8_t> encr_SEK(1024, 0);

  uint8_t encr_SEK [BUF_LEN];

  uint64_t len;

  if (!hex2carray(hex_encr_SEK->c_str(), &len, encr_SEK)){
    throw RPCException(INVALID_HEX, "Invalid encrypted SEK Hex");
  }

  status = set_SEK(eid, &err_status, errMsg.data(), encr_SEK );
  if ( err_status != 0 ){
    cerr << "RPCException thrown" << endl;
    throw RPCException(-666, errMsg.data()) ;
  }

}
