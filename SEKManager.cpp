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
#include "sgxwallet.h"

void generate_SEK(){

  char *errMsg = (char *)calloc(1024, 1);
  int err_status = 0;
  uint8_t* encr_pr_key = (uint8_t *)calloc(1024, 1);
  uint32_t enc_len = 0;

  status = generate_SEK(eid, &err_status, errMsg, encr_pr_key, &enc_len);
  if ( err_status != 0 ){
    std::cerr << "RPCException thrown" << std::endl;
    throw RPCException(-666, errMsg) ;
  }

  char *hexEncrKey = (char *) calloc(BUF_LEN, 1);
  //carray2Hex(encr_pr_key, enc_len, hexEncrKey);

  std::cerr << "key is " << errMsg << std::endl;

  //levelDb->writeDataUnique("SEK", hexEncrKey);

  free(errMsg);
  free(encr_pr_key);
  free(hexEncrKey);
}
