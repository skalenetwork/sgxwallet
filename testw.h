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

    @file testw.h
    @author Stan Kladko
    @date 2020
*/

#ifndef SGXWALLET_TESTW_H
#define SGXWALLET_TESTW_H

#define TEST_BLS_KEY_SHARE                                                     \
  "41607802314451608892376643913822236041848571538142757705987918646499719198" \
  "44"
#define TEST_BLS_KEY_NAME "SCHAIN:17:INDEX:5:KEY:1"
#define SAMPLE_HASH                                                            \
  "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db"
#define SAMPLE_HEX_HASH                                                        \
  "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F"
#define SAMPLE_KEY_NAME                                                        \
  "tmp_NEK:8abc8e8280fb060988b65da4b8cb00779a1e816ec42f8a40ae2daa520e484a01"
#define SAMPLE_AES_KEY "123456789"

#define SAMPLE_POLY_NAME "POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1"
#define RPC_ENDPOINT "http://localhost:1029"
#define RPC_ENDPOINT_HTTPS "https://localhost:1026"
#define ZMQ_IP "127.0.0.1"
#define ZMQ_PORT 1031

#define SAMPLE_PUBLIC_KEY_B                                                    \
  "c0152c48bf640449236036075d65898fded1e242c00acb45519ad5f788ea7cbf9a5df1559e" \
  "7fc87932eee5478b1b9023de19df654395574a690843988c3ff475"

#define SAMPLE_DKG_PUB_KEY_1                                                   \
  "505f55a38f9c064da744f217d1cb993a17705e9839801958cda7c884e08ab4dad7fd8d2295" \
  "3d3ac7f0913de24fd67d7ed36741141b8a3da152d7ba954b0f14e2"
#define SAMPLE_DKG_PUB_KEY_2                                                   \
  "378b3e6fdfe2633256ae1662fcd23466d02ead907b5d4366136341cea5e46f5a7bb67d897d" \
  "6e35f619810238aa143c416f61c640ed214eb9c67a34c4a31b7d25"

// openssl req -new -newkey rsa:2048 -nodes -keyout yourdomain.key -out
// yourdomain.csr^
#define SAMPLE_CSR_FILE_NAME "samples/yourdomain.csr"

#define ECDSA_KEY_NAME_SIZE 68

#endif // SGXWALLET_TESTW_H
