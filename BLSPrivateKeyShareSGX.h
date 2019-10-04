/*
  Copyright (C) 2018-2019 SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

  @file BLSPrivateKeyShare.h
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#ifndef SGXWALLET_BLSPRIVATEKEYSHARESGX_H
#define SGXWALLET_BLSPRIVATEKEYSHARESGX_H
#define SGXWALLET_BLSPRIVATEKEYSHARESGX_H

#include "BLSSigShare.h"
#include "BLSPrivateKeyShare.h"

class BLSPrivateKeyShareSGX {

  size_t requiredSigners;

  size_t totalSigners;

  std::shared_ptr<std::string> encryptedKeyHex;

public:
  std::shared_ptr<BLSSigShare>
      signWithHelperSGX(std::shared_ptr<std::array<uint8_t, 32>> _hash,
                        size_t _signerIndex);

  std::string signWithHelperSGXstr(
            std::shared_ptr<std::array<uint8_t, 32>> hash_byte_arr,
            size_t _signerIndex);

  BLSPrivateKeyShareSGX(std::shared_ptr<std::string> _encryptedKeyHex,
                        size_t _requiredSigners, size_t _totalSigners);


};

#endif // LIBBLS_BLSPRIVATEKEYSHARE_H
