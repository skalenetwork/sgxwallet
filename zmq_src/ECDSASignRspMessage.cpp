/*
  Copyright (C) 2018- SKALE Labs

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
  along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

  @file ECDSARspSignMessage.cpp
  @author Stan Kladko
  @date 2020
*/

#include "SGXWalletServer.hpp"

#include "ECDSASignRspMessage.h"



Json::Value ECDSASignRspMessage::process() {
    // never called
    assert(false);
}

string ECDSASignRspMessage::getSignature() {



    string r = getStringRapid( "signature_r" );
    string v = getStringRapid( "signature_v" );
    string s = getStringRapid("signature_s" );

    auto ret = v + ":" + r.substr( 2 ) + ":" + s.substr( 2 );

    return ret;
}
