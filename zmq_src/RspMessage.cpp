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

  @file RspMessage.cpp
  @author Oleh Nikolaiev
  @date 2021
*/

#include "SGXWalletServer.hpp"

#include "RspMessage.h"

Json::Value ECDSASignRspMessage::process() {
    assert(false);
}

string ECDSASignRspMessage::getSignature() {
    string r = getStringRapid("signature_r");
    string v = getStringRapid("signature_v");
    string s = getStringRapid("signature_s");

    auto ret = v + ":" + r.substr( 2 ) + ":" + s.substr( 2 );

    return ret;
}

Json::Value BLSSignRspMessage::process() {
    assert(false);
}

Json::Value importBLSRspMessage::process() {
    assert(false);
}

Json::Value importECDSARspMessage::process() {
    assert(false);
}

Json::Value generateECDSARspMessage::process() {
    assert(false);
}

Json::Value getPublicECDSARspMessage::process() {
    assert(false);
}

Json::Value generateDKGPolyRspMessage::process() {
    assert(false);
}

Json::Value getVerificationVectorRspMessage::process() {
    assert(false);
}

Json::Value getSecretShareRspMessage::process() {
    assert(false);
}

Json::Value dkgVerificationRspMessage::process() {
    assert(false);
}

Json::Value createBLSPrivateKeyRspMessage::process() {
    assert(false);
}

Json::Value getBLSPublicRspMessage::process() {
    assert(false);
}

Json::Value getAllBLSPublicKeysRspMessage::process() {
    assert(false);
}

Json::Value complaintResponseRspMessage::process() {
    assert(false);
}

Json::Value multG2RspMessage::process() {
    assert(false);
}

Json::Value isPolyExistsRspMessage::process() {
    assert(false);
}

Json::Value getServerStatusRspMessage::process() {
    assert(false);
}

Json::Value getServerVersionRspMessage::process() {
    assert(false);
}

Json::Value deleteBLSKeyRspMessage::process() {
    assert(false);
}

Json::Value GetDecryptionShareRspMessage::process() {
    assert(false);
}

Json::Value generateBLSPrivateKeyRspMessage::process() {
    assert(false);
}

Json::Value popProveRspMessage::process() {
    assert(false);
}
