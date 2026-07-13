/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.
*/

#include "TestKeyGenerator.h"

#include "BLSPublicKey.h"
#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "CryptoTools.h"
#include "SGXException.h"
#include "WalletConstants.h"
#include "common.h"
#include "sgxwallet_common.h"

#include <array>
#include <gmp.h>
#include <iostream>
#include <json/value.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace std;

namespace {

string convertDecToHex(const string &dec, int numBytes = 32) {
  mpz_t num;
  mpz_init(num);
  mpz_set_str(num, dec.c_str(), 10);
  vector<char> tmp(mpz_sizeinbase(num, 16) + 2, 0);
  char *hex = mpz_get_str(tmp.data(), 16, num);
  string result = hex;
  int n_zeroes = numBytes * 2 - result.length();
  result.insert(0, n_zeroes, '0');
  mpz_clear(num);
  return result;
}

} // namespace

void TestKeyGenerator::generateDkgKeys(StubClient &client, int n, int t,
                                       vector<string> &ecdsaKeyNames,
                                       vector<string> &blsKeyNames,
                                       int schainID, int dkgID) {
  vector<Json::Value> ethKeys(n);
  vector<Json::Value> verifVects(n);
  Json::Value pubEthKeys;
  vector<Json::Value> secretShares(n);
  vector<Json::Value> pubBLSKeys(n);
  vector<Json::Value> blsSigShares(n);
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  ecdsaKeyNames.clear();
  blsKeyNames.clear();

  for (uint8_t i = 0; i < n; i++) {
    ethKeys[i] = client.generateECDSAKey();

    CHECK_STATE(ethKeys[i]["status"] == 0);

    auto keyName = ethKeys[i]["keyName"].asString();
    CHECK_STATE(keyName.size() == WalletConstants::ECDSA_KEY_NAME_SIZE);

    ecdsaKeyNames.push_back(keyName);

    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);

    Json::Value response = client.generateDKGPoly(polyName, t);
    CHECK_STATE(response["status"] == 0);
    polyNames[i] = polyName;
    verifVects[i] = client.getVerificationVector(polyName, t);
    CHECK_STATE(verifVects[i]["status"] == 0);
    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = client.getSecretShare(polyNames[i], pubEthKeys, t, n);
    CHECK_STATE(secretShares[i]["status"] == 0);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        CHECK_STATE(pubShare.length() > 60);
        pubShares[i] += convertDecToHex(pubShare);
      }
    }
  }

  vector<string> secShares(n);
  vector<string> pSharesBad(pubShares);

  for (int i = 0; i < n; i++) {
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      Json::Value response = client.dkgVerification(
          pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
      CHECK_STATE(response["status"] == 0);

      bool res = response["result"].asBool();
      CHECK_STATE(res);

      pSharesBad[i][0] = 'q';
      Json::Value wrongVerif = client.dkgVerification(
          pSharesBad[i], ethKeys[j]["keyName"].asString(), secretShare, t, n,
          j);
      res = wrongVerif["result"].asBool();
      CHECK_STATE(!res);
    }
  }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = WalletConstants::SAMPLE_MESSAGE_HASH;
  auto hashArr = make_shared<array<uint8_t, 32>>();
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hashArr->data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, libBLS::BLSPublicKeyShare> pubKeyShares;

  for (int i = 0; i < n; i++) {
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    blsKeyNames.push_back(blsName);

    auto response =
        client.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(),
                                   polyNames[i], secShares[i], t, n);
    CHECK_STATE(response["status"] == 0);
    pubBLSKeys[i] = client.getBLSPublicKeyShare(blsName);
    CHECK_STATE(pubBLSKeys[i]["status"] == 0);
  }

  for (int i = 0; i < t; i++) {
    vector<string> pubKeyVect;
    for (uint8_t j = 0; j < 4; j++) {
      pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
    }
    libBLS::BLSPublicKeyShare pubKey(pubKeyVect, t, n);

    pubKeyShares.insert(make_pair(i + 1, pubKey));
  }

  libBLS::BLSPublicKey blsPublicKey(pubKeyShares, t, n);

  for (int i = 0; i < t; i++) {
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    blsSigShares[i] = client.blsSignMessageHash(blsName, hash, t, n);
    CHECK_STATE(blsSigShares[i]["status"] == 0);
    string sigShare = blsSigShares[i]["signatureShare"].asString();
    libBLS::BLSSigShare sig(sigShare, i + 1, t, n);
    sigShareSet.addSigShare(sig);

    auto pubKey = pubKeyShares.at(i + 1);

    CHECK_STATE(pubKey.VerifySigWithHelper(*hashArr, sig, t, n));
  }

  libBLS::BLSSignature commonSig = sigShareSet.merge();

  CHECK_STATE(blsPublicKey.VerifySigWithHelper(*hashArr, commonSig));

  for (auto &&keyName : ecdsaKeyNames) {
    cerr << keyName << endl;
  }

  for (auto &&keyName : blsKeyNames) {
    cerr << keyName << endl;
  }
}
