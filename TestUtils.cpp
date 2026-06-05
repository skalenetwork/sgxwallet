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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

    @file TestUtils.cpp
    @author Stan Kladko
    @date 2020
*/

#include <jsonrpccpp/server/connectors/httpserver.h>

#include "secure_enclave_u.h"
#include "sgxwallet_common.h"
#include "third_party/intel/create_enclave.h"
#include "third_party/intel/sgx_detect.h"
#include "third_party/spdlog/spdlog.h"
#include <gmp.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <sgx_tcrypto.h>
#include <sgx_urts.h>
#include <stdio.h>

#include "BLSCrypto.h"
#include "CryptoTools.h"
#include "DKGCrypto.h"
#include "LevelDB.h"
#include "SGXException.h"
#include "SGXWalletServer.hpp"
#include "ServerInit.h"

#include "BLSPublicKey.h"
#include "BLSPublicKeyShare.h"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "SEKManager.h"
#include "SGXRegistrationServer.h"
#include "SGXWalletServer.h"
#include "TestUtils.h"
#include "common.h"
#include "sgxwallet.h"
#include "stubclient.h"
#include "testw.h"
#include "third_party/catch.hpp"
#include <algorithm>
#include <limits>
#include <thread>
#include <threshold_encryption/CipheredKey.h>
#include <threshold_encryption/Ciphertext.h>
#include <threshold_encryption/TEDecryptSet.h>
#include <threshold_encryption/TEDecryptionShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/ThresholdEncryption.h>

using namespace jsonrpc;
using namespace std;

namespace {

/**
 * Holds all data from DKG execution
 */
struct RotationDkgData {
  // Each index contains ECDSA key of node index i
  vector<string> ecdsaKeyNames;
  // Each index contains ECDSA key name of node index i
  Json::Value publicEcdsaKeys;
  // Each index contains polynomial name for node index i
  vector<string> polyNames;
  // Each index contains BLS key name for node index i
  vector<string> blsKeyNames;
  // each index contains public shares of node index i, concatenated as hex
  // string public shares are coeff of polynomial * G it follows this format:
  // <coeff1 * G serialized into 4 components> <coeff2 * G serialized into 4
  // components>
  // [hex(a00)||hex(a01)||hex(a02)||hex(a03)]||[hex(a10)||hex(a11)||hex(a12)||hex(a13)]||...
  vector<string> publicShares;
  vector<libBLS::algebra::G2Point> blsPublicKeyShares;
  // Common BLS public key reconstructed from a threshold subset of shares.
  libBLS::algebra::G2Point commonBlsPublicKey;
};

libBLS::algebra::G2Point
blsPublicKeyShareFromResponse(const Json::Value &response) {
  vector<string> pubKeyVect;
  pubKeyVect.reserve(4);
  for (uint8_t i = 0; i < 4; ++i) {
    pubKeyVect.push_back(response["blsPublicKeyShare"][i].asString());
  }
  return libBLS::algebra::G2Point::fromString(pubKeyVect,
                                              libBLS::algebra::Base::DEC);
}

/**
 * @brief Calculate the binomial coefficient "n choose k".
 * @return Number of possible combinations of k elements from a set of n
 * elements.
 */
unsigned long long binomialCoefficient(int n, int k) {
  CHECK_STATE(n >= 0);
  CHECK_STATE(k >= 0);
  CHECK_STATE(k <= n);

  // symmetry (n k) = (n n-k)
  // use least k possible for performance
  if (k > n - k) {
    k = n - k;
  }

  // PROD(i=1 to k) (n-k+i)/i
  unsigned long long result = 1;
  for (int i = 1; i <= k; ++i) {
    const __uint128_t next = static_cast<__uint128_t>(result) *
                             static_cast<unsigned long long>(n - k + i) /
                             static_cast<unsigned long long>(i);
    CHECK_STATE(next <= static_cast<__uint128_t>(
                            numeric_limits<unsigned long long>::max()));
    result = static_cast<unsigned long long>(next);
  }
  return result;
}

/**
 * @brief Given n, k and a rank in the range [0, C(n, k) - 1], return the
 * k-combination corresponding to that rank in lexicographic order.
 */
vector<size_t> unrankCombination(int n, int k, unsigned long long rank) {
  vector<size_t> combination;
  combination.reserve(k);

  // The next selected value must be >= start.
  // This keeps the combination strictly increasing, e.g. [1, 3, 5].
  int start = 0;

  // Build the combination one position at a time.
  //
  // Example for k = 3:
  //   pos = 0 chooses the first element
  //   pos = 1 chooses the second element
  //   pos = 2 chooses the third element
  for (int pos = 0; pos < k; ++pos) {
    // Number of elements still needed, including the current one.
    const int remainingSlots = k - pos;

    // Try every possible value for this position.
    //
    // Upper bound:
    //   value <= n - remainingSlots
    //
    // This guarantees that after choosing `value`, there are still enough
    // larger values left to fill the remaining positions.
    for (int value = start; value <= n - remainingSlots; ++value) {
      // Count how many combinations would exist if we fixed the current
      // position to this candidate `value`.
      //
      // After choosing `value`, we must choose:
      //   remainingSlots - 1
      //
      // elements from the values greater than `value`.
      //
      // Number of values greater than `value` is:
      //   n - value - 1
      //
      // So the block size is:
      //   C(n - value - 1, remainingSlots - 1)
      const unsigned long long count =
          binomialCoefficient(n - value - 1, remainingSlots - 1);

      // If rank is inside this block, then `value` is the correct element
      // for this position.
      if (rank < count) {
        combination.push_back(static_cast<size_t>(value));

        // Next selected value must be greater than the one we just picked.
        start = value + 1;
        break;
      }

      // Otherwise, the desired combination is not in the block starting
      // with this `value`.
      //
      // Skip all combinations in that block and adjust rank relative to
      // the remaining search space.
      rank -= count;
    }
  }

  CHECK_STATE(combination.size() == static_cast<size_t>(k));
  return combination;
}

vector<vector<size_t>> selectedThresholdSubsets(int n, int t,
                                                int coveragePercent) {
  CHECK_STATE(n > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= n);

  if (coveragePercent <= 0) {
    coveragePercent = 1;
  }
  if (coveragePercent > 100) {
    coveragePercent = 100;
  }

  const unsigned long long total = binomialCoefficient(n, t);
  // ceil((total * coveragePercent) / 100)
  unsigned long long selected =
      (total * static_cast<unsigned long long>(coveragePercent) + 99) / 100;
  if (selected == 0) {
    selected = 1;
  }
  if (selected > total) {
    selected = total;
  }

  vector<vector<size_t>> subsets;
  subsets.reserve(static_cast<size_t>(selected));
  for (unsigned long long i = 0; i < selected; ++i) {
    const unsigned long long rank = (i * total) / selected;
    subsets.push_back(unrankCombination(n, t, rank));
  }
  return subsets;
}

/**
 * @brief Reconstruct common BLS public key from threshold of BLS public keys.
 * Works exactly the same for both V2 and V3, since the differences between the
 * global polynomials are already included in the encoding of each individual
 * BLS public key.
 * From this level of execution, both V2 and V3 public BLS keys are P(i)
 * evaluations of some global polynomial. So laggrange interpolation works in
 * both cases
 */
libBLS::algebra::G2Point reconstructCommonPublicKeyV2(
    const vector<libBLS::algebra::G2Point> &publicKeyShares,
    const vector<size_t> &subset, int t, int n) {
  CHECK_STATE(subset.size() >= static_cast<size_t>(t));

  map<size_t, libBLS::BLSPublicKeyShare> publicKeyShareMap;
  for (int i = 0; i < t; ++i) {
    const size_t nodeIndex = subset.at(i);
    vector<string> pubKeyVect = publicKeyShares.at(nodeIndex).toStringVector(
        libBLS::algebra::Base::DEC);
    libBLS::BLSPublicKeyShare pubKey(pubKeyVect, t, n);
    publicKeyShareMap.insert(make_pair(nodeIndex + 1, pubKey));
  }
  // compute BLS public from threshold of shares
  libBLS::BLSPublicKey commonPublicKey(publicKeyShareMap, t, n);
  return commonPublicKey.getPublicKey();
}

/**
 * @brief Helper function that runs a full DKG execution, and outputs:
 *    1. private bls key name for each node
 *    2. polynomial name for each node
 *    3. public shares for each node
 *    4. ecdsa key name for each node
 */
RotationDkgData runDKGV2ForRotation(StubClient &c, int n, int t, int schainID,
                                    int dkgID) {
  RotationDkgData data;
  data.ecdsaKeyNames.resize(n);
  data.polyNames.resize(n);
  data.blsKeyNames.resize(n);
  data.publicShares.resize(n);
  data.blsPublicKeyShares.resize(n);

  vector<Json::Value> ethKeys(n);
  vector<Json::Value> verificationVectors(n);

  // holds node[i]'s secret share for all other nodes
  vector<Json::Value> secretShares(n);

  for (int i = 0; i < n; ++i) {
    ethKeys[i] = c.generateECDSAKey();
    CHECK_STATE(ethKeys[i]["status"] == 0);

    data.ecdsaKeyNames[i] = ethKeys[i]["keyName"].asString();
    CHECK_STATE(data.ecdsaKeyNames[i].size() == ECDSA_KEY_NAME_SIZE);
    data.publicEcdsaKeys.append(ethKeys[i]["publicKey"]);

    data.polyNames[i] = TestUtils::makeDKGPolyName(schainID, i, dkgID);
    Json::Value response = c.generateDKGPoly(data.polyNames[i], t);
    CHECK_STATE(response["status"] == 0);

    verificationVectors[i] = c.getVerificationVector(data.polyNames[i], t);
    CHECK_STATE(verificationVectors[i]["status"] == 0);
    data.publicShares[i] = TestUtils::publicSharesFromVerificationVector(
        verificationVectors[i], t);
  }

  // each secretShares[i] contains all secret shares from node i.
  // encrypted with ECDH shared key between node i and recipient node j, for
  // j=0..n-1, concatenated as hex string.
  for (int contributor = 0; contributor < n; ++contributor) {
    secretShares[contributor] = c.getSecretShareV2(data.polyNames[contributor],
                                                   data.publicEcdsaKeys, t, n);
    CHECK_STATE(secretShares[contributor]["status"] == 0);
  }

  // for node i, hold all secret shares from secretShares[i] (all shares for
  // node i from other nodes)
  vector<string> recipientSecretShares(n);

  for (int contributor = 0; contributor < n; ++contributor) {
    const string contributorShares =
        secretShares[contributor]["secretShare"].asString();
    CHECK_STATE(contributorShares.length() ==
                static_cast<size_t>(n) *
                    TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);

    for (int recipient = 0; recipient < n; ++recipient) {
      const string contribution =
          TestUtils::encryptedDkgSecretContributionForRecipient(
              contributorShares, recipient);
      recipientSecretShares[recipient] += contribution;

      Json::Value verification = c.dkgVerificationV2(
          data.publicShares[contributor], data.ecdsaKeyNames[recipient],
          contribution, t, n, recipient);
      CHECK_STATE(verification["status"] == 0);
      CHECK_STATE(verification["result"].asBool());
    }
  }

  for (int recipient = 0; recipient < n; ++recipient) {
    data.blsKeyNames[recipient] =
        TestUtils::blsNameFromPolyName(data.polyNames[recipient]);
    Json::Value response = c.createBLSPrivateKeyV2(
        data.blsKeyNames[recipient], data.ecdsaKeyNames[recipient],
        data.polyNames[recipient], recipientSecretShares[recipient], t, n);
    CHECK_STATE(response["status"] == 0);

    Json::Value publicKeyResponse =
        c.getBLSPublicKeyShare(data.blsKeyNames[recipient]);
    CHECK_STATE(publicKeyResponse["status"] == 0);
    data.blsPublicKeyShares[recipient] =
        blsPublicKeyShareFromResponse(publicKeyResponse);
  }

  vector<size_t> defaultSubset;
  defaultSubset.reserve(t);
  for (int i = 0; i < t; ++i) {
    defaultSubset.push_back(static_cast<size_t>(i));
  }
  data.commonBlsPublicKey = reconstructCommonPublicKeyV2(
      data.blsPublicKeyShares, defaultSubset, t, n);

  return data;
}

/**
 * @brief Helper function that runs a full DKG V3 execution. Does rotation
 * while keeping the exact same nodes (no node is rotated)
 */
RotationDkgData runDKGV3ForRotation(StubClient &c,
                                    const RotationDkgData &v2Data, int n, int t,
                                    int schainID, int dkgID) {
  RotationDkgData data;
  data.ecdsaKeyNames = v2Data.ecdsaKeyNames;
  data.publicEcdsaKeys = v2Data.publicEcdsaKeys;
  data.polyNames.resize(n);
  data.blsKeyNames.resize(n);
  data.publicShares.resize(n);
  data.blsPublicKeyShares.resize(n);

  vector<Json::Value> verificationVectors(n);
  vector<Json::Value> secretShares(n);

  for (int contributor = 0; contributor < n; ++contributor) {
    data.polyNames[contributor] =
        TestUtils::makeDKGPolyName(schainID, contributor, dkgID);
    // use previous' DKG BLS private key name
    Json::Value response = c.generateDKGPolyV3(
        data.polyNames[contributor], v2Data.blsKeyNames[contributor], t);
    CHECK_STATE(response["status"] == 0);

    // get verification vectors
    verificationVectors[contributor] =
        c.getVerificationVector(data.polyNames[contributor], t);
    CHECK_STATE(verificationVectors[contributor]["status"] == 0);
    data.publicShares[contributor] =
        TestUtils::publicSharesFromVerificationVector(
            verificationVectors[contributor], t);
  }

  for (int contributor = 0; contributor < n; ++contributor) {
    secretShares[contributor] = c.getSecretShareV2(data.polyNames[contributor],
                                                   data.publicEcdsaKeys, t, n);
    CHECK_STATE(secretShares[contributor]["status"] == 0);
  }

  vector<Json::Value> secretContributions(n);
  for (int recipient = 0; recipient < n; ++recipient) {
    secretContributions[recipient] = Json::Value(Json::arrayValue);
  }

  for (int contributor = 0; contributor < n; ++contributor) {
    const string contributorShares =
        secretShares[contributor]["secretShare"].asString();
    CHECK_STATE(contributorShares.length() ==
                static_cast<size_t>(n) *
                    TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);

    for (int recipient = 0; recipient < n; ++recipient) {
      const string contribution =
          TestUtils::encryptedDkgSecretContributionForRecipient(
              contributorShares, recipient);

      Json::Value verification = c.dkgVerificationV2(
          data.publicShares[contributor], data.ecdsaKeyNames[recipient],
          contribution, t, n, recipient);
      CHECK_STATE(verification["status"] == 0);
      CHECK_STATE(verification["result"].asBool());

      Json::Value entry;
      entry["contributorIndex"] = contributor;
      entry["secretShare"] = contribution;
      secretContributions[recipient].append(entry);
    }
  }

  for (int recipient = 0; recipient < n; ++recipient) {
    data.blsKeyNames[recipient] =
        TestUtils::blsNameFromPolyName(data.polyNames[recipient]);
    Json::Value response = c.createBLSPrivateKeyV3(
        data.blsKeyNames[recipient], data.ecdsaKeyNames[recipient],
        data.polyNames[recipient], secretContributions[recipient], t, n);
    CHECK_STATE(response["status"] == 0);

    Json::Value publicKeyResponse =
        c.getBLSPublicKeyShare(data.blsKeyNames[recipient]);
    CHECK_STATE(publicKeyResponse["status"] == 0);
    data.blsPublicKeyShares[recipient] =
        blsPublicKeyShareFromResponse(publicKeyResponse);
  }

  vector<size_t> defaultSubset;
  defaultSubset.reserve(t);
  for (int i = 0; i < t; ++i) {
    defaultSubset.push_back(static_cast<size_t>(i));
  }
  data.commonBlsPublicKey = reconstructCommonPublicKeyV2(
      data.blsPublicKeyShares, defaultSubset, t, n);

  return data;
}

/**
 * @brief Runs DKG V3 rotation, allowing nodes to be rotated out & in
 * @param newCommitteeOldIndices maps each new committee position to the old
 * committee index of the node that takes that position. For example, if
 * newCommitteeOldIndices = [2, 0, 5, 1] means that new node in position 0 is
 * old node 2, new node in position 1 is old node 0, new node in position 2 is
 * old node 5, etc.
 * @param oldN number of nodes in old committee
 * @param newN number of nodes in new committee
 */
RotationDkgData
runDKGV3ForRotationWithNewNodes(StubClient &c, const RotationDkgData &v2Data,
                                const vector<size_t> &newCommitteeOldIndices,
                                int oldN, int newN, int t, int schainID,
                                int dkgID) {
  CHECK_STATE(oldN > 0);
  CHECK_STATE(newN > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= oldN);
  CHECK_STATE(t <= newN);
  CHECK_STATE(newCommitteeOldIndices.size() == static_cast<size_t>(newN));

  RotationDkgData data;
  data.ecdsaKeyNames.resize(newN);
  data.polyNames.resize(newN);
  data.blsKeyNames.resize(newN);
  data.publicShares.resize(newN);
  data.blsPublicKeyShares.resize(newN);

  for (int newPosition = 0; newPosition < newN; ++newPosition) {
    const size_t oldIndex = newCommitteeOldIndices.at(newPosition);
    // Node was part of old committee - reuse ECDSA key.
    if (oldIndex < static_cast<size_t>(oldN)) {
      data.ecdsaKeyNames[newPosition] = v2Data.ecdsaKeyNames.at(oldIndex);
      data.publicEcdsaKeys.append(v2Data.publicEcdsaKeys[(int)oldIndex]);
    }
    // Node is new to the committee - generate ECDSA key.
    else {
      Json::Value ethKey = c.generateECDSAKey();
      CHECK_STATE(ethKey["status"] == 0);
      data.ecdsaKeyNames[newPosition] = ethKey["keyName"].asString();
      CHECK_STATE(data.ecdsaKeyNames[newPosition].size() ==
                  ECDSA_KEY_NAME_SIZE);
      data.publicEcdsaKeys.append(ethKey["publicKey"]);
    }
  }

  const size_t dealerCount = static_cast<size_t>(t);
  vector<string> dealerPolyNames(dealerCount);
  vector<string> dealerPublicShares(dealerCount);
  vector<Json::Value> dealerSecretShares(dealerCount);

  // Dealers are deterministically the first t old committee nodes.
  for (size_t oldDealerIndex = 0; oldDealerIndex < dealerCount;
       ++oldDealerIndex) {
    // generate new polynomial for each dealer
    dealerPolyNames[oldDealerIndex] = TestUtils::makeDKGPolyName(
        schainID, static_cast<int>(oldDealerIndex), dkgID);
    Json::Value response =
        c.generateDKGPolyV3(dealerPolyNames[oldDealerIndex],
                            v2Data.blsKeyNames.at(oldDealerIndex), t);
    CHECK_STATE(response["status"] == 0);

    // get verification vectors
    Json::Value verificationVector =
        c.getVerificationVector(dealerPolyNames[oldDealerIndex], t);
    CHECK_STATE(verificationVector["status"] == 0);
    dealerPublicShares[oldDealerIndex] =
        TestUtils::publicSharesFromVerificationVector(verificationVector, t);

    // get secret contributions from this dealer - using 'newN' number of points
    // one for each new node
    dealerSecretShares[oldDealerIndex] = c.getSecretShareV2(
        dealerPolyNames[oldDealerIndex], data.publicEcdsaKeys, t, newN);
    CHECK_STATE(dealerSecretShares[oldDealerIndex]["status"] == 0);
  }

  vector<Json::Value> secretContributions(newN);
  for (int recipient = 0; recipient < newN; ++recipient) {
    secretContributions[recipient] = Json::Value(Json::arrayValue);
  }

  // Aggregate all secret contributions per each node in new group
  // for each contributor
  for (size_t oldDealerIndex = 0; oldDealerIndex < dealerCount;
       ++oldDealerIndex) {
    // get contributor's secret share (includes all clients)
    const string contributorShares =
        dealerSecretShares[oldDealerIndex]["secretShare"].asString();
    CHECK_STATE(contributorShares.length() ==
                static_cast<size_t>(newN) *
                    TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);

    // for each new node - save the secret contribution from 'oldDealerIndex'
    for (int recipient = 0; recipient < newN; ++recipient) {
      const string contribution =
          TestUtils::encryptedDkgSecretContributionForRecipient(
              contributorShares, recipient);

      Json::Value verification = c.dkgVerificationV2(
          dealerPublicShares[oldDealerIndex], data.ecdsaKeyNames[recipient],
          contribution, t, newN, recipient);
      CHECK_STATE(verification["status"] == 0);
      CHECK_STATE(verification["result"].asBool());

      Json::Value entry;
      entry["contributorIndex"] = static_cast<Json::UInt>(oldDealerIndex);
      entry["secretShare"] = contribution;
      secretContributions[recipient].append(entry);
    }
  }

  for (int recipient = 0; recipient < newN; ++recipient) {
    const size_t nodeLabel = newCommitteeOldIndices.at(recipient);
    // create BLS key name for new node
    const string syntheticPolyName = TestUtils::makeDKGPolyName(
        schainID, static_cast<int>(nodeLabel), dkgID);
    data.blsKeyNames[recipient] =
        TestUtils::blsNameFromPolyName(syntheticPolyName);

    // set polyName for new nodes that contributed as dealers
    string cleanupPolyName;
    if (nodeLabel < static_cast<size_t>(t)) {
      cleanupPolyName = TestUtils::makeDKGPolyName(
          schainID, static_cast<int>(nodeLabel), dkgID);
      data.polyNames[recipient] = cleanupPolyName;
    }

    // new node indices - dont have any polynomial names
    if (nodeLabel >= static_cast<size_t>(oldN)) {
      CHECK_STATE(data.polyNames[recipient].empty());
      CHECK_STATE(cleanupPolyName.empty());
    }

    // merge the secret contributions
    // polyName is empty for new nodes, filled for dealers
    Json::Value response = c.createBLSPrivateKeyV3(
        data.blsKeyNames[recipient], data.ecdsaKeyNames[recipient],
        cleanupPolyName, secretContributions[recipient], t, newN);
    CHECK_STATE(response["status"] == 0);

    Json::Value publicKeyResponse =
        c.getBLSPublicKeyShare(data.blsKeyNames[recipient]);
    CHECK_STATE(publicKeyResponse["status"] == 0);
    data.blsPublicKeyShares[recipient] =
        blsPublicKeyShareFromResponse(publicKeyResponse);
  }

  vector<size_t> defaultSubset;
  defaultSubset.reserve(t);
  for (int i = 0; i < t; ++i) {
    defaultSubset.push_back(static_cast<size_t>(i));
  }
  data.commonBlsPublicKey = reconstructCommonPublicKeyV2(
      data.blsPublicKeyShares, defaultSubset, t, newN);

  return data;
}

vector<vector<uint8_t>> buildRotationPlaintexts(int n, int t,
                                                int ciphertextCount) {
  CHECK_STATE(ciphertextCount > 0);

  vector<vector<uint8_t>> plaintexts;
  plaintexts.reserve(ciphertextCount);
  for (int i = 0; i < ciphertextCount; ++i) {
    string plaintext = "dkg-v2-v3-rotation:" + to_string(n) + ":" +
                       to_string(t) + ":" + to_string(i);
    plaintexts.emplace_back(plaintext.begin(), plaintext.end());
    CHECK_STATE(!plaintexts.back().empty());
  }
  return plaintexts;
}

/**
 * @brief Helper function that collects decryption shares for a given ciphertext
 * from all nodes.
 * @return A 2D vector of hex-encoded decryption shares, indexed by
 * [node][ciphertext].
 */
vector<vector<string>>
collectDecryptionShares(StubClient &c, const vector<string> &blsKeyNames,
                        const vector<libBLS::algebra::G2Point> &publicKeyShares,
                        const vector<libBLS::CipheredKey> &cipheredKeys, int t,
                        int n) {
  vector<vector<string>> sharesByNode(n, vector<string>(cipheredKeys.size()));

  Json::Value publicDecryptionValues;
  publicDecryptionValues["publicDecryptionValues"] =
      Json::Value(Json::arrayValue);

  vector<libBLS::CipheredKey> keysForInput = cipheredKeys;
  vector<string> shareInputs =
      libBLS::CipheredKey::getDecryptionShareInputBatch(keysForInput);
  CHECK_STATE(shareInputs.size() == cipheredKeys.size());

  for (size_t i = 0; i < shareInputs.size(); ++i) {
    publicDecryptionValues["publicDecryptionValues"][(int)i] = shareInputs[i];
  }

  for (int node = 0; node < n; ++node) {
    Json::Value response =
        c.getDecryptionShares(blsKeyNames[node], publicDecryptionValues);
    CHECK_STATE(response["status"] == 0);
    CHECK_STATE(!response.isMember("failedRequests"));
    CHECK_STATE(response["decryptionShares"].isArray());
    CHECK_STATE(response["decryptionShares"].size() == cipheredKeys.size());

    libBLS::TEPublicKeyShare publicKeyShare(publicKeyShares[node], node + 1, t,
                                            n);
    for (Json::ArrayIndex ciphertextIndex = 0;
         ciphertextIndex < response["decryptionShares"].size();
         ++ciphertextIndex) {
      const string shareHex =
          response["decryptionShares"][ciphertextIndex].asString();
      sharesByNode[node][ciphertextIndex] = shareHex;

      libBLS::TEDecryptionShare decryptionShare(shareHex, node + 1);
      libBLS::ThresholdEncryption::validateDecryptionShare(
          cipheredKeys[ciphertextIndex], decryptionShare, publicKeyShare);
    }
  }

  return sharesByNode;
}

void assertMixedV2V3SharesFail(const vector<libBLS::Ciphertext> &ciphertexts,
                               const vector<vector<uint8_t>> &plaintexts,
                               const vector<libBLS::CipheredKey> &cipheredKeys,
                               const vector<vector<string>> &v2DecryptionShares,
                               const vector<vector<string>> &v3DecryptionShares,
                               const vector<vector<size_t>> &selectedSubsets,
                               const libBLS::TEPublicKey &commonPublicKey,
                               int t, int n) {
  if (t < 2 || selectedSubsets.empty()) {
    return;
  }

  const vector<size_t> &subset = selectedSubsets.front();
  libBLS::TEDecryptSet mixedDecryptSet(t, n);

  for (int i = 0; i < t - 1; ++i) {
    const size_t node = subset.at(i);
    mixedDecryptSet.addDecryptShare(
        libBLS::TEDecryptionShare(v3DecryptionShares[node][0], node + 1));
  }

  const size_t v2Node = subset.at(t - 1);
  mixedDecryptSet.addDecryptShare(
      libBLS::TEDecryptionShare(v2DecryptionShares[v2Node][0], v2Node + 1));

  bool failed = false;
  try {
    libBLS::AES256Key aesKey = libBLS::ThresholdEncryption::combineShares(
        cipheredKeys[0], mixedDecryptSet);
    vector<uint8_t> decrypted = libBLS::ThresholdEncryption::validateAndDecrypt(
        ciphertexts[0], aesKey, commonPublicKey);
    failed = (decrypted != plaintexts[0]);
  } catch (...) {
    failed = true;
  }

  CHECK_STATE(failed);
}

struct DecryptionShareRef {
  string shareHex;
  size_t signerIndex;
};

vector<size_t> buildCommitteeRotatingLastNodes(int oldN, int newN,
                                               int rotatedCount) {
  CHECK_STATE(oldN > 0);
  CHECK_STATE(newN > 0);
  CHECK_STATE(rotatedCount > 0);
  CHECK_STATE(rotatedCount < oldN);
  CHECK_STATE(rotatedCount < newN);

  const int retainedCount = newN - rotatedCount;
  CHECK_STATE(retainedCount > 0);
  CHECK_STATE(retainedCount <= oldN);

  vector<size_t> newCommitteeOldIndices;
  newCommitteeOldIndices.reserve(newN);
  for (int retained = 0; retained < retainedCount; ++retained) {
    newCommitteeOldIndices.push_back(static_cast<size_t>(retained));
  }
  for (int joining = 0; joining < rotatedCount; ++joining) {
    newCommitteeOldIndices.push_back(static_cast<size_t>(oldN + joining));
  }
  CHECK_STATE(newCommitteeOldIndices.size() == static_cast<size_t>(newN));
  return newCommitteeOldIndices;
}

vector<size_t> buildCommitteeRotatingFirstNodes(int n, int rotatedCount) {
  CHECK_STATE(n > 0);
  CHECK_STATE(rotatedCount > 0);
  CHECK_STATE(rotatedCount < n);

  vector<size_t> newCommitteeOldIndices;
  newCommitteeOldIndices.reserve(n);
  for (int retained = rotatedCount; retained < n; ++retained) {
    newCommitteeOldIndices.push_back(static_cast<size_t>(retained));
  }
  for (int joining = 0; joining < rotatedCount; ++joining) {
    newCommitteeOldIndices.push_back(static_cast<size_t>(n + joining));
  }
  CHECK_STATE(newCommitteeOldIndices.size() == static_cast<size_t>(n));
  return newCommitteeOldIndices;
}

vector<size_t> firstThresholdNodes(int t) {
  CHECK_STATE(t > 0);

  vector<size_t> nodes;
  nodes.reserve(static_cast<size_t>(t));
  for (int node = 0; node < t; ++node) {
    nodes.push_back(static_cast<size_t>(node));
  }
  return nodes;
}

vector<size_t> retiredLastNodes(int n, int rotatedCount) {
  CHECK_STATE(n > 0);
  CHECK_STATE(rotatedCount > 0);
  CHECK_STATE(rotatedCount < n);

  vector<size_t> nodes;
  nodes.reserve(static_cast<size_t>(rotatedCount));
  for (int node = n - rotatedCount; node < n; ++node) {
    nodes.push_back(static_cast<size_t>(node));
  }
  return nodes;
}

vector<size_t> retiredFirstNodes(int rotatedCount) {
  CHECK_STATE(rotatedCount > 0);

  vector<size_t> nodes;
  nodes.reserve(static_cast<size_t>(rotatedCount));
  for (int node = 0; node < rotatedCount; ++node) {
    nodes.push_back(static_cast<size_t>(node));
  }
  return nodes;
}

vector<size_t> respondingNodes(int n, int nonRespondingCount) {
  CHECK_STATE(n > 0);
  CHECK_STATE(nonRespondingCount >= 0);
  CHECK_STATE(nonRespondingCount < n);

  vector<size_t> nodes;
  nodes.reserve(static_cast<size_t>(n - nonRespondingCount));
  for (int node = nonRespondingCount; node < n; ++node) {
    nodes.push_back(static_cast<size_t>(node));
  }
  return nodes;
}

void encryptRotationPayload(
    int n, int t, int ciphertextCount,
    const libBLS::TEPublicKey &thresholdEncryptionPublicKey,
    vector<vector<uint8_t>> &plaintexts,
    vector<libBLS::Ciphertext> &ciphertexts,
    vector<libBLS::CipheredKey> &cipheredKeys) {
  plaintexts = buildRotationPlaintexts(n, t, ciphertextCount);

  ciphertexts.clear();
  cipheredKeys.clear();
  ciphertexts.reserve(plaintexts.size());
  cipheredKeys.reserve(plaintexts.size());

  for (const auto &plaintext : plaintexts) {
    libBLS::Ciphertext ciphertext = libBLS::ThresholdEncryption::encrypt(
        plaintext, thresholdEncryptionPublicKey);
    CHECK_STATE(ciphertext.getKeys().size() == 1);
    cipheredKeys.push_back(ciphertext.getTargetKey());
    ciphertexts.push_back(ciphertext);
  }

  vector<bool> encryptionValidation =
      libBLS::ThresholdEncryption::validateEncryptionBatch(cipheredKeys);
  CHECK_STATE(encryptionValidation.size() == cipheredKeys.size());
  for (bool isValid : encryptionValidation) {
    CHECK_STATE(isValid);
  }
}

vector<DecryptionShareRef>
shareRefsFromNodes(const vector<vector<string>> &decryptionShares,
                   const vector<size_t> &nodes, size_t ciphertextIndex) {
  vector<DecryptionShareRef> refs;
  refs.reserve(nodes.size());
  for (size_t node : nodes) {
    refs.push_back({decryptionShares.at(node).at(ciphertextIndex), node + 1});
  }
  return refs;
}

bool shareRefsDecryptToPlaintext(
    const vector<libBLS::Ciphertext> &ciphertexts,
    const vector<vector<uint8_t>> &plaintexts,
    const vector<libBLS::CipheredKey> &cipheredKeys,
    const vector<DecryptionShareRef> &shareRefs,
    const libBLS::TEPublicKey &commonPublicKey, int t, int n,
    size_t ciphertextIndex = 0) {
  CHECK_STATE(ciphertextIndex < ciphertexts.size());
  CHECK_STATE(ciphertextIndex < plaintexts.size());
  CHECK_STATE(ciphertextIndex < cipheredKeys.size());

  try {
    libBLS::TEDecryptSet decryptSet(t, n);
    for (const auto &shareRef : shareRefs) {
      decryptSet.addDecryptShare(
          libBLS::TEDecryptionShare(shareRef.shareHex, shareRef.signerIndex));
    }

    libBLS::AES256Key aesKey = libBLS::ThresholdEncryption::combineShares(
        cipheredKeys[ciphertextIndex], decryptSet);
    vector<uint8_t> decrypted = libBLS::ThresholdEncryption::validateAndDecrypt(
        ciphertexts[ciphertextIndex], aesKey, commonPublicKey);
    return decrypted == plaintexts[ciphertextIndex];
  } catch (...) {
    return false;
  }
}

void assertShareRefsDecrypt(const vector<libBLS::Ciphertext> &ciphertexts,
                            const vector<vector<uint8_t>> &plaintexts,
                            const vector<libBLS::CipheredKey> &cipheredKeys,
                            const vector<DecryptionShareRef> &shareRefs,
                            const libBLS::TEPublicKey &commonPublicKey, int t,
                            int n) {
  CHECK_STATE(shareRefsDecryptToPlaintext(ciphertexts, plaintexts, cipheredKeys,
                                          shareRefs, commonPublicKey, t, n));
}

void assertShareRefsFail(const vector<libBLS::Ciphertext> &ciphertexts,
                         const vector<vector<uint8_t>> &plaintexts,
                         const vector<libBLS::CipheredKey> &cipheredKeys,
                         const vector<DecryptionShareRef> &shareRefs,
                         const libBLS::TEPublicKey &commonPublicKey, int t,
                         int n) {
  CHECK_STATE(!shareRefsDecryptToPlaintext(
      ciphertexts, plaintexts, cipheredKeys, shareRefs, commonPublicKey, t, n));
}

vector<size_t> takeFirstNodes(const vector<size_t> &nodes, int count) {
  CHECK_STATE(count >= 0);
  CHECK_STATE(static_cast<size_t>(count) <= nodes.size());
  return vector<size_t>(nodes.begin(), nodes.begin() + count);
}

} // namespace

default_random_engine TestUtils::randGen((unsigned int)time(0));

string TestUtils::stringFromFr(libBLS::algebra::FrScalar &el,
                               libBLS::algebra::Base base) {
  return el.toString(base);
}

string TestUtils::convertDecToHex(string dec, int numBytes) {
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

string TestUtils::makeDKGPolyName(int schainID, int nodeID, int dkgID) {
  return "POLY:SCHAIN_ID:" + to_string(schainID) +
         ":NODE_ID:" + to_string(nodeID) + ":DKG_ID:" + to_string(dkgID);
}

string TestUtils::makeBLSKeyName(int schainID, int nodeID, int dkgID) {
  return "BLS_KEY:SCHAIN_ID:" + to_string(schainID) +
         ":NODE_ID:" + to_string(nodeID) + ":DKG_ID:" + to_string(dkgID);
}

string TestUtils::blsNameFromPolyName(const string &polyName) {
  return "BLS_KEY" + polyName.substr(4);
}

string TestUtils::publicSharesFromVerificationVector(
    const Json::Value &verificationVectorResponse, int t) {
  CHECK_STATE(t > 0);

  const bool hasWrappedVerificationVector =
      verificationVectorResponse.isObject() &&
      verificationVectorResponse.isMember("verificationVector");
  const Json::Value &verificationVector =
      hasWrappedVerificationVector
          ? verificationVectorResponse["verificationVector"]
          : verificationVectorResponse;

  CHECK_STATE(verificationVector.isArray());
  CHECK_STATE(verificationVector.size() == static_cast<Json::ArrayIndex>(t));

  // Example (t=2):
  // [[a00,a01,a02,a03], [a10,a11,a12,a13]] as decimal strings becomes
  // hex(a00)||hex(a01)||...||hex(a13), each coordinate padded to 32 bytes.
  string publicShares;
  for (int coeff = 0; coeff < t; ++coeff) {
    CHECK_STATE(verificationVector[coeff].isArray());
    CHECK_STATE(verificationVector[coeff].size() == 4);
    for (int coord = 0; coord < 4; ++coord) {
      const string publicShare = verificationVector[coeff][coord].asString();
      CHECK_STATE(publicShare.length() > 60);
      publicShares += TestUtils::convertDecToHex(publicShare);
    }
  }
  return publicShares;
}

string TestUtils::encryptedDkgSecretContributionForRecipient(
    const string &secretShares, int recipientIndex) {
  CHECK_STATE(recipientIndex >= 0);
  const size_t offset =
      TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN * recipientIndex;
  CHECK_STATE(secretShares.length() >=
              offset + TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);
  return secretShares.substr(
      offset, TestUtils::DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN);
}

Json::Value TestUtils::dkgV3SecretContributionsForRecipient(
    const vector<string> &dealerSecretShares, int recipientIndex) {
  Json::Value secretContributions(Json::arrayValue);
  for (size_t contributor = 0; contributor < dealerSecretShares.size();
       ++contributor) {
    Json::Value entry;
    entry["contributorIndex"] = static_cast<Json::UInt>(contributor);
    entry["secretShare"] =
        TestUtils::encryptedDkgSecretContributionForRecipient(
            dealerSecretShares[contributor], recipientIndex);
    secretContributions.append(entry);
  }
  return secretContributions;
}

void TestUtils::resetDB() {
  CHECK_STATE(system("bash -c \"rm -rf " SGXDATA_FOLDER "* \"") == 0);
}

shared_ptr<string> TestUtils::encryptTestKey() {
  const char *key = TEST_BLS_KEY_SHARE;
  int errStatus = -1;
  vector<char> errMsg(BUF_LEN, 0);
  ;
  string encryptedKeyHex =
      encryptBLSKeyShare2Hex(&errStatus, errMsg.data(), key);

  CHECK_STATE(!encryptedKeyHex.empty());
  CHECK_STATE(errStatus == 0);

  return make_shared<string>(encryptedKeyHex);
}

vector<libBLS::algebra::FrScalar>
TestUtils::splitStringToFr(const char *coeffs, const char symbol) {
  string str(coeffs);
  string delim;
  delim.push_back(symbol);
  vector<libBLS::algebra::FrScalar> tokens;
  size_t prev = 0, pos = 0;
  do {
    pos = str.find(delim, prev);
    if (pos == string::npos)
      pos = str.length();
    string token = str.substr(prev, pos - prev);
    if (!token.empty()) {
      libBLS::algebra::FrScalar coeff(libBLS::algebra::FrScalar::fromString(
          token, libBLS::algebra::Base::DEC));
      tokens.push_back(coeff);
    }
    prev = pos + delim.length();
  } while (pos < str.length() && prev < str.length());

  return tokens;
}

vector<string> TestUtils::splitStringTest(const char *coeffs,
                                          const char symbol) {
  string str(coeffs);
  string delim;
  delim.push_back(symbol);
  vector<string> g2Strings;
  size_t prev = 0, pos = 0;
  do {
    pos = str.find(delim, prev);
    if (pos == string::npos)
      pos = str.length();
    string token = str.substr(prev, pos - prev);
    if (!token.empty()) {
      string coeff(token.c_str());
      g2Strings.push_back(coeff);
    }
    prev = pos + delim.length();
  } while (pos < str.length() && prev < str.length());

  return g2Strings;
}

libBLS::algebra::G2Point
TestUtils::vectStringToG2(const vector<string> &G2_str_vect) {
  libBLS::algebra::G2Point coeff = libBLS::algebra::G2Point::identity();
  coeff.setZC0(libBLS::algebra::FqElement::one());
  coeff.setZC1(libBLS::algebra::FqElement::zero());

  coeff.setXC0(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(0), libBLS::algebra::Base::DEC));
  coeff.setXC1(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(1), libBLS::algebra::Base::DEC));
  coeff.setYC0(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(2), libBLS::algebra::Base::DEC));
  coeff.setYC1(libBLS::algebra::FqElement::fromString(
      G2_str_vect.at(3), libBLS::algebra::Base::DEC));

  return coeff;
}

void TestUtils::sendRPCRequest() {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int n = 16, t = 16;
  Json::Value ethKeys[n];
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  Json::Value secretShares[n];
  Json::Value pubBLSKeys[n];
  Json::Value blsSigShares[n];
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  static atomic<int> counter(1);

  int schainID = counter.fetch_add(1);
  int dkgID = counter.fetch_add(1);

  int testCount = 1;

  if (getenv("NIGHTLY_TESTS")) {
    testCount = 10;
  }

  for (uint8_t i = 0; i < n; i++) {
    usleep(100000);
    ethKeys[i] = c.generateECDSAKey();

    for (int i2 = 0; i2 < testCount; i2++) {
      auto keyName = ethKeys[i]["keyName"].asString();
      Json::Value sig = c.ecdsaSignMessageHash(16, keyName, SAMPLE_HASH);
      CHECK_STATE(sig["status"].asInt() == 0);
    }

    CHECK_STATE(ethKeys[i]["status"] == 0);
    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);
    auto response = c.generateDKGPoly(polyName, t);
    CHECK_STATE(response["status"] == 0);
    polyNames[i] = polyName;

    for (int i3 = 0; i3 <= testCount; i3++) {
      verifVects[i] = c.getVerificationVector(polyName, t);
      CHECK_STATE(verifVects[i]["status"] == 0);
    }

    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    usleep(100000);
    for (int i4 = 0; i4 <= testCount; i4++) {
      secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
    }
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        pubShares[i] += convertDecToHex(pubShare);
      }
    }
  }

  vector<string> secShares(n);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      usleep(100000);
      for (int i5 = 0; i5 <= testCount; i5++) {
        Json::Value verif =
            c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(),
                              secretShare, t, n, j);
        CHECK_STATE(verif["status"] == 0);
      }
    }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  auto hash_arr = make_shared<array<uint8_t, 32>>();
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, shared_ptr<libBLS::BLSPublicKeyShare>> coeffs_pkeys_map;

  Json::Value publicShares;
  for (int i = 0; i < n; ++i) {
    publicShares["publicShares"][i] = pubShares[i];
  }

  Json::Value blsPublicKeys;

  for (int i6 = 0; i6 <= testCount; i6++) {
    blsPublicKeys = c.calculateAllBLSPublicKeys(publicShares, t, n);
    CHECK_STATE(blsPublicKeys["status"] == 0);
  }

  for (int i = 0; i < t; i++) {
    string endName = polyNames[i].substr(4);
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    string secretShare = secretShares[i]["secretShare"].asString();

    auto response =
        c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(),
                              polyNames[i], secShares[i], t, n);
    CHECK_STATE(response["status"] == 0);

    for (int i7 = 0; i7 <= testCount; i7++) {
      pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
    }
    CHECK_STATE(pubBLSKeys[i]["status"] == 0);

    // Use G2Point::fromString with vector of decimal strings
    std::vector<std::string> pubKeyVec = {
        pubBLSKeys[i]["blsPublicKeyShare"][0].asString(),
        pubBLSKeys[i]["blsPublicKeyShare"][1].asString(),
        pubBLSKeys[i]["blsPublicKeyShare"][2].asString(),
        pubBLSKeys[i]["blsPublicKeyShare"][3].asString()};
    libBLS::algebra::G2Point publicKey = libBLS::algebra::G2Point::fromString(
        pubKeyVec, libBLS::algebra::Base::DEC);

    string public_key_str = convertG2ToString(publicKey);

    CHECK_STATE(public_key_str == blsPublicKeys["publicKeys"][i].asString());

    string hash = SAMPLE_HASH;
    blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
    CHECK_STATE(blsSigShares[i]["status"] == 0);

    string sig_share_ptr = blsSigShares[i]["signatureShare"].asString();
    libBLS::BLSSigShare sig(sig_share_ptr, i + 1, t, n);
    sigShareSet.addSigShare(sig);
  }

  sigShareSet.merge();
}

void TestUtils::sendRPCRequestV2() {
  HttpClient client(RPC_ENDPOINT);
  StubClient c(client, JSONRPC_CLIENT_V2);

  int n = 16, t = 16;
  Json::Value ethKeys[n];
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  Json::Value secretShares[n];
  Json::Value pubBLSKeys[n];
  Json::Value blsSigShares[n];
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  static atomic<int> counter(1);

  int schainID = counter.fetch_add(1);
  int dkgID = counter.fetch_add(1);
  for (uint8_t i = 0; i < n; i++) {
    ethKeys[i] = c.generateECDSAKey();
    CHECK_STATE(ethKeys[i]["status"] == 0);
    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);
    auto response = c.generateDKGPoly(polyName, t);
    CHECK_STATE(response["status"] == 0);
    polyNames[i] = polyName;
    verifVects[i] = c.getVerificationVector(polyName, t);
    CHECK_STATE(verifVects[i]["status"] == 0);

    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = c.getSecretShareV2(polyNames[i], pubEthKeys, t, n);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        pubShares[i] += convertDecToHex(pubShare);
      }
    }
  }

  vector<string> secShares(n);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      Json::Value verif = c.dkgVerificationV2(
          pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
      CHECK_STATE(verif["status"] == 0);
    }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  auto hash_arr = make_shared<array<uint8_t, 32>>();
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, shared_ptr<libBLS::BLSPublicKeyShare>> coeffs_pkeys_map;

  Json::Value publicShares;
  for (int i = 0; i < n; ++i) {
    publicShares["publicShares"][i] = pubShares[i];
  }

  Json::Value blsPublicKeys = c.calculateAllBLSPublicKeys(publicShares, t, n);
  CHECK_STATE(blsPublicKeys["status"] == 0);

  for (int i = 0; i < t; i++) {
    string endName = polyNames[i].substr(4);
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    string secretShare = secretShares[i]["secretShare"].asString();

    auto response =
        c.createBLSPrivateKeyV2(blsName, ethKeys[i]["keyName"].asString(),
                                polyNames[i], secShares[i], t, n);
    CHECK_STATE(response["status"] == 0);
    pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
    CHECK_STATE(pubBLSKeys[i]["status"] == 0);

    // Use G2Point::fromString with colon-delimited decimal string
    string pubKeyStr = pubBLSKeys[i]["blsPublicKeyShare"][0].asString() + ":" +
                       pubBLSKeys[i]["blsPublicKeyShare"][1].asString() + ":" +
                       pubBLSKeys[i]["blsPublicKeyShare"][2].asString() + ":" +
                       pubBLSKeys[i]["blsPublicKeyShare"][3].asString();
    libBLS::algebra::G2Point publicKey = libBLS::algebra::G2Point::fromString(
        pubKeyStr, libBLS::algebra::Base::DEC);

    string public_key_str = convertG2ToString(publicKey);

    CHECK_STATE(public_key_str == blsPublicKeys["publicKeys"][i].asString());

    string hash = SAMPLE_HASH;
    blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
    CHECK_STATE(blsSigShares[i]["status"] == 0);

    string sig_share_ptr = blsSigShares[i]["signatureShare"].asString();
    libBLS::BLSSigShare sig(sig_share_ptr, i + 1, t, n);
    sigShareSet.addSigShare(sig);
  }

  sigShareSet.merge();
}

void TestUtils::sendRPCRequestZMQ() {
  auto client = make_shared<ZMQClient>(ZMQ_IP, ZMQ_PORT, true,
                                       "./sgx_data/cert_data/rootCA.pem",
                                       "./sgx_data/cert_data/rootCA.key");

  int n = 16, t = 16;
  vector<string> ethKeys(n);
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  vector<string> secretShares(n);
  Json::Value pubBLSKeys[n];
  vector<string> blsSigShares(n);
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  static atomic<int> counter(1);

  int schainID = counter.fetch_add(1);
  int dkgID = counter.fetch_add(1);
  for (uint8_t i = 0; i < n; i++) {
    auto generatedKey = client->generateECDSAKey();
    ethKeys[i] = generatedKey.second;
    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);
    CHECK_STATE(client->generateDKGPoly(polyName, t));
    polyNames[i] = polyName;
    verifVects[i] = client->getVerificationVector(polyName, t);

    pubEthKeys.append(generatedKey.first);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = client->getSecretShare(polyNames[i], pubEthKeys, t, n);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i][k][j].asString();
        pubShares[i] += convertDecToHex(pubShare);
      }
    }
  }

  vector<string> secShares(n);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare = secretShares[i].substr(192 * j, 192);
      secShares[i] += secretShares[j].substr(192 * i, 192);
      bool verif = client->dkgVerification(pubShares[i], ethKeys[j],
                                           secretShare, t, n, j);
      CHECK_STATE(verif);
    }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  auto hash_arr = make_shared<array<uint8_t, 32>>();
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, shared_ptr<libBLS::BLSPublicKeyShare>> coeffs_pkeys_map;

  Json::Value publicShares;
  for (int i = 0; i < n; ++i) {
    publicShares["publicShares"][i] = pubShares[i];
  }

  Json::Value blsPublicKeys = client->getAllBlsPublicKeys(publicShares, t, n);

  for (int i = 0; i < t; i++) {
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    string secretShare = secretShares[i];

    CHECK_STATE(client->createBLSPrivateKey(blsName, ethKeys[i], polyNames[i],
                                            secShares[i], t, n));
    pubBLSKeys[i] = client->getBLSPublicKey(blsName);

    // Use G2Point::fromString with colon-delimited decimal string
    string pubKeyStr =
        pubBLSKeys[i][0].asString() + ":" + pubBLSKeys[i][1].asString() + ":" +
        pubBLSKeys[i][2].asString() + ":" + pubBLSKeys[i][3].asString();
    libBLS::algebra::G2Point publicKey = libBLS::algebra::G2Point::fromString(
        pubKeyStr, libBLS::algebra::Base::DEC);

    string public_key_str = convertG2ToString(publicKey);

    CHECK_STATE(public_key_str == blsPublicKeys[i].asString());

    string hash = SAMPLE_HASH;
    blsSigShares[i] = client->blsSignMessageHash(blsName, hash, t, n);
    CHECK_STATE(blsSigShares[i].length() > 0);

    libBLS::BLSSigShare sig(blsSigShares[i], i + 1, t, n);
    sigShareSet.addSigShare(sig);
  }

  sigShareSet.merge();
}

void TestUtils::destroyEnclave() {
  if (eid != 0) {
    sgx_destroy_enclave(eid);
    eid = 0;
  }
}

void TestUtils::doDKG(StubClient &c, int n, int t,
                      vector<string> &_ecdsaKeyNames,
                      vector<string> &_blsKeyNames, int schainID, int dkgID) {
  Json::Value ethKeys[n];
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  Json::Value secretShares[n];
  Json::Value pubBLSKeys[n];
  Json::Value blsSigShares[n];
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  _ecdsaKeyNames.clear();
  _blsKeyNames.clear();

  for (uint8_t i = 0; i < n; i++) {
    ethKeys[i] = c.generateECDSAKey();

    CHECK_STATE(ethKeys[i]["status"] == 0);

    auto keyName = ethKeys[i]["keyName"].asString();
    CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);

    _ecdsaKeyNames.push_back(keyName);

    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);

    Json::Value response = c.generateDKGPoly(polyName, t);
    CHECK_STATE(response["status"] == 0);
    polyNames[i] = polyName;
    verifVects[i] = c.getVerificationVector(polyName, t);
    CHECK_STATE(verifVects[i]["status"] == 0);
    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
    CHECK_STATE(secretShares[i]["status"] == 0);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        CHECK_STATE(pubShare.length() > 60);
        pubShares[i] += TestUtils::convertDecToHex(pubShare);
      }
    }
  }

  int k = 0;

  vector<string> secShares(n);

  vector<string> pSharesBad(pubShares);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      Json::Value response = c.dkgVerification(
          pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
      CHECK_STATE(response["status"] == 0);

      bool res = response["result"].asBool();
      CHECK_STATE(res);

      k++;

      pSharesBad[i][0] = 'q';
      Json::Value wrongVerif =
          c.dkgVerification(pSharesBad[i], ethKeys[j]["keyName"].asString(),
                            secretShare, t, n, j);
      res = wrongVerif["result"].asBool();
      CHECK_STATE(!res);
    }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  auto hash_arr = make_shared<array<uint8_t, 32>>();
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hash_arr->data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, libBLS::BLSPublicKeyShare> pubKeyShares;

  for (int i = 0; i < n; i++) {
    string endName = polyNames[i].substr(4);
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    _blsKeyNames.push_back(blsName);
    string secretShare = secretShares[i]["secretShare"].asString();

    auto response =
        c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(),
                              polyNames[i], secShares[i], t, n);
    CHECK_STATE(response["status"] == 0);
    pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
    CHECK_STATE(pubBLSKeys[i]["status"] == 0);
  }

  for (int i = 0; i < t; i++) {
    vector<string> pubKeyVect;
    for (uint8_t j = 0; j < 4; j++) {
      pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
    }
    libBLS::BLSPublicKeyShare pubKey(pubKeyVect, t, n);

    pubKeyShares.insert(std::make_pair(i + 1, pubKey));
  }

  // create pub key

  libBLS::BLSPublicKey blsPublicKey(pubKeyShares, t, n);

  // sign verify a sample sig

  for (int i = 0; i < t; i++) {

    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
    CHECK_STATE(blsSigShares[i]["status"] == 0);
    string sig_share = blsSigShares[i]["signatureShare"].asString();
    libBLS::BLSSigShare sig(sig_share, i + 1, t, n);
    sigShareSet.addSigShare(sig);

    auto pubKey = pubKeyShares.at(i + 1);

    CHECK_STATE(pubKey.VerifySigWithHelper(*hash_arr, sig, t, n));
  }

  libBLS::BLSSignature commonSig = sigShareSet.merge();

  CHECK_STATE(blsPublicKey.VerifySigWithHelper(*hash_arr, commonSig));

  for (auto &&i : _ecdsaKeyNames)
    cerr << i << endl;

  for (auto &&i : _blsKeyNames)
    cerr << i << endl;
}

void TestUtils::doDKGV2(StubClient &c, int n, int t,
                        vector<string> &_ecdsaKeyNames,
                        vector<string> &_blsKeyNames, int schainID, int dkgID) {
  Json::Value ethKeys[n];
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  Json::Value secretShares[n];
  Json::Value pubBLSKeys[n];
  Json::Value blsSigShares[n];
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  _ecdsaKeyNames.clear();
  _blsKeyNames.clear();

  for (uint8_t i = 0; i < n; i++) {
    ethKeys[i] = c.generateECDSAKey();

    CHECK_STATE(ethKeys[i]["status"] == 0);

    auto keyName = ethKeys[i]["keyName"].asString();
    CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);

    _ecdsaKeyNames.push_back(keyName);

    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);

    Json::Value response = c.generateDKGPoly(polyName, t);
    CHECK_STATE(response["status"] == 0);
    polyNames[i] = polyName;
    verifVects[i] = c.getVerificationVector(polyName, t);
    CHECK_STATE(verifVects[i]["status"] == 0);
    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = c.getSecretShareV2(polyNames[i], pubEthKeys, t, n);
    CHECK_STATE(secretShares[i]["status"] == 0);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        CHECK_STATE(pubShare.length() > 60);
        pubShares[i] += TestUtils::convertDecToHex(pubShare);
      }
    }
  }

  int k = 0;

  vector<string> secShares(n);

  vector<string> pSharesBad(pubShares);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      Json::Value response = c.dkgVerificationV2(
          pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
      CHECK_STATE(response["status"] == 0);

      bool res = response["result"].asBool();
      CHECK_STATE(res);

      k++;

      pSharesBad[i][0] = 'q';
      Json::Value wrongVerif =
          c.dkgVerificationV2(pSharesBad[i], ethKeys[j]["keyName"].asString(),
                              secretShare, t, n, j);
      res = wrongVerif["result"].asBool();
      CHECK_STATE(!res);
    }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  array<uint8_t, 32> hashArr;
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hashArr.data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, libBLS::BLSPublicKeyShare> pubKeyShares;

  for (int i = 0; i < n; i++) {
    string endName = polyNames[i].substr(4);
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    _blsKeyNames.push_back(blsName);
    string secretShare = secretShares[i]["secretShare"].asString();

    auto response =
        c.createBLSPrivateKeyV2(blsName, ethKeys[i]["keyName"].asString(),
                                polyNames[i], secShares[i], t, n);
    CHECK_STATE(response["status"] == 0);
    pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
    CHECK_STATE(pubBLSKeys[i]["status"] == 0);
  }

  for (int i = 0; i < t; i++) {
    vector<string> pubKeyVect;
    for (uint8_t j = 0; j < 4; j++) {
      pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
    }
    libBLS::BLSPublicKeyShare pubKey(pubKeyVect, t, n);

    pubKeyShares.insert(std::make_pair(i + 1, pubKey));
  }

  // create pub key

  libBLS::BLSPublicKey blsPublicKey(pubKeyShares, t, n);

  // sign verify a sample sig

  for (int i = 0; i < t; i++) {

    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n);
    CHECK_STATE(blsSigShares[i]["status"] == 0);
    string sig_share = blsSigShares[i]["signatureShare"].asString();
    libBLS::BLSSigShare sig(sig_share, i + 1, t, n);
    sigShareSet.addSigShare(sig);

    auto pubKey = pubKeyShares.at(i + 1);

    CHECK_STATE(pubKey.VerifySigWithHelper(hashArr, sig, t, n));
  }

  libBLS::BLSSignature commonSig = sigShareSet.merge();

  CHECK_STATE(blsPublicKey.VerifySigWithHelper(hashArr, commonSig));

  for (auto &&i : _ecdsaKeyNames)
    cerr << i << endl;

  for (auto &&i : _blsKeyNames)
    cerr << i << endl;
}

void TestUtils::doDKGV3Rotation(StubClient &c, int n, int t, int schainID,
                                int dkgV2ID, int dkgV3ID, int coveragePercent,
                                int ciphertextCount) {
  CHECK_STATE(n > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= n);
  CHECK_STATE(n <= 32);
  CHECK_STATE(ciphertextCount > 0);

  // run DKGV2 to get initial keys and set up for rotation
  RotationDkgData v2Data = runDKGV2ForRotation(c, n, t, schainID, dkgV2ID);
  CHECK_STATE(v2Data.blsKeyNames.size() == static_cast<size_t>(n));
  CHECK_STATE(v2Data.blsPublicKeyShares.size() == static_cast<size_t>(n));

  // select subset based on t, n, and % of possible covered threshold sets
  vector<vector<size_t>> selectedSubsets =
      selectedThresholdSubsets(n, t, coveragePercent);
  CHECK_STATE(!selectedSubsets.empty());

  const libBLS::algebra::G2Point v2CommonPublicKey = v2Data.commonBlsPublicKey;
  libBLS::TEPublicKey thresholdEncryptionPublicKey(v2CommonPublicKey);

  // get 'ciphertextCount' plaintexts. n & t used for plaintext naming only
  vector<vector<uint8_t>> plaintexts =
      buildRotationPlaintexts(n, t, ciphertextCount);
  // holds ciphertexts encrypted with common public key from DKGV2
  vector<libBLS::Ciphertext> ciphertexts;
  vector<libBLS::CipheredKey> cipheredKeys;
  ciphertexts.reserve(plaintexts.size());
  cipheredKeys.reserve(plaintexts.size());

  // encrypt ciphertexts using key from DKGV2
  for (const auto &plaintext : plaintexts) {
    libBLS::Ciphertext ciphertext = libBLS::ThresholdEncryption::encrypt(
        plaintext, thresholdEncryptionPublicKey);
    CHECK_STATE(ciphertext.getKeys().size() == 1);
    cipheredKeys.push_back(ciphertext.getTargetKey());
    ciphertexts.push_back(ciphertext);
  }

  // validate encryption
  vector<bool> encryptionValidation =
      libBLS::ThresholdEncryption::validateEncryptionBatch(cipheredKeys);
  CHECK_STATE(encryptionValidation.size() == cipheredKeys.size());
  for (bool isValid : encryptionValidation) {
    CHECK_STATE(isValid);
  }

  // rotate
  RotationDkgData v3Data =
      runDKGV3ForRotation(c, v2Data, n, t, schainID, dkgV3ID);
  CHECK_STATE(v3Data.blsKeyNames.size() == static_cast<size_t>(n));
  CHECK_STATE(v3Data.blsPublicKeyShares.size() == static_cast<size_t>(n));
  // common public should stay the same
  CHECK_STATE(v3Data.commonBlsPublicKey == v2CommonPublicKey);

  // collect decryption shares from DKGV2 keys
  vector<vector<string>> v2DecryptionShares = collectDecryptionShares(
      c, v2Data.blsKeyNames, v2Data.blsPublicKeyShares, cipheredKeys, t, n);
  // collect decryption shares from DKGV3 KEYS
  vector<vector<string>> v3DecryptionShares = collectDecryptionShares(
      c, v3Data.blsKeyNames, v3Data.blsPublicKeyShares, cipheredKeys, t, n);

  for (const auto &subset : selectedSubsets) {
    // reconstructing common public from node's public key shares should yield
    // same common public key for both DKGV2 and DKGV3 keys
    const libBLS::algebra::G2Point subsetV2CommonPublicKey =
        reconstructCommonPublicKeyV2(v2Data.blsPublicKeyShares, subset, t, n);
    CHECK_STATE(subsetV2CommonPublicKey == v2CommonPublicKey);
    const libBLS::algebra::G2Point subsetV3CommonPublicKey =
        reconstructCommonPublicKeyV2(v3Data.blsPublicKeyShares, subset, t, n);
    CHECK_STATE(subsetV3CommonPublicKey == v2CommonPublicKey);

    // decrypt DKGV2 ciphertexts using DKGV3 keys - should work
    for (size_t ciphertextIndex = 0; ciphertextIndex < ciphertexts.size();
         ++ciphertextIndex) {
      libBLS::TEDecryptSet decryptSet(t, n);
      for (int i = 0; i < t; ++i) {
        const size_t node = subset.at(i);
        decryptSet.addDecryptShare(libBLS::TEDecryptionShare(
            v3DecryptionShares[node][ciphertextIndex], node + 1));
      }

      libBLS::AES256Key aesKey = libBLS::ThresholdEncryption::combineShares(
          cipheredKeys[ciphertextIndex], decryptSet);
      vector<uint8_t> decrypted =
          libBLS::ThresholdEncryption::validateAndDecrypt(
              ciphertexts[ciphertextIndex], aesKey,
              thresholdEncryptionPublicKey);
      CHECK_STATE(decrypted == plaintexts[ciphertextIndex]);
    }
  }

  // try decrypting using mix of decryption shares from V2 and V3 - should fail
  assertMixedV2V3SharesFail(
      ciphertexts, plaintexts, cipheredKeys, v2DecryptionShares,
      v3DecryptionShares, selectedSubsets, thresholdEncryptionPublicKey, t, n);
}

void TestUtils::doDKGV3RotationWithNewNodes(StubClient &c, int oldN, int newN,
                                            int t, int rotatedCount,
                                            int schainID, int dkgV2ID,
                                            int dkgV3ID, int ciphertextCount) {
  CHECK_STATE(oldN > 0);
  CHECK_STATE(newN > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= oldN);
  CHECK_STATE(t <= newN);
  CHECK_STATE(rotatedCount > 0);
  CHECK_STATE(rotatedCount < oldN);
  CHECK_STATE(rotatedCount < newN);
  CHECK_STATE(ciphertextCount > 0);

  const int retainedCount = newN - rotatedCount;
  CHECK_STATE(retainedCount > 0);
  CHECK_STATE(retainedCount + rotatedCount == newN);

  // run initial DKG2 to get keys for old committee and set up for rotation
  RotationDkgData v2Data = runDKGV2ForRotation(c, oldN, t, schainID, dkgV2ID);
  CHECK_STATE(v2Data.blsKeyNames.size() == static_cast<size_t>(oldN));
  CHECK_STATE(v2Data.blsPublicKeyShares.size() == static_cast<size_t>(oldN));

  vector<size_t> newCommitteeOldIndices;
  newCommitteeOldIndices.reserve(newN);
  // push deterministically N first indices in intersection
  for (int retained = 0; retained < retainedCount; ++retained) {
    newCommitteeOldIndices.push_back(static_cast<size_t>(retained));
  }
  // push new nodes
  for (int joining = 0; joining < rotatedCount; ++joining) {
    newCommitteeOldIndices.push_back(static_cast<size_t>(oldN + joining));
  }
  CHECK_STATE(newCommitteeOldIndices.size() == static_cast<size_t>(newN));

  const libBLS::algebra::G2Point v2CommonPublicKey = v2Data.commonBlsPublicKey;
  libBLS::TEPublicKey thresholdEncryptionPublicKey(v2CommonPublicKey);

  // generate ciphertexts using DKGV2 common public key
  vector<vector<uint8_t>> plaintexts =
      buildRotationPlaintexts(newN, t, ciphertextCount);
  vector<libBLS::Ciphertext> ciphertexts;
  vector<libBLS::CipheredKey> cipheredKeys;
  ciphertexts.reserve(plaintexts.size());
  cipheredKeys.reserve(plaintexts.size());

  for (const auto &plaintext : plaintexts) {
    libBLS::Ciphertext ciphertext = libBLS::ThresholdEncryption::encrypt(
        plaintext, thresholdEncryptionPublicKey);
    CHECK_STATE(ciphertext.getKeys().size() == 1);
    cipheredKeys.push_back(ciphertext.getTargetKey());
    ciphertexts.push_back(ciphertext);
  }

  vector<bool> encryptionValidation =
      libBLS::ThresholdEncryption::validateEncryptionBatch(cipheredKeys);
  CHECK_STATE(encryptionValidation.size() == cipheredKeys.size());
  for (bool isValid : encryptionValidation) {
    CHECK_STATE(isValid);
  }

  // rotate to a new group - with rotatedCount of nodes rotated out, and
  // rotatedCount nodes rotated in
  RotationDkgData v3Data = runDKGV3ForRotationWithNewNodes(
      c, v2Data, newCommitteeOldIndices, oldN, newN, t, schainID, dkgV3ID);
  CHECK_STATE(v3Data.blsKeyNames.size() == static_cast<size_t>(newN));
  CHECK_STATE(v3Data.blsPublicKeyShares.size() == static_cast<size_t>(newN));
  CHECK_STATE(v3Data.commonBlsPublicKey == v2CommonPublicKey);

  // new nodes have larger indices & have no polynomials set (no names)
  for (int joining = retainedCount; joining < newN; ++joining) {
    CHECK_STATE(newCommitteeOldIndices.at(joining) >=
                static_cast<size_t>(oldN));
    CHECK_STATE(v3Data.polyNames.at(joining).empty());
  }

  vector<vector<string>> v3DecryptionShares = collectDecryptionShares(
      c, v3Data.blsKeyNames, v3Data.blsPublicKeyShares, cipheredKeys, t, newN);

  // test 30% of all possible subsets of size t from the new committee - should
  // all work
  vector<vector<size_t>> selectedSubsets =
      selectedThresholdSubsets(newN, t, 30);
  CHECK_STATE(!selectedSubsets.empty());

  for (const auto &subset : selectedSubsets) {
    const libBLS::algebra::G2Point subsetV3CommonPublicKey =
        reconstructCommonPublicKeyV2(v3Data.blsPublicKeyShares, subset, t,
                                     newN);
    CHECK_STATE(subsetV3CommonPublicKey == v2CommonPublicKey);

    for (size_t ciphertextIndex = 0; ciphertextIndex < ciphertexts.size();
         ++ciphertextIndex) {
      libBLS::TEDecryptSet decryptSet(t, newN);
      for (int i = 0; i < t; ++i) {
        const size_t node = subset.at(i);
        decryptSet.addDecryptShare(libBLS::TEDecryptionShare(
            v3DecryptionShares[node][ciphertextIndex], node + 1));
      }

      libBLS::AES256Key aesKey = libBLS::ThresholdEncryption::combineShares(
          cipheredKeys[ciphertextIndex], decryptSet);
      vector<uint8_t> decrypted =
          libBLS::ThresholdEncryption::validateAndDecrypt(
              ciphertexts[ciphertextIndex], aesKey,
              thresholdEncryptionPublicKey);
      CHECK_STATE(decrypted == plaintexts[ciphertextIndex]);
    }
  }
}

void TestUtils::doDKGV3UnsafeRotatedNodesCanDecrypt(StubClient &c, int n, int t,
                                                    int rotatedCount,
                                                    int schainID, int dkgV2ID,
                                                    int dkgV3ID) {
  CHECK_STATE(n > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= n);
  CHECK_STATE(rotatedCount >= t);
  CHECK_STATE(rotatedCount < n);

  RotationDkgData v2Data = runDKGV2ForRotation(c, n, t, schainID, dkgV2ID);
  CHECK_STATE(v2Data.blsKeyNames.size() == static_cast<size_t>(n));
  CHECK_STATE(v2Data.blsPublicKeyShares.size() == static_cast<size_t>(n));

  const libBLS::algebra::G2Point v2CommonPublicKey = v2Data.commonBlsPublicKey;
  libBLS::TEPublicKey thresholdEncryptionPublicKey(v2CommonPublicKey);

  vector<vector<uint8_t>> plaintexts;
  vector<libBLS::Ciphertext> ciphertexts;
  vector<libBLS::CipheredKey> cipheredKeys;
  encryptRotationPayload(n, t, 1, thresholdEncryptionPublicKey, plaintexts,
                         ciphertexts, cipheredKeys);

  vector<vector<string>> v2DecryptionShares = collectDecryptionShares(
      c, v2Data.blsKeyNames, v2Data.blsPublicKeyShares, cipheredKeys, t, n);

  vector<size_t> newCommitteeOldIndices =
      buildCommitteeRotatingLastNodes(n, n, rotatedCount);
  RotationDkgData v3Data = runDKGV3ForRotationWithNewNodes(
      c, v2Data, newCommitteeOldIndices, n, n, t, schainID, dkgV3ID);
  CHECK_STATE(v3Data.commonBlsPublicKey == v2CommonPublicKey);

  vector<vector<string>> v3DecryptionShares = collectDecryptionShares(
      c, v3Data.blsKeyNames, v3Data.blsPublicKeyShares, cipheredKeys, t, n);
  assertShareRefsDecrypt(
      ciphertexts, plaintexts, cipheredKeys,
      shareRefsFromNodes(v3DecryptionShares, firstThresholdNodes(t), 0),
      thresholdEncryptionPublicKey, t, n);

  const vector<size_t> retiredThresholdNodes =
      takeFirstNodes(retiredLastNodes(n, rotatedCount), t);
  assertShareRefsDecrypt(
      ciphertexts, plaintexts, cipheredKeys,
      shareRefsFromNodes(v2DecryptionShares, retiredThresholdNodes, 0),
      thresholdEncryptionPublicKey, t, n);
}

void TestUtils::doDKGV3CrossEpochRetiredNodesCannotCollude(
    StubClient &c, int n, int t, int firstRotatedCount, int secondRotatedCount,
    int schainID, int dkgV2ID, int dkgV3ID, int dkgV4ID) {
  CHECK_STATE(n > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= n);
  CHECK_STATE(firstRotatedCount > 0);
  CHECK_STATE(secondRotatedCount > 0);
  CHECK_STATE(firstRotatedCount < t);
  CHECK_STATE(secondRotatedCount < t);
  CHECK_STATE(firstRotatedCount + secondRotatedCount > t);
  CHECK_STATE(firstRotatedCount < n);
  CHECK_STATE(secondRotatedCount < n);

  RotationDkgData v2Data = runDKGV2ForRotation(c, n, t, schainID, dkgV2ID);
  CHECK_STATE(v2Data.blsKeyNames.size() == static_cast<size_t>(n));
  CHECK_STATE(v2Data.blsPublicKeyShares.size() == static_cast<size_t>(n));

  const libBLS::algebra::G2Point v2CommonPublicKey = v2Data.commonBlsPublicKey;
  libBLS::TEPublicKey thresholdEncryptionPublicKey(v2CommonPublicKey);

  vector<vector<uint8_t>> plaintexts;
  vector<libBLS::Ciphertext> ciphertexts;
  vector<libBLS::CipheredKey> cipheredKeys;
  encryptRotationPayload(n, t, 1, thresholdEncryptionPublicKey, plaintexts,
                         ciphertexts, cipheredKeys);

  vector<vector<string>> v2DecryptionShares = collectDecryptionShares(
      c, v2Data.blsKeyNames, v2Data.blsPublicKeyShares, cipheredKeys, t, n);

  RotationDkgData v3Data = runDKGV3ForRotationWithNewNodes(
      c, v2Data, buildCommitteeRotatingLastNodes(n, n, firstRotatedCount), n, n,
      t, schainID, dkgV3ID);
  CHECK_STATE(v3Data.commonBlsPublicKey == v2CommonPublicKey);

  vector<vector<string>> v3DecryptionShares = collectDecryptionShares(
      c, v3Data.blsKeyNames, v3Data.blsPublicKeyShares, cipheredKeys, t, n);
  assertShareRefsDecrypt(
      ciphertexts, plaintexts, cipheredKeys,
      shareRefsFromNodes(v3DecryptionShares, firstThresholdNodes(t), 0),
      thresholdEncryptionPublicKey, t, n);

  RotationDkgData v4Data = runDKGV3ForRotationWithNewNodes(
      c, v3Data, buildCommitteeRotatingFirstNodes(n, secondRotatedCount), n, n,
      t, schainID, dkgV4ID);
  CHECK_STATE(v4Data.commonBlsPublicKey == v2CommonPublicKey);

  vector<vector<string>> v4DecryptionShares = collectDecryptionShares(
      c, v4Data.blsKeyNames, v4Data.blsPublicKeyShares, cipheredKeys, t, n);
  assertShareRefsDecrypt(
      ciphertexts, plaintexts, cipheredKeys,
      shareRefsFromNodes(v4DecryptionShares, firstThresholdNodes(t), 0),
      thresholdEncryptionPublicKey, t, n);

  vector<DecryptionShareRef> retiredShareRefs = shareRefsFromNodes(
      v2DecryptionShares, retiredLastNodes(n, firstRotatedCount), 0);
  vector<DecryptionShareRef> secondEpochRetiredShareRefs = shareRefsFromNodes(
      v3DecryptionShares, retiredFirstNodes(secondRotatedCount), 0);
  retiredShareRefs.insert(retiredShareRefs.end(),
                          secondEpochRetiredShareRefs.begin(),
                          secondEpochRetiredShareRefs.end());
  CHECK_STATE(retiredShareRefs.size() > static_cast<size_t>(t));

  vector<vector<size_t>> selectedSubsets = selectedThresholdSubsets(
      static_cast<int>(retiredShareRefs.size()), t, 100);
  CHECK_STATE(!selectedSubsets.empty());

  for (const auto &subset : selectedSubsets) {
    vector<DecryptionShareRef> mixedEpochShareRefs;
    mixedEpochShareRefs.reserve(subset.size());
    for (size_t retiredShareIndex : subset) {
      mixedEpochShareRefs.push_back(retiredShareRefs.at(retiredShareIndex));
    }
    assertShareRefsFail(ciphertexts, plaintexts, cipheredKeys,
                        mixedEpochShareRefs, thresholdEncryptionPublicKey, t,
                        n);
  }
}

void TestUtils::doDKGV3RotationWithNonRespondingNodes(
    StubClient &c, int n, int t, int rotatedCount, int nonRespondingCount,
    bool shouldDecrypt, int schainID, int dkgV2ID, int dkgV3ID) {
  CHECK_STATE(n > 0);
  CHECK_STATE(t > 0);
  CHECK_STATE(t <= n);
  CHECK_STATE(rotatedCount > 0);
  CHECK_STATE(rotatedCount < n);
  CHECK_STATE(nonRespondingCount >= 0);
  CHECK_STATE(nonRespondingCount < n);

  RotationDkgData v2Data = runDKGV2ForRotation(c, n, t, schainID, dkgV2ID);
  CHECK_STATE(v2Data.blsKeyNames.size() == static_cast<size_t>(n));
  CHECK_STATE(v2Data.blsPublicKeyShares.size() == static_cast<size_t>(n));

  const libBLS::algebra::G2Point v2CommonPublicKey = v2Data.commonBlsPublicKey;
  libBLS::TEPublicKey thresholdEncryptionPublicKey(v2CommonPublicKey);

  vector<vector<uint8_t>> plaintexts;
  vector<libBLS::Ciphertext> ciphertexts;
  vector<libBLS::CipheredKey> cipheredKeys;
  encryptRotationPayload(n, t, 1, thresholdEncryptionPublicKey, plaintexts,
                         ciphertexts, cipheredKeys);

  RotationDkgData v3Data = runDKGV3ForRotationWithNewNodes(
      c, v2Data, buildCommitteeRotatingLastNodes(n, n, rotatedCount), n, n, t,
      schainID, dkgV3ID);
  CHECK_STATE(v3Data.commonBlsPublicKey == v2CommonPublicKey);

  vector<vector<string>> v3DecryptionShares = collectDecryptionShares(
      c, v3Data.blsKeyNames, v3Data.blsPublicKeyShares, cipheredKeys, t, n);
  const vector<DecryptionShareRef> availableShareRefs = shareRefsFromNodes(
      v3DecryptionShares, respondingNodes(n, nonRespondingCount), 0);

  if (shouldDecrypt) {
    CHECK_STATE(availableShareRefs.size() >= static_cast<size_t>(t));
    assertShareRefsDecrypt(ciphertexts, plaintexts, cipheredKeys,
                           availableShareRefs, thresholdEncryptionPublicKey, t,
                           n);
  } else {
    CHECK_STATE(availableShareRefs.size() < static_cast<size_t>(t));
    assertShareRefsFail(ciphertexts, plaintexts, cipheredKeys,
                        availableShareRefs, thresholdEncryptionPublicKey, t, n);
  }
}

void TestUtils::doZMQBLS(shared_ptr<ZMQClient> _zmqClient, StubClient &c, int n,
                         int t, vector<string> &_ecdsaKeyNames,
                         vector<string> &_blsKeyNames, int schainID,
                         int dkgID) {
  Json::Value ethKeys[n];
  Json::Value verifVects[n];
  Json::Value pubEthKeys;
  Json::Value secretShares[n];
  Json::Value pubBLSKeys[n];
  Json::Value blsSigShares[n];
  vector<string> pubShares(n);
  vector<string> polyNames(n);

  _ecdsaKeyNames.clear();
  _blsKeyNames.clear();

  for (uint8_t i = 0; i < n; i++) {
    ethKeys[i] = c.generateECDSAKey();

    CHECK_STATE(ethKeys[i]["status"] == 0);

    auto keyName = ethKeys[i]["keyName"].asString();
    CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);

    _ecdsaKeyNames.push_back(keyName);

    string polyName = "POLY:SCHAIN_ID:" + to_string(schainID) +
                      ":NODE_ID:" + to_string(i) +
                      ":DKG_ID:" + to_string(dkgID);

    Json::Value response = c.generateDKGPoly(polyName, t);
    CHECK_STATE(response["status"] == 0);
    polyNames[i] = polyName;
    verifVects[i] = c.getVerificationVector(polyName, t);
    CHECK_STATE(verifVects[i]["status"] == 0);
    pubEthKeys.append(ethKeys[i]["publicKey"]);
  }

  for (uint8_t i = 0; i < n; i++) {
    secretShares[i] = c.getSecretShareV2(polyNames[i], pubEthKeys, t, n);
    CHECK_STATE(secretShares[i]["status"] == 0);
    for (uint8_t k = 0; k < t; k++) {
      for (uint8_t j = 0; j < 4; j++) {
        string pubShare = verifVects[i]["verificationVector"][k][j].asString();
        CHECK_STATE(pubShare.length() > 60);
        pubShares[i] += TestUtils::convertDecToHex(pubShare);
      }
    }
  }

  int k = 0;

  vector<string> secShares(n);

  vector<string> pSharesBad(pubShares);

  for (int i = 0; i < n; i++)
    for (int j = 0; j < n; j++) {
      string secretShare =
          secretShares[i]["secretShare"].asString().substr(192 * j, 192);
      secShares[i] +=
          secretShares[j]["secretShare"].asString().substr(192 * i, 192);
      Json::Value response = c.dkgVerificationV2(
          pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
      CHECK_STATE(response["status"] == 0);

      bool res = response["result"].asBool();
      CHECK_STATE(res);

      k++;

      pSharesBad[i][0] = 'q';
      Json::Value wrongVerif =
          c.dkgVerificationV2(pSharesBad[i], ethKeys[j]["keyName"].asString(),
                              secretShare, t, n, j);
      res = wrongVerif["result"].asBool();
      CHECK_STATE(!res);
    }

  libBLS::BLSSigShareSet sigShareSet(t, n);

  string hash = SAMPLE_HASH;

  array<uint8_t, 32> hashArr;
  uint64_t binLen;
  if (!hex2carray(hash.c_str(), &binLen, hashArr.data(), 32)) {
    throw SGXException(TEST_INVALID_HEX, "Invalid hash");
  }

  map<size_t, libBLS::BLSPublicKeyShare> pubKeyShares;

  for (int i = 0; i < n; i++) {
    string endName = polyNames[i].substr(4);
    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    _blsKeyNames.push_back(blsName);
    string secretShare = secretShares[i]["secretShare"].asString();

    auto response =
        c.createBLSPrivateKeyV2(blsName, ethKeys[i]["keyName"].asString(),
                                polyNames[i], secShares[i], t, n);
    CHECK_STATE(response["status"] == 0);
    pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
    CHECK_STATE(pubBLSKeys[i]["status"] == 0);
  }

  for (int i = 0; i < t; i++) {
    vector<string> pubKeyVect;
    for (uint8_t j = 0; j < 4; j++) {
      pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
    }
    libBLS::BLSPublicKeyShare pubKey(pubKeyVect, t, n);

    pubKeyShares.insert(std::make_pair(i + 1, pubKey));
  }

  // create pub key

  libBLS::BLSPublicKey blsPublicKey(pubKeyShares, t, n);

  // sign verify a sample sig

  for (int i = 0; i < t; i++) {

    string blsName = "BLS_KEY" + polyNames[i].substr(4);
    auto sigShare = _zmqClient->blsSignMessageHash(blsName, hash, t, n);
    libBLS::BLSSigShare sig(sigShare, i + 1, t, n);
    sigShareSet.addSigShare(sig);

    auto pubKey = pubKeyShares.at(i + 1);

    CHECK_STATE(pubKey.VerifySigWithHelper(hashArr, sig, t, n));
  }

  libBLS::BLSSignature commonSig = sigShareSet.merge();

  CHECK_STATE(blsPublicKey.VerifySigWithHelper(hashArr, commonSig));

  for (auto &&i : _ecdsaKeyNames)
    cerr << i << endl;

  for (auto &&i : _blsKeyNames)
    cerr << i << endl;
}

int sessionKeyRecoverDH(const char *skey_str, const char *sshare,
                        char *common_key) {

  int ret = -1;

  SAFE_CHAR_BUF(pb_keyB_x, 65);
  SAFE_CHAR_BUF(pb_keyB_y, 65);

  mpz_t skey;
  mpz_init(skey);
  point pub_keyB = point_init();
  point session_key = point_init();

  pb_keyB_x[64] = 0;
  strncpy(pb_keyB_x, sshare, 64);
  strncpy(pb_keyB_y, sshare + 64, 64);
  pb_keyB_y[64] = 0;

  if (!common_key) {
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);

    return ret;
  }

  common_key[0] = 0;

  if (!skey_str) {
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);
    return ret;
  }

  if (!sshare) {
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);

    return ret;
  }

  if (mpz_set_str(skey, skey_str, 16) == -1) {
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);

    return ret;
  }

  domain_parameters curve;
  curve = domain_parameters_init();
  domain_parameters_load_curve(curve, secp256k1);

  if (point_set_hex(pub_keyB, pb_keyB_x, pb_keyB_y) != 0) {
    mpz_clear(skey);
    point_clear(pub_keyB);
    point_clear(session_key);
    domain_parameters_clear(curve);
    return ret;
  }

  point_multiplication(session_key, skey, pub_keyB, curve);

  SAFE_CHAR_BUF(arr_x, BUF_LEN);

  mpz_get_str(arr_x, 16, session_key->x);
  int n_zeroes = 64 - strlen(arr_x);
  for (int i = 0; i < n_zeroes; i++) {
    common_key[i] = '0';
  }
  strncpy(common_key + n_zeroes, arr_x, strlen(arr_x));

  ret = 0;

  mpz_clear(skey);
  point_clear(pub_keyB);
  point_clear(session_key);
  domain_parameters_clear(curve);

  return ret;
}

int xorDecryptDH(char *key, const char *cypher, vector<char> &message) {

  int ret = -1;

  if (!cypher) {
    return ret;
  }

  if (!key) {
    return ret;
  }

  if (!message.data()) {
    return ret;
  }

  SAFE_CHAR_BUF(msg_bin, 33)

  SAFE_CHAR_BUF(key_bin, 33)

  uint64_t key_length;
  if (!hex2carray(key, &key_length, (uint8_t *)key_bin, 33)) {
    return ret;
  }

  uint64_t cypher_length;

  SAFE_CHAR_BUF(cypher_bin, 33);
  if (!hex2carray(cypher, &cypher_length, (uint8_t *)cypher_bin, 33)) {
    return ret;
  }

  for (int i = 0; i < 32; i++) {
    msg_bin[i] = cypher_bin[i] ^ key_bin[i];
  }

  message = carray2Hex((unsigned char *)msg_bin, 32);

  ret = 0;

  return ret;
}

int xorDecryptDHV2(char *key, const char *cypher, vector<char> &message) {

  int ret = -1;

  if (!cypher) {
    return ret;
  }

  if (!key) {
    return ret;
  }

  if (!message.data()) {
    return ret;
  }

  SAFE_CHAR_BUF(msg_bin, 33)

  uint64_t cypher_length;

  SAFE_CHAR_BUF(cypher_bin, 33);
  if (!hex2carray(cypher, &cypher_length, (uint8_t *)cypher_bin, 33)) {
    return ret;
  }

  for (int i = 0; i < 32; i++) {
    msg_bin[i] = cypher_bin[i] ^ (uint8_t)key[i];
  }

  message = carray2Hex((unsigned char *)msg_bin, 32);

  ret = 0;

  return ret;
}
