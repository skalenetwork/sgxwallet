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

    @file TestUtils.h
    @author Stan Kladko
    @date 2020
*/

#ifndef SGXWALLET_TESTUTILS_H
#define SGXWALLET_TESTUTILS_H

#include "abstractstubserver.h"
#include "secure_enclave_u.h"
#include "sgxwallet_common.h"
#include "stubclient.h"
#include "third_party/intel/create_enclave.h"
#include "third_party/intel/sgx_detect.h"
#include "zmq_src/ZMQClient.h"
#include <dkg/dkg.h>
#include <gmp.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <libBLS/backends/algebra.hpp>
#include <libBLS/bls/bls.h>
#include <random>
#include <sgx_tcrypto.h>
#include <sgx_urts.h>
#include <stdio.h>

using namespace std;

using namespace jsonrpc;

class TestUtils {

public:
  static constexpr size_t DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN =
      SECRET_SHARE_NUM_BYTES * 2;

  static default_random_engine randGen;

  static string
  stringFromFr(libBLS::algebra::FrScalar &el,
               libBLS::algebra::Base base = libBLS::algebra::Base::DEC);

  static string convertDecToHex(string dec, int numBytes = 32);

  static string makeDKGPolyName(int schainID, int nodeID, int dkgID);

  static string makeBLSKeyName(int schainID, int nodeID, int dkgID);

  static string blsNameFromPolyName(const string &polyName);

  static string publicSharesFromVerificationVector(
      const Json::Value &verificationVectorResponse, int t);

  static string encryptedDkgSecretContributionForRecipient(
      const string &secretShares, int recipientIndex);

  static Json::Value dkgV3SecretContributionsForRecipient(
      const vector<string> &dealerSecretShares, int recipientIndex);

  static void genTestKeys();

  static void resetDB();

  static shared_ptr<string> encryptTestKey();

  static vector<libBLS::algebra::FrScalar> splitStringToFr(const char *coeffs,
                                                           const char symbol);

  static vector<string> splitStringTest(const char *coeffs, const char symbol);

  static libBLS::algebra::G2Point
  vectStringToG2(const vector<string> &G2_str_vect);

  static void sendRPCRequest();

  static void sendRPCRequestV2();

  static void destroyEnclave();

  static void doDKG(StubClient &c, int n, int t, vector<string> &_ecdsaKeyNames,
                    vector<string> &_blsKeyNames, int schainID, int dkgID);

  static void doDKGV2(StubClient &c, int n, int t,
                      vector<string> &_ecdsaKeyNames,
                      vector<string> &_blsKeyNames, int schainID, int dkgID);

  /**
   * @brief Executes DKG V3 rotation, maintaining the exact same nodes in the group.
   * simply regenerates keys and shares.
   * Internally does 1 DKG V2 before DKG V3, since V3 requires existing BLS keys
   * from previous rotation to be present.
   */
  static void doDKGV3Rotation(StubClient &c, int n, int t, int schainID,
                              int dkgV2ID, int dkgV3ID,
                              int coveragePercent, int ciphertextCount);

  /**
   * @brief Executes DKG V3 rotation with new nodes added to the group.
   * Allows nodes to be rotated out of old group, and new nodes rotated in.
   * New nodes will not participate actively in DKG V3 - will not submit
   * secret contributions.
   * Allows new group to be of different size than old group, as long as 
   * threshold is maintained.
   */
  static void doDKGV3RotationWithNewNodes(StubClient &c, int oldN, int newN,
                                          int t, int rotatedCount,
                                          int schainID, int dkgV2ID,
                                          int dkgV3ID, int ciphertextCount);

  /**
   * @brief Demonstrates why rotating out a full threshold is unsafe.
   * Executes DKG V2, rotates `rotatedCount` nodes through DKG V3, verifies
   * the new group can still decrypt, then verifies that `t` retired V2 nodes
   * can also collude and decrypt ciphertext encrypted before rotation.
   * This is a security proof test, not a production policy check.
   */
  static void doDKGV3UnsafeRotatedNodesCanDecrypt(
      StubClient &c, int n, int t, int rotatedCount, int schainID,
      int dkgV2ID, int dkgV3ID);

  /**
   * @brief Verifies retired nodes from separate rotations cannot mix shares.
   * Executes two sequential DKG V3 rotations where each rotation retires fewer
   * than `t` nodes, but the total retired nodes across both rotations is more
   * than `t`. Confirms live epochs can decrypt, while every threshold-sized
   * mix of retired shares from different epochs fails to decrypt.
   */
  static void doDKGV3CrossEpochRetiredNodesCannotCollude(
      StubClient &c, int n, int t, int firstRotatedCount,
      int secondRotatedCount, int schainID, int dkgV2ID, int dkgV3ID,
      int dkgV4ID);

  /**
   * @brief Verifies rotation behavior with non-responding nodes.
   * Executes DKG V2 followed by DKG V3 rotation, then simulates malicious
   * nodes by excluding `nonRespondingCount` nodes from the decryption set.
   * If `shouldDecrypt` is true, the remaining nodes must form a threshold and
   * decrypt successfully; otherwise decryption must fail with insufficient
   * shares.
   */
  static void doDKGV3RotationWithNonRespondingNodes(
      StubClient &c, int n, int t, int rotatedCount, int nonRespondingCount,
      bool shouldDecrypt, int schainID, int dkgV2ID, int dkgV3ID);

  static void doZMQBLS(shared_ptr<ZMQClient> _zmqClient, StubClient &c, int n,
                       int t, vector<string> &_ecdsaKeyNames,
                       vector<string> &_blsKeyNames, int schainID, int dkgID);

  static void sendRPCRequestZMQ();

  // Simple start barrier - used by multi-threaded load tests
  struct start_barrier {
    explicit start_barrier(int count) : count(count) {}
    void wait() {
      std::unique_lock<std::mutex> lock(m);
      if (--count == 0) {
        cv.notify_all();
      } else {
        cv.wait(lock, [&] { return count == 0; });
      }
    }

  private:
    int count;
    std::mutex m;
    std::condition_variable cv;
  };
};

int sessionKeyRecoverDH(const char *skey_str, const char *sshare,
                        char *common_key);

int xorDecryptDH(char *key, const char *cypher, vector<char> &message);

int xorDecryptDHV2(char *key, const char *cypher, vector<char> &message);

#endif // SGXWALLET_TESTW_H
