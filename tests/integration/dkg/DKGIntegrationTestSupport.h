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

#ifndef SGXWALLET_TESTS_INTEGRATION_DKG_DKGINTEGRATIONTESTSUPPORT_H
#define SGXWALLET_TESTS_INTEGRATION_DKG_DKGINTEGRATIONTESTSUPPORT_H

#include "sgxwallet_common.h"
#include "stubclient.h"
#include "zmq_src/ZMQClient.h"

#include <cstddef>
#include <json/value.h>
#include <memory>
#include <string>
#include <vector>

namespace DKGIntegrationTestSupport {

static constexpr size_t DKG_ENCRYPTED_SECRET_CONTRIBUTION_HEX_LEN =
    SECRET_SHARE_NUM_BYTES * 2;

std::string makeDKGPolyName(int schainID, int nodeID, int dkgID);

std::string makeBLSKeyName(int schainID, int nodeID, int dkgID);

std::string blsNameFromPolyName(const std::string &polyName);

std::string publicSharesFromVerificationVector(
    const Json::Value &verificationVectorResponse, int t);

std::string
encryptedDkgSecretContributionForRecipient(const std::string &secretShares,
                                           int recipientIndex);

Json::Value dkgV3SecretContributionsForRecipient(
    const std::vector<std::string> &dealerSecretShares, int recipientIndex);

void sendRPCRequestV2();

void sendRPCRequestZMQ();

int sessionKeyRecoverDH(const char *skey_str, const char *sshare,
                        char *common_key);

int xorDecryptDH(char *key, const char *cypher, std::vector<char> &message);

int xorDecryptDHV2(char *key, const char *cypher, std::vector<char> &message);

void doDKG(StubClient &c, int n, int t,
           std::vector<std::string> &_ecdsaKeyNames,
           std::vector<std::string> &_blsKeyNames, int schainID, int dkgID);

void doDKGV2(StubClient &c, int n, int t,
             std::vector<std::string> &_ecdsaKeyNames,
             std::vector<std::string> &_blsKeyNames, int schainID, int dkgID);

/**
 * @brief Executes DKG V3 rotation, maintaining the exact same nodes in the
 * group. Simply regenerates keys and shares. Internally does one DKG V2 before
 * DKG V3, since V3 requires existing BLS keys from the previous rotation.
 */
void doDKGV3Rotation(StubClient &c, int n, int t, int schainID, int dkgV2ID,
                     int dkgV3ID, int coveragePercent, int ciphertextCount);

/**
 * @brief Executes DKG V3 rotation with new nodes added to the group.
 */
void doDKGV3RotationWithNewNodes(StubClient &c, int oldN, int newN, int t,
                                 int rotatedCount, int schainID, int dkgV2ID,
                                 int dkgV3ID, int ciphertextCount);

/**
 * @brief Demonstrates why rotating out a full threshold is unsafe.
 */
void doDKGV3UnsafeRotatedNodesCanDecrypt(StubClient &c, int n, int t,
                                         int rotatedCount, int schainID,
                                         int dkgV2ID, int dkgV3ID);

/**
 * @brief Verifies retired nodes from separate rotations cannot mix shares.
 */
void doDKGV3CrossEpochRetiredNodesCannotCollude(StubClient &c, int n, int t,
                                                int firstRotatedCount,
                                                int secondRotatedCount,
                                                int schainID, int dkgV2ID,
                                                int dkgV3ID, int dkgV4ID);

/**
 * @brief Verifies rotation behavior with non-responding nodes.
 */
void doDKGV3RotationWithNonRespondingNodes(StubClient &c, int n, int t,
                                           int rotatedCount,
                                           int nonRespondingCount,
                                           bool shouldDecrypt, int schainID,
                                           int dkgV2ID, int dkgV3ID);

void doZMQBLS(std::shared_ptr<ZMQClient> _zmqClient, StubClient &c, int n,
              int t, std::vector<std::string> &_ecdsaKeyNames,
              std::vector<std::string> &_blsKeyNames, int schainID, int dkgID);

} // namespace DKGIntegrationTestSupport

#endif // SGXWALLET_TESTS_INTEGRATION_DKG_DKGINTEGRATIONTESTSUPPORT_H
