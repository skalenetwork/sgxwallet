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
*/

#include "third_party/catch.hpp"

#include <functional>
#include <string>

#include "../../CryptoTools.h"
#include "../../SGXException.h"
#include "../../sgxwallet_common.h"

// ---------------------------------------------------------------------------
// Fixtures: 64-char (32-byte) hex scalars at the interesting boundaries.
// ---------------------------------------------------------------------------

// alt_bn128 scalar field order r (BLS upper bound), as hex.
static const std::string BLS_ORDER_HEX =
    "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001";
static const std::string BLS_ORDER_MINUS_1_HEX =
    "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000000";

// secp256k1 group order n (ECDSA upper bound), as hex.
static const std::string ECDSA_ORDER_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static const std::string ECDSA_ORDER_MINUS_1_HEX =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";

static const std::string ONE_HEX =
    "0000000000000000000000000000000000000000000000000000000000000001";
static const std::string ZERO_HEX =
    "0000000000000000000000000000000000000000000000000000000000000000";

// Wrappers that bind the validator exactly as the production call sites do
// (BLSCrypto.cpp / ECDSACrypto.cpp), so the tests exercise the real bindings.
static std::string validateBls(const std::string &key) {
  return normalizeAndValidateScalarHex(key, ALT_BN128_ORDER_DEC, 10,
                                       BLS_IMPORT_INVALID_KEY_SHARE,
                                       "BLS key share");
}

static std::string validateEcdsa(const std::string &key) {
  return normalizeAndValidateScalarHex(key, SECP256K1_ORDER_HEX, 16,
                                       INVALID_ECDSA_IMPORT_HEX,
                                       "ECDSA key share");
}

// Runs fn, and returns the status of the SGXException it is expected to throw.
static int32_t thrownStatus(const std::function<void()> &fn) {
  try {
    fn();
  } catch (const SGXException &e) {
    return e.getStatus();
  }
  FAIL("expected SGXException was not thrown");
  return 0;
}

// ---------------------------------------------------------------------------
// normalizeHexInput
// ---------------------------------------------------------------------------

TEST_CASE("normalizeHexInput - strips lowercase 0x prefix",
          "[unit][CryptoTools][normalizeHexInput]") {
  REQUIRE(normalizeHexInput("0xabcd") == "abcd");
}

TEST_CASE("normalizeHexInput - strips uppercase 0X prefix",
          "[unit][CryptoTools][normalizeHexInput]") {
  REQUIRE(normalizeHexInput("0Xabcd") == "abcd");
}

TEST_CASE("normalizeHexInput - leaves unprefixed input unchanged",
          "[unit][CryptoTools][normalizeHexInput]") {
  REQUIRE(normalizeHexInput("abcd") == "abcd");
}

TEST_CASE("normalizeHexInput - a leading 0 that is not 0x is preserved",
          "[unit][CryptoTools][normalizeHexInput]") {
  REQUIRE(normalizeHexInput("0abc") == "0abc");
}

TEST_CASE("normalizeHexInput - too-short input is not mistaken for a prefix",
          "[unit][CryptoTools][normalizeHexInput]") {
  REQUIRE(normalizeHexInput("0") == "0");
  REQUIRE(normalizeHexInput("") == "");
}

// ---------------------------------------------------------------------------
// normalizeAndValidateScalarHex - accepted scalars
// ---------------------------------------------------------------------------

TEST_CASE("validate - BLS accepts a scalar just below the order",
          "[unit][CryptoTools][validateScalar][bls]") {
  REQUIRE(validateBls(BLS_ORDER_MINUS_1_HEX) == BLS_ORDER_MINUS_1_HEX);
}

TEST_CASE("validate - ECDSA accepts a scalar just below the order",
          "[unit][CryptoTools][validateScalar][ecdsa]") {
  REQUIRE(validateEcdsa(ECDSA_ORDER_MINUS_1_HEX) == ECDSA_ORDER_MINUS_1_HEX);
}

TEST_CASE("validate - the smallest valid scalar (1) is accepted",
          "[unit][CryptoTools][validateScalar]") {
  REQUIRE(validateBls(ONE_HEX) == ONE_HEX);
  REQUIRE(validateEcdsa(ONE_HEX) == ONE_HEX);
}

TEST_CASE("validate - a 0x prefix is stripped and the normalized key returned",
          "[unit][CryptoTools][validateScalar]") {
  REQUIRE(validateBls("0x" + BLS_ORDER_MINUS_1_HEX) == BLS_ORDER_MINUS_1_HEX);
  REQUIRE(validateEcdsa("0X" + ECDSA_ORDER_MINUS_1_HEX) ==
          ECDSA_ORDER_MINUS_1_HEX);
}

// ---------------------------------------------------------------------------
// normalizeAndValidateScalarHex - out-of-range scalars
// ---------------------------------------------------------------------------

TEST_CASE("validate - zero is rejected as out of range",
          "[unit][CryptoTools][validateScalar]") {
  REQUIRE(thrownStatus([] { validateBls(ZERO_HEX); }) ==
          BLS_IMPORT_INVALID_KEY_SHARE);
  REQUIRE(thrownStatus([] { validateEcdsa(ZERO_HEX); }) ==
          INVALID_ECDSA_IMPORT_HEX);
}

TEST_CASE("validate - a scalar equal to the order is rejected",
          "[unit][CryptoTools][validateScalar]") {
  REQUIRE(thrownStatus([] { validateBls(BLS_ORDER_HEX); }) ==
          BLS_IMPORT_INVALID_KEY_SHARE);
  REQUIRE(thrownStatus([] { validateEcdsa(ECDSA_ORDER_HEX); }) ==
          INVALID_ECDSA_IMPORT_HEX);
}

// The BLS (alt_bn128) order is smaller than the secp256k1 order, so a scalar
// equal to the BLS order is a valid ECDSA scalar but an invalid BLS one. This
// guards against the two validations being accidentally interchanged.
TEST_CASE("validate - BLS order value is invalid for BLS but valid for ECDSA",
          "[unit][CryptoTools][validateScalar][cross-curve]") {
  REQUIRE(thrownStatus([] { validateBls(BLS_ORDER_HEX); }) ==
          BLS_IMPORT_INVALID_KEY_SHARE);
  REQUIRE(validateEcdsa(BLS_ORDER_HEX) == BLS_ORDER_HEX);
}

// ---------------------------------------------------------------------------
// normalizeAndValidateScalarHex - malformed input
// ---------------------------------------------------------------------------

TEST_CASE("validate - a key shorter than 64 hex chars is rejected",
          "[unit][CryptoTools][validateScalar]") {
  REQUIRE(thrownStatus([] { validateBls("abcd"); }) ==
          BLS_IMPORT_INVALID_KEY_SHARE);
  REQUIRE(thrownStatus([] { validateBls(BLS_ORDER_MINUS_1_HEX.substr(1)); }) ==
          BLS_IMPORT_INVALID_KEY_SHARE);
}

TEST_CASE("validate - a key longer than 64 hex chars is rejected",
          "[unit][CryptoTools][validateScalar]") {
  REQUIRE(thrownStatus([] { validateEcdsa(ECDSA_ORDER_MINUS_1_HEX + "0"); }) ==
          INVALID_ECDSA_IMPORT_HEX);
}

TEST_CASE("validate - a 64-char string with non-hex characters is rejected",
          "[unit][CryptoTools][validateScalar]") {
  const std::string nonHex(64, 'g');
  REQUIRE(thrownStatus([&] { validateBls(nonHex); }) ==
          BLS_IMPORT_INVALID_KEY_SHARE);
  REQUIRE(thrownStatus([&] { validateEcdsa(nonHex); }) ==
          INVALID_ECDSA_IMPORT_HEX);
}
