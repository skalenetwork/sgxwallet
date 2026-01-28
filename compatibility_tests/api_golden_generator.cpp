/*
  API Golden Vector Generator
  
  This program connects to a running sgxwallet server and captures
  API request/response pairs for compatibility testing.
  
  Usage:
    1. Start sgxwallet server (old libff version)
    2. Run: ./api_golden_generator http://localhost:1029 > api_golden_vectors.json
    3. Test against new mcl version using api_validator
*/

#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <ctime>
#include <sstream>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include "stubclient.h"
#include "hex_utils.h"

using namespace std;
using namespace jsonrpc;

// Fixed test inputs for deterministic tests
const string DETERMINISTIC_HASH = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const string DETERMINISTIC_POLY_NAME = "POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1";
const string DETERMINISTIC_POLY_NAME2 = "POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:2"; // For test 15 (createBLSPrivateKey consumes poly)
const string DETERMINISTIC_POLY_NAME3 = "POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:3"; // For test 18 (createBLSPrivateKeyV2 consumes poly)
const string DETERMINISTIC_BLS_KEY = "BLS_KEY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1";
const string DETERMINISTIC_BLS_KEY2 = "BLS_KEY:SCHAIN_ID:2:NODE_ID:2:DKG_ID:2";
const string DETERMINISTIC_ETH_KEY = "NEK:1";
const string DETERMINISTIC_ETH_KEY2 = "NEK:2";
const string DETERMINISTIC_ETH_KEY3 = "NEK:3";
const string DETERMINISTIC_G2_SCALAR = "12345678901234567890";

string getCurrentTimestamp() {
  time_t now = time(0);
  struct tm tstruct;
  char buf[80];
  tstruct = *gmtime(&now);
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tstruct);
  return string(buf);
}

void printTestHeader() {
  cout << "{\n";
  cout << "  \"format_version\": \"2.0\",\n";
  cout << "  \"test_type\": \"api_level\",\n";
  cout << "  \"timestamp\": \"" << getCurrentTimestamp() << "\",\n";
  cout << "  \"description\": \"API-level golden vectors for sgxwallet libff->mcl migration\",\n";
  cout << "  \"tests\": [\n";
}

void printTestFooter() {
  cout << "  ]\n";
  cout << "}\n";
}

string indentJson(const string& json, const string& indent) {
  stringstream result;
  stringstream ss(json);
  string line;
  bool first = true;
  while (getline(ss, line)) {
    if (!first) {
      result << "\n";
    }
    result << indent << line;
    first = false;
  }
  return result.str();
}

void printTest(const string& testId, const string& description, 
               const string& method, const Json::Value& request,
               const Json::Value& response, const string& validationType,
               const Json::Value& validationCriteria, bool isLast = false) {
  Json::StreamWriterBuilder builder;
  builder["indentation"] = "  ";
  
  string requestJson = Json::writeString(builder, request);
  string responseJson = Json::writeString(builder, response);
  string criteriaJson = Json::writeString(builder, validationCriteria);
  
  // Remove trailing newline from Json::writeString output
  if (!requestJson.empty() && requestJson.back() == '\n') requestJson.pop_back();
  if (!responseJson.empty() && responseJson.back() == '\n') responseJson.pop_back();
  if (!criteriaJson.empty() && criteriaJson.back() == '\n') criteriaJson.pop_back();
  
  cout << "    {\n";
  cout << "      \"test_id\": \"" << testId << "\",\n";
  cout << "      \"description\": \"" << description << "\",\n";
  cout << "      \"method\": \"" << method << "\",\n";
  cout << "      \"request\": " << indentJson(requestJson, "      ") << ",\n";
  cout << "      \"expected_response\": " << indentJson(responseJson, "      ") << ",\n";
  cout << "      \"validation_type\": \"" << validationType << "\",\n";
  cout << "      \"validation_criteria\": " << indentJson(criteriaJson, "      ") << "\n";
  cout << (isLast ? "    }\n" : "    },\n");
}

bool checkStatus(const Json::Value& response, const string& testName) {
  if (!response.isMember("status") || response["status"].asInt() != 0) {
    cerr << "ERROR in " << testName << ": ";
    if (response.isMember("errorMessage")) {
      cerr << response["errorMessage"].asString() << endl;
    } else {
      cerr << "Unknown error" << endl;
    }
    return false;
  }
  return true;
}

int main(int argc, char* argv[]) {
  string endpoint = "http://localhost:1029";
  if (argc > 1) {
    endpoint = argv[1];
  }

  cerr << "Connecting to sgxwallet at " << endpoint << "..." << endl;

  try {
    HttpClient httpClient(endpoint);
    StubClient client(httpClient, JSONRPC_CLIENT_V2);
    
    printTestHeader();
    bool firstTest = true;

    // ===== DETERMINISTIC TESTS =====
    // These should produce byte-identical results
    
    cerr << "[1/9] Testing importBLSKeyShare (deterministic)..." << endl;
    // Test 1: Import a fixed BLS key share
    {
      if (!firstTest) cout << ",\n";
      firstTest = false;
      
      // Use a fixed key share for deterministic testing
      string keyShare = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      
      Json::Value request;
      request["keyShare"] = keyShare;
      request["keyShareName"] = DETERMINISTIC_BLS_KEY;
      
      Json::Value response = client.importBLSKeyShare(keyShare, DETERMINISTIC_BLS_KEY);
      
      if (!checkStatus(response, "importBLSKeyShare")) {
        return 1;
      }
      
      // Remove encrypted value from expected response (it's random due to SEK)
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("encryptedKeyShare")) {
        expectedResponse["encryptedKeyShare"] = "<encrypted>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["encryptedKeyShare"] = "must_be_present";
      criteria["comparison"] = "structural";
      
      printTest("api_import_bls_001", "Import BLS key share (encryption is random)",
                "importBLSKeyShare", request, expectedResponse, "functional", criteria);
    }

    cerr << "[2/9] Testing getBLSPublicKeyShare (deterministic)..." << endl;
    // Test 2: Get BLS public key from imported share
    {
      Json::Value request;
      request["blsKeyName"] = DETERMINISTIC_BLS_KEY;
      
      Json::Value response = client.getBLSPublicKeyShare(DETERMINISTIC_BLS_KEY);
      
      if (!checkStatus(response, "getBLSPublicKeyShare")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["blsPublicKeyShare"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_get_bls_pubkey_001", "Get BLS public key share",
                "getBLSPublicKeyShare", request, response, "deterministic", criteria);
    }

    cerr << "[3/9] Testing blsSignMessageHash (deterministic)..." << endl;
    // Test 3: Sign message hash with deterministic input
    {
      int t = 2, n = 3;
      
      Json::Value request;
      request["keyShareName"] = DETERMINISTIC_BLS_KEY;
      request["messageHash"] = DETERMINISTIC_HASH;
      request["t"] = t;
      request["n"] = n;
      
      Json::Value response = client.blsSignMessageHash(DETERMINISTIC_BLS_KEY, DETERMINISTIC_HASH, t, n);
      
      if (!checkStatus(response, "blsSignMessageHash")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["signatureShare"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_bls_sign_001", "BLS sign with deterministic hash",
                "blsSignMessageHash", request, response, "deterministic", criteria);
    }

    // ===== FUNCTIONAL TESTS =====
    // These involve randomness - only check success/failure and structure
    
    cerr << "[4/9] Testing generateECDSAKey (functional, has randomness)..." << endl;
    // Test 4: Generate ECDSA key (random)
    {
      Json::Value request = Json::nullValue;
      Json::Value response = client.generateECDSAKey();
      
      if (!checkStatus(response, "generateECDSAKey")) {
        return 1;
      }
      
      // Remove the actual key values for comparison (they're random)
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("keyName")) {
        expectedResponse["keyName"] = "<random>";
      }
      if (expectedResponse.isMember("publicKey")) {
        expectedResponse["publicKey"] = "<random>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["keyName"] = "must_be_present";
      criteria["publicKey"] = "must_be_present";
      criteria["comparison"] = "structural";
      
      printTest("api_gen_ecdsa_001", "Generate ECDSA key (random)",
                "generateECDSAKey", request, expectedResponse, "functional", criteria);
    }

    cerr << "[5/9] Testing generateDKGPoly (functional, has randomness)..." << endl;
    // Test 5: Generate DKG polynomial (random)
    {
      int t = 3;
      
      Json::Value request;
      request["polyName"] = DETERMINISTIC_POLY_NAME;
      request["t"] = t;
      
      Json::Value response = client.generateDKGPoly(DETERMINISTIC_POLY_NAME, t);
      
      if (!checkStatus(response, "generateDKGPoly")) {
        return 1;
      }
      
      // Remove random poly name for comparison
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("polyName")) {
        expectedResponse["polyName"] = "<provided>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["comparison"] = "structural";
      
      printTest("api_gen_dkg_poly_001", "Generate DKG polynomial (random coefficients)",
                "generateDKGPoly", request, expectedResponse, "functional", criteria);
    }

    cerr << "[6/9] Testing getVerificationVector (functional)..." << endl;
    // Test 6: Get verification vector
    {
      int t = 3;
      // Use the poly from test 5 (don't regenerate it)
      
      Json::Value request;
      request["polyName"] = DETERMINISTIC_POLY_NAME;
      request["t"] = t;
      
      Json::Value response = client.getVerificationVector(DETERMINISTIC_POLY_NAME, t);
      
      if (!checkStatus(response, "getVerificationVector")) {
        return 1;
      }
      
      Json::Value expectedResponse;
      expectedResponse["status"] = 0;
      expectedResponse["verificationVector"] = "<array_of_G2_points>";
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["verificationVector"] = "must_be_array";
      criteria["vector_length"] = t; // Returns t elements (not t+1)
      criteria["comparison"] = "structural";
      
      printTest("api_get_verif_vect_001", "Get verification vector for DKG poly",
                "getVerificationVector", request, expectedResponse, "functional", criteria);
    }

    cerr << "[7/20] Testing importECDSAKey (deterministic)..." << endl;
    // Test 7: Import ECDSA key with fixed value
    {
      string privateKey = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      
      Json::Value request;
      request["key"] = privateKey;
      request["keyName"] = DETERMINISTIC_ETH_KEY;
      
      Json::Value response = client.importECDSAKey(privateKey, DETERMINISTIC_ETH_KEY);
      
      if (!checkStatus(response, "importECDSAKey")) {
        return 1;
      }
      
      // Remove encrypted value from expected response (it's random due to SEK)
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("encryptedKey")) {
        expectedResponse["encryptedKey"] = "<encrypted>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["encryptedKey"] = "must_be_present";
      criteria["comparison"] = "structural";
      
      printTest("api_import_ecdsa_001", "Import ECDSA key (encryption is random)",
                "importECDSAKey", request, expectedResponse, "functional", criteria);
    }

    // Import additional ECDSA keys for DKG (need unique keys per participant)
    cerr << "Importing additional ECDSA keys for DKG tests..." << endl;
    {
      string privateKey2 = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
      client.importECDSAKey(privateKey2, DETERMINISTIC_ETH_KEY2);
      
      string privateKey3 = "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba";
      client.importECDSAKey(privateKey3, DETERMINISTIC_ETH_KEY3);
    }

    cerr << "[8/9] Testing getPublicECDSAKey (deterministic)..." << endl;
    // Test 8: Get ECDSA public key from imported key
    {
      Json::Value request;
      request["keyName"] = DETERMINISTIC_ETH_KEY;
      
      Json::Value response = client.getPublicECDSAKey(DETERMINISTIC_ETH_KEY);
      
      if (!checkStatus(response, "getPublicECDSAKey")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["publicKey"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_get_ecdsa_pubkey_001", "Get ECDSA public key",
                "getPublicECDSAKey", request, response, "deterministic", criteria);
    }

    cerr << "[9/15] Testing ecdsaSignMessageHash (deterministic)..." << endl;
    // Test 9: ECDSA sign with deterministic hash
    {
      int base = 16;
      
      Json::Value request;
      request["base"] = base;
      request["keyName"] = DETERMINISTIC_ETH_KEY;
      request["messageHash"] = DETERMINISTIC_HASH;
      
      Json::Value response = client.ecdsaSignMessageHash(base, DETERMINISTIC_ETH_KEY, DETERMINISTIC_HASH);
      
      if (!checkStatus(response, "ecdsaSignMessageHash")) {
        return 1;
      }
      
      // ECDSA signatures have randomness (k value) unless using RFC 6979
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("signature_r")) {
        expectedResponse["signature_r"] = "<signature_r>";
      }
      if (expectedResponse.isMember("signature_s")) {
        expectedResponse["signature_s"] = "<signature_s>";
      }
      if (expectedResponse.isMember("signature_v")) {
        expectedResponse["signature_v"] = "<signature_v>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["signature_r"] = "must_be_present";
      criteria["signature_s"] = "must_be_present";
      criteria["signature_v"] = "must_be_present";
      criteria["comparison"] = "structural";
      
      printTest("api_ecdsa_sign_001", "ECDSA sign (signature has randomness)",
                "ecdsaSignMessageHash", request, expectedResponse, "functional", criteria);
    }

    // ===== CORE CRYPTO OPERATIONS (libff/mcl primitives) =====
    
    cerr << "[10/15] Testing multG2 (deterministic, core G2 operation)..." << endl;
    // Test 10: G2 scalar multiplication - core libff/mcl operation
    {
      Json::Value request;
      request["x"] = DETERMINISTIC_G2_SCALAR;
      
      Json::Value response = client.multG2(DETERMINISTIC_G2_SCALAR);
      
      if (!checkStatus(response, "multG2")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["g2Point"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_mult_g2_001", "Multiply G2 generator by scalar",
                "multG2", request, response, "deterministic", criteria);
    }

    cerr << "[11/15] Testing generateBLSPrivateKey (deterministic with fixed name)..." << endl;
    // Test 11: Generate a full BLS private key
    {
      Json::Value request;
      request["blsKeyName"] = DETERMINISTIC_BLS_KEY2;
      
      Json::Value response = client.generateBLSPrivateKey(DETERMINISTIC_BLS_KEY2);
      
      if (!checkStatus(response, "generateBLSPrivateKey")) {
        return 1;
      }
      
      // Note: generateBLSPrivateKey only returns status (no blsPublicKey in response)
      Json::Value expectedResponse = response;
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["comparison"] = "structural";
      
      printTest("api_gen_bls_key_001", "Generate full BLS private key",
                "generateBLSPrivateKey", request, expectedResponse, "functional", criteria);
    }

    cerr << "[12/15] Testing popProve (deterministic)..." << endl;
    // Test 12: Proof of possession for BLS key
    {
      Json::Value request;
      request["blsKeyName"] = DETERMINISTIC_BLS_KEY;
      
      Json::Value response = client.popProve(DETERMINISTIC_BLS_KEY);
      
      if (!checkStatus(response, "popProve")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["popProof"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_pop_prove_001", "Generate proof of possession for BLS key",
                "popProve", request, response, "deterministic", criteria);
    }

    // ===== FULL DKG WORKFLOW =====
    
    // Get 3 unique ECDSA public keys for DKG participants
    Json::Value ecdsaPubKeyResponse1 = client.getPublicECDSAKey(DETERMINISTIC_ETH_KEY);
    string ecdsaPubKey1 = ecdsaPubKeyResponse1["publicKey"].asString();
    
    Json::Value ecdsaPubKeyResponse2 = client.getPublicECDSAKey(DETERMINISTIC_ETH_KEY2);
    string ecdsaPubKey2 = ecdsaPubKeyResponse2["publicKey"].asString();
    
    Json::Value ecdsaPubKeyResponse3 = client.getPublicECDSAKey(DETERMINISTIC_ETH_KEY3);
    string ecdsaPubKey3 = ecdsaPubKeyResponse3["publicKey"].asString();
    
    cerr << "[13/20] Testing getSecretShare (deterministic)..." << endl;
    // Test 13: Get secret share from DKG polynomial
    {
      int t = 3, n = 3;
      
      // Create public keys array with 3 unique ECDSA public keys
      Json::Value publicKeys;
      publicKeys.append(ecdsaPubKey1);
      publicKeys.append(ecdsaPubKey2);
      publicKeys.append(ecdsaPubKey3);
      
      Json::Value request;
      request["polyName"] = DETERMINISTIC_POLY_NAME;
      request["publicKeys"] = publicKeys;
      request["t"] = t;
      request["n"] = n;
      
      Json::Value response = client.getSecretShare(DETERMINISTIC_POLY_NAME, publicKeys, t, n);
      
      if (!checkStatus(response, "getSecretShare")) {
        return 1;
      }
      
      // Secret shares depend on random polynomial from test 5
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("secretShare")) {
        expectedResponse["secretShare"] = "<random_depends_on_poly>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["secretShare"] = "must_be_present";
      criteria["comparison"] = "structural";
      
      printTest("api_get_secret_share_001", "Compute secret shares (depends on random poly)",
                "getSecretShare", request, expectedResponse, "functional", criteria);
    }

    cerr << "[14/20] Testing dkgVerification (deterministic)..." << endl;
    // Test 14: Verify DKG secret share
    {
      int t = 3, n = 3, index = 0;
      
      // First get verification vector
      Json::Value verifVector = client.getVerificationVector(DETERMINISTIC_POLY_NAME, t);
      
      // Get secret shares using real ECDSA public keys
      Json::Value publicKeys;
      publicKeys.append(ecdsaPubKey1);
      publicKeys.append(ecdsaPubKey2);
      publicKeys.append(ecdsaPubKey3);
      
      Json::Value secretShareResponse = client.getSecretShare(DETERMINISTIC_POLY_NAME, publicKeys, t, n);
      string allSecretShares = secretShareResponse["secretShare"].asString();
      // Each secret share is 192 hex chars (96 bytes). Extract share for index 0
      string secretShare = allSecretShares.substr(index * 192, 192);
      
      // Convert verification vector to concatenated hex string (not JSON)
      // The verification vector returns decimal strings, but dkgVerification needs hex
      // Each G2 point has 4 components, each must be 64 hex chars = 256 chars total per point
      // Need t points concatenated
      string publicShares = "";
      for (int i = 0; i < t; i++) {
        for (int j = 0; j < 4; j++) {
          string decStr = verifVector["verificationVector"][i][j].asString();
          string hexComponent = convertDecToHex(decStr, 32); // 32 bytes = 64 hex chars
          publicShares += hexComponent;
        }
      }
      
      Json::Value request;
      request["publicShares"] = publicShares;
      request["ethKeyName"] = DETERMINISTIC_ETH_KEY;
      request["secretShare"] = secretShare;
      request["t"] = t;
      request["n"] = n;
      request["index"] = index;
      
      Json::Value response = client.dkgVerification(publicShares, DETERMINISTIC_ETH_KEY, secretShare, t, n, index);
      
      if (!checkStatus(response, "dkgVerification")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["result"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_dkg_verification_001", "Verify DKG secret share with verification vector",
                "dkgVerification", request, response, "deterministic", criteria);
    }

    cerr << "[15/20] Testing createBLSPrivateKey (deterministic)..." << endl;
    // Test 15: Create BLS private key from verified secret share
    // Note: createBLSPrivateKey consumes the polynomial, so use a separate poly for this test
    {
      int t = 3, n = 3;
      
      // Generate a separate polynomial for this test (createBLSPrivateKey consumes it)
      client.generateDKGPoly(DETERMINISTIC_POLY_NAME2, t);
      
      // Get secret shares using real ECDSA public keys
      Json::Value publicKeys;
      publicKeys.append(ecdsaPubKey1);
      publicKeys.append(ecdsaPubKey2);
      publicKeys.append(ecdsaPubKey3);
      
      Json::Value secretShareResponse = client.getSecretShare(DETERMINISTIC_POLY_NAME2, publicKeys, t, n);
      string allSecretShares = secretShareResponse["secretShare"].asString();
      // createBLSPrivateKey needs all n secret shares concatenated (n * 192 chars)
      
      string blsKeyName = "BLS_KEY:SCHAIN_ID:99:NODE_ID:99:DKG_ID:99";
      
      Json::Value request;
      request["blsKeyName"] = blsKeyName;
      request["ethKeyName"] = DETERMINISTIC_ETH_KEY;
      request["polyName"] = DETERMINISTIC_POLY_NAME2;
      request["secretShare"] = allSecretShares;
      request["t"] = t;
      request["n"] = n;
      
      Json::Value response = client.createBLSPrivateKey(blsKeyName, DETERMINISTIC_ETH_KEY, 
                                                         DETERMINISTIC_POLY_NAME2, allSecretShares, t, n);
      
      if (!checkStatus(response, "createBLSPrivateKey")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["encryptedKey"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_create_bls_key_001", "Create BLS key from DKG secret share",
                "createBLSPrivateKey", request, response, "deterministic", criteria);
    }

    // ===== V2 PROTOCOL TESTS (Updated DKG) =====
    
    cerr << "[16/20] Testing getSecretShareV2 (deterministic)..." << endl;
    // Test 16: Get secret share using V2 protocol
    {
      int t = 3, n = 3;
      
      Json::Value publicKeys;
      publicKeys.append(ecdsaPubKey1);
      publicKeys.append(ecdsaPubKey2);
      publicKeys.append(ecdsaPubKey3);
      
      Json::Value request;
      request["polyName"] = DETERMINISTIC_POLY_NAME;
      request["publicKeys"] = publicKeys;
      request["t"] = t;
      request["n"] = n;
      
      Json::Value response = client.getSecretShareV2(DETERMINISTIC_POLY_NAME, publicKeys, t, n);
      
      if (!checkStatus(response, "getSecretShareV2")) {
        return 1;
      }
      
      // Secret shares depend on random polynomial from test 5
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("secretShare")) {
        expectedResponse["secretShare"] = "<random_depends_on_poly>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["secretShare"] = "must_be_present";
      criteria["comparison"] = "structural";
      
      printTest("api_get_secret_share_v2_001", "Compute secret shares V2 (depends on random poly)",
                "getSecretShareV2", request, expectedResponse, "functional", criteria);
    }

    cerr << "[17/20] Testing dkgVerificationV2 (deterministic)..." << endl;
    // Test 17: Verify DKG secret share with V2 protocol
    {
      int t = 3, n = 3, index = 0;
      
      Json::Value verifVector = client.getVerificationVector(DETERMINISTIC_POLY_NAME, t);
      
      Json::Value publicKeys;
      publicKeys.append(ecdsaPubKey1);
      publicKeys.append(ecdsaPubKey2);
      publicKeys.append(ecdsaPubKey3);
      
      Json::Value secretShareResponse = client.getSecretShareV2(DETERMINISTIC_POLY_NAME, publicKeys, t, n);
      string allSecretShares = secretShareResponse["secretShare"].asString();
      // Each secret share is 192 hex chars (96 bytes). Extract share for index 0
      string secretShare = allSecretShares.substr(index * 192, 192);
      
      // Convert verification vector to concatenated hex string (not JSON)
      // The verification vector returns decimal strings, but dkgVerificationV2 needs hex
      // Each G2 point has 4 components, each must be 64 hex chars = 256 chars total per point
      // Need t points concatenated
      string publicShares = "";
      for (int i = 0; i < t; i++) {
        for (int j = 0; j < 4; j++) {
          string decStr = verifVector["verificationVector"][i][j].asString();
          string hexComponent = convertDecToHex(decStr, 32); // 32 bytes = 64 hex chars
          publicShares += hexComponent;
        }
      }
      
      Json::Value request;
      request["publicShares"] = publicShares;
      request["ethKeyName"] = DETERMINISTIC_ETH_KEY;
      request["secretShare"] = secretShare;
      request["t"] = t;
      request["n"] = n;
      request["index"] = index;
      
      Json::Value response = client.dkgVerificationV2(publicShares, DETERMINISTIC_ETH_KEY, secretShare, t, n, index);
      
      if (!checkStatus(response, "dkgVerificationV2")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["result"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_dkg_verification_v2_001", "Verify DKG share with V2 protocol",
                "dkgVerificationV2", request, response, "deterministic", criteria);
    }

    cerr << "[18/20] Testing createBLSPrivateKeyV2 (deterministic)..." << endl;
    // Test 18: Create BLS private key with V2 protocol
    // Note: createBLSPrivateKeyV2 consumes the polynomial, so use a separate poly for this test
    {
      int t = 3, n = 3;
      
      // Generate a separate polynomial for this test (createBLSPrivateKeyV2 consumes it)
      client.generateDKGPoly(DETERMINISTIC_POLY_NAME3, t);
      
      Json::Value publicKeys;
      publicKeys.append(ecdsaPubKey1);
      publicKeys.append(ecdsaPubKey2);
      publicKeys.append(ecdsaPubKey3);
      
      Json::Value secretShareResponse = client.getSecretShareV2(DETERMINISTIC_POLY_NAME3, publicKeys, t, n);
      string allSecretShares = secretShareResponse["secretShare"].asString();
      // createBLSPrivateKeyV2 needs all n secret shares concatenated (n * 192 chars)
      
      string blsKeyName = "BLS_KEY:SCHAIN_ID:100:NODE_ID:100:DKG_ID:100";
      
      Json::Value request;
      request["blsKeyName"] = blsKeyName;
      request["ethKeyName"] = DETERMINISTIC_ETH_KEY;
      request["polyName"] = DETERMINISTIC_POLY_NAME3;
      request["secretShare"] = allSecretShares;
      request["t"] = t;
      request["n"] = n;
      
      Json::Value response = client.createBLSPrivateKeyV2(blsKeyName, DETERMINISTIC_ETH_KEY, 
                                                           DETERMINISTIC_POLY_NAME3, allSecretShares, t, n);
      
      if (!checkStatus(response, "createBLSPrivateKeyV2")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["encryptedKey"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_create_bls_key_v2_001", "Create BLS key with V2 protocol",
                "createBLSPrivateKeyV2", request, response, "deterministic", criteria);
    }

    // ===== BLS PUBLIC KEY AGGREGATION =====
    // Test 19: Aggregate BLS public keys from shares
    {
      int t = 3, n = 3;
      
      // Get verification vector which contains public key shares
      Json::Value verifVector = client.getVerificationVector(DETERMINISTIC_POLY_NAME, t);
      
      // Convert verification vector to hex format for each participant
      // Each participant needs all t G2 points concatenated (256 hex chars each = 768 total for t=3)
      Json::Value publicShares;
      for (int i = 0; i < n; i++) {
        string pubShare = "";
        for (int k = 0; k < t; k++) {
          for (int j = 0; j < 4; j++) {
            string decStr = verifVector["verificationVector"][k][j].asString();
            string hexComponent = convertDecToHex(decStr, 32); // 32 bytes = 64 hex chars
            pubShare += hexComponent;
          }
        }
        publicShares["publicShares"][i] = pubShare;
      }
      
      Json::Value request;
      request["publicShares"] = publicShares["publicShares"];
      request["t"] = t;
      request["n"] = n;
      
      Json::Value response = client.calculateAllBLSPublicKeys(publicShares, t, n);
      
      if (!checkStatus(response, "calculateAllBLSPublicKeys")) {
        return 1;
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["publicKeys"] = "must_match_exactly";
      criteria["comparison"] = "exact";
      
      printTest("api_calc_all_bls_pubkeys_001", "Aggregate BLS public keys from shares",
                "calculateAllBLSPublicKeys", request, response, "deterministic", criteria);
    }

    // ===== DKG FAULT TOLERANCE =====
    
    cerr << "[20/20] Testing complaintResponse (deterministic)..." << endl;
    // Test 20: Generate complaint response for DKG
    {
      int t = 3, n = 3, ind = 1;
      
      Json::Value request;
      request["polyName"] = DETERMINISTIC_POLY_NAME;
      request["t"] = t;
      request["n"] = n;
      request["ind"] = ind;
      
      Json::Value response = client.complaintResponse(DETERMINISTIC_POLY_NAME, t, n, ind);
      
      if (!checkStatus(response, "complaintResponse")) {
        return 1;
      }
      
      // Complaint response depends on random polynomial
      Json::Value expectedResponse = response;
      if (expectedResponse.isMember("dhKey")) {
        expectedResponse["dhKey"] = "<random_depends_on_poly>";
      }
      if (expectedResponse.isMember("share*G2")) {
        expectedResponse["share*G2"] = "<random_depends_on_poly>";
      }
      if (expectedResponse.isMember("verificationVectorMult")) {
        expectedResponse["verificationVectorMult"] = "<array_of_G2_points>";
      }
      
      Json::Value criteria;
      criteria["status"] = 0;
      criteria["dhKey"] = "must_be_present";
      criteria["share*G2"] = "must_be_present";
      criteria["verificationVectorMult"] = "must_be_array";
      criteria["comparison"] = "structural";
      
      printTest("api_complaint_response_001", "Generate DKG complaint response (depends on random poly)",
                "complaintResponse", request, expectedResponse, "functional", criteria, true);
    }

    printTestFooter();
    
    cerr << "\n=== SUCCESS ===" << endl;
    cerr << "Golden vectors generated successfully!" << endl;
    cerr << "Save the output to api_golden_vectors.json" << endl;
    
    return 0;
    
  } catch (JsonRpcException &e) {
    cerr << "JSON-RPC Error: " << e.what() << endl;
    return 1;
  } catch (exception &e) {
    cerr << "Error: " << e.what() << endl;
    return 1;
  }
}
