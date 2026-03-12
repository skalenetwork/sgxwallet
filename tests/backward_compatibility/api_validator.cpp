/*
  API Compatibility Validator

  This program reads golden API vectors and validates them against
  a running sgxwallet server (new mcl version).

  Usage:
    1. Start sgxwallet server (new mcl version)
    2. Run: ./api_validator api_golden_vectors.json

  Validation modes:
  - deterministic: Byte-exact comparison of responses
  - functional: Structural validation (success/failure, field presence)
*/

#include "stubclient.h"
#include <fstream>
#include <iostream>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <string>

using namespace std;
using namespace jsonrpc;

int totalTests = 0;
int passedTests = 0;
int failedTests = 0;

bool compareJsonValues(const Json::Value &expected, const Json::Value &actual,
                       const string &path = "root") {
  if (expected.type() != actual.type()) {
    cerr << "  Type mismatch at " << path << ": expected " << expected.type()
         << ", got " << actual.type() << endl;
    return false;
  }

  if (expected.isObject()) {
    for (const string &key : expected.getMemberNames()) {
      if (!actual.isMember(key)) {
        cerr << "  Missing field at " << path << "." << key << endl;
        return false;
      }
      if (!compareJsonValues(expected[key], actual[key], path + "." + key)) {
        return false;
      }
    }
    return true;
  } else if (expected.isArray()) {
    if (expected.size() != actual.size()) {
      cerr << "  Array size mismatch at " << path << ": expected "
           << expected.size() << ", got " << actual.size() << endl;
      return false;
    }
    for (Json::ArrayIndex i = 0; i < expected.size(); i++) {
      if (!compareJsonValues(expected[i], actual[i],
                             path + "[" + to_string(i) + "]")) {
        return false;
      }
    }
    return true;
  } else {
    // Primitive types
    if (expected != actual) {
      cerr << "  Value mismatch at " << path << ":" << endl;
      cerr << "    Expected: " << expected.toStyledString() << endl;
      cerr << "    Actual:   " << actual.toStyledString() << endl;
      return false;
    }
    return true;
  }
}

bool validateStructural(const Json::Value &actual,
                        const Json::Value &criteria) {
  // Check if required fields are present
  for (const string &key : criteria.getMemberNames()) {
    if (key == "status") {
      if (!actual.isMember("status") ||
          actual["status"].asInt() != criteria["status"].asInt()) {
        cerr << "  Status check failed" << endl;
        return false;
      }
    } else if (key == "comparison") {
      // Skip metadata
      continue;
    } else if (key == "vector_length") {
      if (!actual.isMember("verificationVector")) {
        cerr << "  Missing verificationVector field" << endl;
        return false;
      }
      if (actual["verificationVector"].size() !=
          criteria["vector_length"].asUInt()) {
        cerr << "  verificationVector length mismatch: expected "
             << criteria["vector_length"].asUInt() << ", got "
             << actual["verificationVector"].size() << endl;
        return false;
      }
    } else {
      string expectedValue = criteria[key].asString();
      if (expectedValue == "must_be_present") {
        if (!actual.isMember(key)) {
          cerr << "  Missing required field: " << key << endl;
          return false;
        }
      } else if (expectedValue == "must_be_array") {
        if (!actual.isMember(key) || !actual[key].isArray()) {
          cerr << "  Field " << key << " must be an array" << endl;
          return false;
        }
      }
    }
  }
  return true;
}

bool runTest(StubClient &client, const Json::Value &test) {
  totalTests++;

  string testId = test["test_id"].asString();
  string description = test["description"].asString();
  string method = test["method"].asString();
  string validationType = test["validation_type"].asString();

  cout << "\n[" << totalTests << "] " << testId << ": " << description << endl;
  cout << "  Method: " << method << " (validation: " << validationType << ")"
       << endl;

  try {
    Json::Value request = test["request"];
    Json::Value expectedResponse = test["expected_response"];
    Json::Value criteria = test["validation_criteria"];
    Json::Value actualResponse;

    // Call the appropriate method
    if (method == "importBLSKeyShare") {
      actualResponse = client.importBLSKeyShare(
          request["keyShare"].asString(), request["keyShareName"].asString());
    } else if (method == "getBLSPublicKeyShare") {
      actualResponse =
          client.getBLSPublicKeyShare(request["blsKeyName"].asString());
    } else if (method == "blsSignMessageHash") {
      actualResponse = client.blsSignMessageHash(
          request["keyShareName"].asString(), request["messageHash"].asString(),
          request["t"].asInt(), request["n"].asInt());
    } else if (method == "generateECDSAKey") {
      actualResponse = client.generateECDSAKey();
    } else if (method == "generateDKGPoly") {
      actualResponse = client.generateDKGPoly(request["polyName"].asString(),
                                              request["t"].asInt());
    } else if (method == "getVerificationVector") {
      actualResponse = client.getVerificationVector(
          request["polyName"].asString(), request["t"].asInt());
    } else if (method == "importECDSAKey") {
      actualResponse = client.importECDSAKey(request["key"].asString(),
                                             request["keyName"].asString());
    } else if (method == "getPublicECDSAKey") {
      actualResponse = client.getPublicECDSAKey(request["keyName"].asString());
    } else if (method == "ecdsaSignMessageHash") {
      actualResponse = client.ecdsaSignMessageHash(
          request["base"].asInt(), request["keyName"].asString(),
          request["messageHash"].asString());
    } else if (method == "multG2") {
      actualResponse = client.multG2(request["x"].asString());
    } else if (method == "generateBLSPrivateKey") {
      actualResponse =
          client.generateBLSPrivateKey(request["blsKeyName"].asString());
    } else if (method == "getSecretShare") {
      actualResponse = client.getSecretShare(
          request["polyName"].asString(), request["publicKeys"],
          request["t"].asInt(), request["n"].asInt());
    } else if (method == "dkgVerification") {
      actualResponse = client.dkgVerification(
          request["publicShares"].asString(), request["ethKeyName"].asString(),
          request["secretShare"].asString(), request["t"].asInt(),
          request["n"].asInt(), request["index"].asInt());
    } else if (method == "createBLSPrivateKey") {
      actualResponse = client.createBLSPrivateKey(
          request["blsKeyName"].asString(), request["ethKeyName"].asString(),
          request["polyName"].asString(), request["secretShare"].asString(),
          request["t"].asInt(), request["n"].asInt());
    } else if (method == "getSecretShareV2") {
      actualResponse = client.getSecretShareV2(
          request["polyName"].asString(), request["publicKeys"],
          request["t"].asInt(), request["n"].asInt());
    } else if (method == "dkgVerificationV2") {
      actualResponse = client.dkgVerificationV2(
          request["publicShares"].asString(), request["ethKeyName"].asString(),
          request["secretShare"].asString(), request["t"].asInt(),
          request["n"].asInt(), request["index"].asInt());
    } else if (method == "createBLSPrivateKeyV2") {
      actualResponse = client.createBLSPrivateKeyV2(
          request["blsKeyName"].asString(), request["ethKeyName"].asString(),
          request["polyName"].asString(), request["secretShare"].asString(),
          request["t"].asInt(), request["n"].asInt());
    } else if (method == "calculateAllBLSPublicKeys") {
      Json::Value publicShares;
      publicShares["publicShares"] = request["publicShares"];
      actualResponse = client.calculateAllBLSPublicKeys(
          publicShares, request["t"].asInt(), request["n"].asInt());
    } else if (method == "complaintResponse") {
      actualResponse = client.complaintResponse(
          request["polyName"].asString(), request["t"].asInt(),
          request["n"].asInt(), request["ind"].asInt());
    } else {
      cerr << "  SKIP: Unknown method " << method << endl;
      return false;
    }

    // Validate based on type
    bool passed = false;
    if (validationType == "deterministic") {
      // Exact comparison
      passed = compareJsonValues(expectedResponse, actualResponse);
    } else if (validationType == "functional") {
      // Structural validation
      passed = validateStructural(actualResponse, criteria);
    } else {
      cerr << "  ERROR: Unknown validation type: " << validationType << endl;
      return false;
    }

    if (passed) {
      cout << "  ✓ PASS" << endl;
      passedTests++;
      return true;
    } else {
      cout << "  ✗ FAIL" << endl;
      failedTests++;
      return false;
    }

  } catch (JsonRpcException &e) {
    cout << "  ✗ FAIL: JSON-RPC Error: " << e.what() << endl;
    failedTests++;
    return false;
  } catch (exception &e) {
    cout << "  ✗ FAIL: " << e.what() << endl;
    failedTests++;
    return false;
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " <golden_vectors.json> [endpoint]" << endl;
    cerr << "Example: " << argv[0]
         << " api_golden_vectors.json http://localhost:1029" << endl;
    return 1;
  }

  string vectorFile = argv[1];
  string endpoint = "http://localhost:1029";
  if (argc > 2) {
    endpoint = argv[2];
  }

  cout << "=== API Compatibility Validator ===" << endl;
  cout << "Golden vectors: " << vectorFile << endl;
  cout << "SGXWallet endpoint: " << endpoint << endl;
  cout << endl;

  // Load golden vectors
  ifstream file(vectorFile);
  if (!file.is_open()) {
    cerr << "ERROR: Could not open " << vectorFile << endl;
    return 1;
  }

  Json::Value root;
  Json::CharReaderBuilder builder;
  string errs;

  if (!Json::parseFromStream(builder, file, &root, &errs)) {
    cerr << "ERROR: Failed to parse JSON: " << errs << endl;
    return 1;
  }

  file.close();

  cout << "Format version: " << root["format_version"].asString() << endl;
  cout << "Test type: " << root["test_type"].asString() << endl;
  cout << "Timestamp: " << root["timestamp"].asString() << endl;
  cout << "Description: " << root["description"].asString() << endl;
  cout << endl;

  // Connect to server
  try {
    HttpClient httpClient(endpoint);
    StubClient client(httpClient, JSONRPC_CLIENT_V2);

    // Run tests
    const Json::Value &tests = root["tests"];
    cout << "Running " << tests.size() << " tests..." << endl;

    for (const Json::Value &test : tests) {
      runTest(client, test);
    }

    // Summary
    cout << "\n=== SUMMARY ===" << endl;
    cout << "Total tests: " << totalTests << endl;
    cout << "Passed: " << passedTests << " ("
         << (passedTests * 100 / totalTests) << "%)" << endl;
    cout << "Failed: " << failedTests << endl;

    if (failedTests == 0) {
      cout << "\n✓ ALL TESTS PASSED - Current backend is compatible!" << endl;
      return 0;
    } else {
      cout << "\n✗ SOME TESTS FAILED - Review failures above" << endl;
      return 1;
    }

  } catch (exception &e) {
    cerr << "ERROR: " << e.what() << endl;
    return 1;
  }
}
