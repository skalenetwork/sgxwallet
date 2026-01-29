/*
    Copyright (C) 2019-Present SKALE Labs
    ...
*/

#define GMP_WITH_SGX 1

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// Mcl Support
#include "DKGUtils.h"
#include "MclUtils.h"

// Needed for mpz_t types in DomainParameters
#include <sgx_tgmp.h>

#include "EnclaveCommon.h"
#include "EnclaveConstants.h"
#include "secure_enclave_t.h"

using namespace std;

thread_local uint8_t decryptedDkgPoly[DKG_BUFER_LENGTH];

uint8_t *getThreadLocalDecryptedDkgPoly() { return decryptedDkgPoly; }

string *stringFromKey(Fr *_key) {
  string *ret = nullptr;
  try {
    char buf[1024];
    // getStr usually returns size irrespective of exception mode
    size_t len = _key->getStr(buf, sizeof(buf), 10);
    if (len == 0) {
      LOG_ERROR("stringFromKey: getStr failed");
      return nullptr;
    }
    ret = new string(buf);
  } catch (...) {
    LOG_ERROR("Unknown throwable");
  }
  return ret;
}

string *stringFromFq(Fp *_fq) {
  string *ret = nullptr;
  try {
    char buf[1024];
    size_t len = _fq->getStr(buf, sizeof(buf), 10);
    if (len == 0)
      return nullptr;
    ret = new string(buf);
  } catch (...) {
    LOG_ERROR("Unknown throwable");
  }
  return ret;
}

string *stringFromG1(G1 *_g1) {
  string *ret = nullptr;
  try {
    G1 P = *_g1;
    P.normalize();
    char bufX[1024];
    char bufY[1024];
    P.x.getStr(bufX, sizeof(bufX), 10);
    P.y.getStr(bufY, sizeof(bufY), 10);
    string sX(bufX);
    string sY(bufY);
    ret = new string(sX + ":" + sY);
  } catch (...) {
    LOG_ERROR("Unknown throwable");
  }
  return ret;
}

Fr *keyFromString(const char *_keyStringHex) {
  Fr *ret = nullptr;
  try {
    Fr val;
    // Use helper that handles modular reduction if needed
    if (!trySettingFrFromString(val, _keyStringHex, 16)) {
      LOG_ERROR("keyFromString: trySettingFrFromString failed");
      return nullptr;
    }

    // Log the actual key value in decimal for debugging
    char keyBuf[1024];
    size_t len = val.getStr(keyBuf, sizeof(keyBuf), 10);
    if (len > 0) {
      LOG_DEBUG("keyFromString: final key value (dec) = ");
      LOG_DEBUG(keyBuf);
    }

    ret = new Fr(val);
  } catch (...) {
    LOG_ERROR("Unknown throwable");
  }
  return ret;
}

// Global state
static int inited = 0;
domain_parameters curve;

void enclave_init() {
  LOG_INFO(__FUNCTION__);

  if (inited == 1)
    return;
  inited = 1;

  LOG_INFO("Initing mcl");
  initMcl();

  LOG_INFO("Initing params");
  curve = domain_parameters_init();
  if (!curve) {
    LOG_ERROR("Failed to init curve");
    goto fail;
  }
  domain_parameters_load_curve(curve, secp256k1);
  LOG_INFO("Initing done");
  return;

fail:
  domain_parameters_clear(curve);
  abort();
}

void enclave_clear() {
  if (inited == 0)
    return;
  inited = 0;
  domain_parameters_clear(curve);
}

bool enclave_sign(const char *_keyString, const char *_hashXString,
                  const char *_hashYString, char *sig) {
  bool ret = false;
  Fr *key = nullptr;
  string *r = nullptr;

  if (!_keyString || !_hashXString || !_hashYString || !sig) {
    LOG_ERROR("Null argument");
    return false;
  }

  LOG_DEBUG("enclave_sign: key_hex = ");
  LOG_DEBUG(_keyString);
  LOG_DEBUG("enclave_sign: hashX = ");
  LOG_DEBUG(_hashXString);
  LOG_DEBUG("enclave_sign: hashY = ");
  LOG_DEBUG(_hashYString);

  try {
    key = keyFromString(_keyString);
    if (!key) {
      LOG_ERROR("Null key");
      goto clean;
    }

    bool b = false;
    Fp hashX;
    hashX.setStr(&b, _hashXString, 10);
    if (!b) {
      LOG_ERROR("Failed to set hashX");
      goto clean;
    }

    Fp hashY;
    hashY.setStr(&b, _hashYString, 10);
    if (!b) {
      LOG_ERROR("Failed to set hashY");
      goto clean;
    }

    G1 hash;
    hash.set(&b, hashX, hashY);
    if (!b) {
      LOG_ERROR("Failed to set hash G1");
      goto clean;
    }

    if (!hash.isValid()) {
      LOG_ERROR("Invalid hash point");
      goto clean;
    }

    G1 sign;
    G1::mul(sign, hash, *key);

    r = stringFromG1(&sign);
    if (!r) {
      LOG_ERROR("Sign serialization failed");
      goto clean;
    }

    memset(sig, 0, ENCLAVE_BUF_LEN);
    strncpy(sig, r->c_str(), ENCLAVE_BUF_LEN - 1);

    ret = true;

  } catch (exception &e) {
    LOG_ERROR(e.what());
  } catch (...) {
    LOG_ERROR("Unknown throwable");
  }

clean:
  SAFE_DELETE(key);
  SAFE_DELETE(r);
  return ret;
}

// ... helpers
void carray2Hex(const unsigned char *d, int _len, char *_hexArray) {
  const char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (int j = 0; j < _len; j++) {
    _hexArray[j * 2] = hexval[((d[j] >> 4) & 0xF)];
    _hexArray[j * 2 + 1] = hexval[(d[j]) & 0x0F];
  }
  _hexArray[_len * 2] = 0;
}

int char2int(char _input) {
  if (_input >= '0' && _input <= '9')
    return _input - '0';
  if (_input >= 'A' && _input <= 'F')
    return _input - 'A' + 10;
  if (_input >= 'a' && _input <= 'f')
    return _input - 'a' + 10;
  return -1;
}

bool hex2carray2(const char *_hex, uint64_t *_bin_len, uint8_t *_bin,
                 const int _max_length) {
  int len = strnlen(_hex, _max_length);
  if (len == 0 && len % 2 == 1)
    return false;
  *_bin_len = len / 2;
  for (int i = 0; i < len / 2; i++) {
    int high = char2int((char)_hex[i * 2]);
    int low = char2int((char)_hex[i * 2 + 1]);
    if (high < 0 || low < 0)
      return false;
    _bin[i] = (unsigned char)(high * 16 + low);
  }
  return true;
}

bool hex2carray(const char *_hex, uint64_t *_bin_len, uint8_t *_bin) {
  int len = strnlen(_hex, 2 * ENCLAVE_BUF_LEN);
  if (len == 0 && len % 2 == 1)
    return false;
  *_bin_len = len / 2;
  for (int i = 0; i < len / 2; i++) {
    int high = char2int((char)_hex[i * 2]);
    int low = char2int((char)_hex[i * 2 + 1]);
    if (high < 0 || low < 0)
      return false;
    _bin[i] = (unsigned char)(high * 16 + low);
  }
  return true;
}

enum log_level {
  L_TRACE = 0,
  L_DEBUG = 1,
  L_INFO = 2,
  L_WARNING = 3,
  L_ERROR = 4
};
uint32_t globalLogLevel_ = 2;

void logMsg(log_level _level, const char *_msg) {
  if (_level < globalLogLevel_)
    return;
  if (!_msg) {
    oc_printf("Null msg in logMsg");
    return;
  }
  oc_printf("***ENCLAVE_LOG***:");
  oc_printf(_msg);
  oc_printf("\n");
}

void LOG_INFO(const char *_msg) { logMsg(L_INFO, _msg); };
void LOG_WARN(const char *_msg) { logMsg(L_WARNING, _msg); };
void LOG_ERROR(const char *_msg) { logMsg(L_ERROR, _msg); };
void LOG_DEBUG(const char *_msg) { logMsg(L_DEBUG, _msg); };
void LOG_TRACE(const char *_msg) { logMsg(L_TRACE, _msg); };
