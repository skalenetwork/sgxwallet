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

    @file EnclaveCommon.cpp
    @author Stan Kladko
    @date 2019
*/

#define GMP_WITH_SGX 1

#include <string.h>
#include <cstdint>

#include "../third_party/SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_init.hpp"
#include "../third_party/SCIPR/libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp"

#include "secure_enclave_t.h"

#include "EnclaveConstants.h"
#include "EnclaveCommon.h"

using namespace std;

thread_local uint8_t decryptedDkgPoly[DKG_BUFER_LENGTH];

uint8_t *getThreadLocalDecryptedDkgPoly() {
    return decryptedDkgPoly;
}


string *stringFromKey(libff::alt_bn128_Fr *_key) {
    string *ret = nullptr;
    mpz_t t;
    mpz_init(t);

    SAFE_CHAR_BUF(arr, BUF_LEN);

    try {
        _key->as_bigint().to_mpz(t);

        char *tmp = mpz_get_str(arr, 10, t);

        if (!tmp) {
            LOG_ERROR("stringFromKey: mpz_get_str failed");
            goto clean;
        }
        ret = new string(tmp);
    } catch (exception &e) {
        LOG_ERROR(e.what());
        goto clean;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        goto clean;
    }

    clean:
    mpz_clear(t);
    return ret;
}

string *stringFromFq(libff::alt_bn128_Fq *_fq) {

    string *ret = nullptr;
    mpz_t t;
    mpz_init(t);
    SAFE_CHAR_BUF(arr, BUF_LEN);

    try {
        _fq->as_bigint().to_mpz(t);
        char *tmp = mpz_get_str(arr, 10, t);
        ret = new string(tmp);
    } catch (exception &e) {
        LOG_ERROR(e.what());
        goto clean;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        goto clean;
    }

    clean:
    mpz_clear(t);
    return ret;
}

string *stringFromG1(libff::alt_bn128_G1 *_g1) {

    string *sX = nullptr;
    string *sY = nullptr;
    string *ret = nullptr;


    try {
        _g1->to_affine_coordinates();

        auto sX = stringFromFq(&_g1->X);

        if (!sX) {
            goto clean;
        }

        auto sY = stringFromFq(&_g1->Y);

        if (!sY) {
            goto clean;
        }

        ret = new string(*sX + ":" + *sY);

    } catch (exception &e) {
        LOG_ERROR(e.what());
        goto clean;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        goto clean;
    }

    clean:

    SAFE_FREE(sX);
    SAFE_FREE(sY);

    return ret;

}

libff::alt_bn128_Fr *keyFromString(const char *_keyStringHex) {

    mpz_t skey;
    mpz_init(skey);
    SAFE_CHAR_BUF(skey_dec, BUF_LEN);
    libff::alt_bn128_Fr *ret = nullptr;

    if (mpz_set_str(skey, _keyStringHex, 16) == -1) {
        goto clean;
    }

    mpz_get_str(skey_dec, 10, skey);

    ret = new libff::alt_bn128_Fr(skey_dec);

    goto clean;

    clean:

    mpz_clear(skey);
    return ret;
}

int inited = 0;

domain_parameters curve;

void enclave_init() {

    LOG_INFO(__FUNCTION__ );

    if (inited == 1)
        return;
    inited = 1;


    LOG_INFO("Initing libff");
    try {

        LOG_INFO("Initing params");

        libff::init_alt_bn128_params();

        LOG_INFO("Initing curve");
        curve = domain_parameters_init();
        LOG_INFO("Initing curve domain");
        domain_parameters_load_curve(curve, secp256k1);
    } catch (exception& e) {
        LOG_ERROR("Exception in libff init");
        LOG_ERROR(e.what());
        abort();
    } catch (...) {
        LOG_ERROR("Unknown exception in libff");
        abort();
    }
    LOG_INFO("Inited libff");
}

bool enclave_sign(const char *_keyString, const char *_hashXString, const char *_hashYString,
                  char *sig) {
    bool ret = false;

    libff::alt_bn128_Fr* key = nullptr;
    string * r = nullptr;

    if (!_keyString) {
        LOG_ERROR("Null key string");
        goto clean;
    }

    if (!_hashXString) {
        LOG_ERROR("Null hashX");
        goto clean;
    }

    if (!_hashYString) {
        LOG_ERROR("Null hashY");
        goto clean;
    }

    if (!sig) {
        LOG_ERROR("Null sig");
        goto clean;
    }

    try {
        auto key = keyFromString(_keyString);

        if (!key) {
            LOG_ERROR("Null key");
            goto clean;
        }

        libff::alt_bn128_Fq hashX(_hashXString);
        libff::alt_bn128_Fq hashY(_hashYString);
        libff::alt_bn128_Fq hashZ = 1;

        libff::alt_bn128_G1 hash(hashX, hashY, hashZ);

        libff::alt_bn128_G1 sign = key->as_bigint() * hash;

        sign.to_affine_coordinates();

        auto r = stringFromG1(&sign);

        memset(sig, 0, BUF_LEN);

        strncpy(sig, r->c_str(), BUF_LEN);

        ret =  true;

    } catch (exception &e) {
        LOG_ERROR(e.what());
        goto clean;
    } catch (...) {
        LOG_ERROR("Unknown throwable");
        goto clean;
    }

    clean:

    SAFE_DELETE(key);
    SAFE_DELETE(r);
    return ret;

}

void carray2Hex(const unsigned char *d, int _len, char *_hexArray) {
    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
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

bool hex2carray2(const char *_hex, uint64_t *_bin_len,
                 uint8_t *_bin, const int _max_length) {
    int len = strnlen(_hex, _max_length);

    if (len == 0 && len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (int i = 0; i < len / 2; i++) {
        int high = char2int((char) _hex[i * 2]);
        int low = char2int((char) _hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        _bin[i] = (unsigned char) (high * 16 + low);
    }

    return true;
}

bool hex2carray(const char *_hex, uint64_t *_bin_len,
                uint8_t *_bin) {
    int len = strnlen(_hex, 2 * BUF_LEN);

    if (len == 0 && len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (int i = 0; i < len / 2; i++) {
        int high = char2int((char) _hex[i * 2]);
        int low = char2int((char) _hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        _bin[i] = (unsigned char) (high * 16 + low);
    }

    return true;
}

enum log_level {
    L_TRACE = 0, L_DEBUG = 1, L_INFO = 2, L_WARNING = 3, L_ERROR = 4
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


void LOG_INFO(const char *_msg) {
    logMsg(L_INFO, _msg);
};
void LOG_WARN(const char *_msg) {
    logMsg(L_WARNING, _msg);
};

void LOG_ERROR(const char *_msg) {
    logMsg(L_ERROR, _msg);
};
void LOG_DEBUG(const char *_msg) {
    logMsg(L_DEBUG, _msg);
};
void LOG_TRACE(const char *_msg) {
    logMsg(L_TRACE, _msg);
};
