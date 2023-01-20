/*
    Copyright (C) 2021-Present SKALE Labs

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

    @file CryptoTools.cpp
    @author Oleh Nikolaiev
    @date 2021
*/

#include <vector>

#include "common.h"
#include "CryptoTools.h"

using std::vector;

int char2int(char _input) {
    if (_input >= '0' && _input <= '9')
        return _input - '0';
    if (_input >= 'A' && _input <= 'F')
        return _input - 'A' + 10;
    if (_input >= 'a' && _input <= 'f')
        return _input - 'a' + 10;
    return -1;
}

vector<char> carray2Hex(const unsigned char *d, uint64_t _len) {

    CHECK_STATE(d);

    vector<char> _hexArray( 2 * _len + 1);

    char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    for (uint64_t j = 0; j < _len; j++) {
        _hexArray[j * 2] = hexval[((d[j] >> 4) & 0xF)];
        _hexArray[j * 2 + 1] = hexval[(d[j]) & 0x0F];
    }

    _hexArray[_len * 2] = 0;

    return _hexArray;
}

bool hex2carray(const char *_hex, uint64_t *_bin_len,
                uint8_t *_bin, uint64_t _max_length) {
    CHECK_STATE(_hex);
    CHECK_STATE(_bin);
    CHECK_STATE(_bin_len)

    uint64_t len = strnlen(_hex, 2 * _max_length + 1);

    CHECK_STATE(len != 2 * _max_length + 1);

    CHECK_STATE(len <= 2 * _max_length);

    if (len % 2 == 1)
        return false;

    *_bin_len = len / 2;

    for (uint64_t i = 0; i < len / 2; i++) {
        int high = char2int((char) _hex[i * 2]);
        int low = char2int((char) _hex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        _bin[i] = (unsigned char) (high * 16 + low);
    }

    return true;
}

vector <std::string> splitString(const char *coeffs, const char symbol) {
    CHECK_STATE(coeffs);
    std::string str(coeffs);
    std::string delim;
    delim.push_back(symbol);
    vector <std::string> G2Strings;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == std::string::npos) pos = str.length();
        std::string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            std::string coeff(token.c_str());
            G2Strings.push_back(coeff);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return G2Strings;
}
