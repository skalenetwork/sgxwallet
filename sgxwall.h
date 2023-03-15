/*
    Copyright (C) 2020-Present SKALE Labs

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

    @file sgxwall.h
    @author Stan Kladko
    @date 2020
*/

class SGXWallet {

public:
  static void signalHandler(int signalNo);

  static void printUsage();

  static void serializeKeys(const vector<string> &_ecdsaKeyNames,
                            const vector<string> &_blsKeyNames,
                            const string &_fileName);
};
