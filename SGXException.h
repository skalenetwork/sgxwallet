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

    @file SGXException.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_SGXEXCEPTION_H
#define SGXD_SGXEXCEPTION_H

#include <exception>
#include <string>

using namespace std;

class SGXException : public exception {

  const int32_t status;
  const string errString;

public:
  SGXException(int32_t _status, const string &_errString)
      : status(_status), errString(_errString) {}

  const string getMessage() const {
    return "SGXException:status:" + to_string(status) + ":" + errString;
  }

  const string &getErrString() const { return errString; }

  const char *what() const noexcept override;

  const int32_t getStatus() const { return status; }
};

#endif // SGXD_SGXEXCEPTION_H
