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

    @file SGXRegistrationServer.h
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXD_SGXREGISTRATIONSERVER_H
#define SGXD_SGXREGISTRATIONSERVER_H


#include "abstractregserver.h"
#include <mutex>

using namespace jsonrpc;
using namespace std;

class SGXRegistrationServer: public AbstractRegServer {
  std::recursive_mutex m;
  bool is_cert_created;
  bool cert_auto_sign;

  //std::string hash;

public:

  SGXRegistrationServer(AbstractServerConnector &connector, serverVersion_t type, bool auto_sign = false);

  void set_cert_created(bool b);

  virtual Json::Value SignCertificate(const std::string& csr);
  virtual Json::Value GetCertificate(const std::string& hash);

};


extern int init_registration_server(bool sign_automatically = false);



#endif // SGXD_SGXREGISTRATIONSERVER_H