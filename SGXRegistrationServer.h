//
// Created by kladko on 12/9/19.
//

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