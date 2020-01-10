//
// Created by kladko on 12/24/19.
//

#ifndef SGXD_CSRMANAGERSERVER_H
#define SGXD_CSRMANAGERSERVER_H

#include "abstractCSRManagerServer.h"
#include "LevelDB.h"

#include <mutex>

using namespace jsonrpc;

class CSRManagerServer : public abstractCSRManagerServer {

  std::recursive_mutex m;

  public:

  CSRManagerServer(AbstractServerConnector &connector, serverVersion_t type);

  virtual Json::Value GetUnsignedCSRs();
  virtual Json::Value SignByHash(const std::string& hash, int status);
};

extern int init_csrmanager_server();




#endif //SGXD_CSRMANAGERSERVER_H
