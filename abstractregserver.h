//
// Created by kladko on 12/9/19.
//

#ifndef SGXD_ABSTRACTREGSERVER_H
#define SGXD_ABSTRACTREGSERVER_H

#include <jsonrpccpp/server.h>

class AbstractRegServer : public jsonrpc::AbstractServer<AbstractRegServer>
{
public:
  AbstractRegServer(jsonrpc::AbstractServerConnector &conn, jsonrpc::serverVersion_t type = jsonrpc::JSONRPC_SERVER_V2) : jsonrpc::AbstractServer<AbstractRegServer>(conn, type)
  {
    this->bindAndAddMethod(jsonrpc::Procedure("SignCertificate", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"certificate",jsonrpc::JSON_STRING, NULL), &AbstractRegServer::SignCertificateI);
    this->bindAndAddMethod(jsonrpc::Procedure("GetCertificate", jsonrpc::PARAMS_BY_NAME, jsonrpc::JSON_OBJECT,"hash",jsonrpc::JSON_STRING, NULL), &AbstractRegServer::GetCertificateI);
  }

  inline virtual void SignCertificateI(const Json::Value &request, Json::Value &response)
  {
    response = this->SignCertificate( request["certificate"].asString());
  }
  inline virtual void GetCertificateI(const Json::Value &request, Json::Value &response)
  {
    response = this->GetCertificate( request["hash"].asString());
  }


  virtual Json::Value SignCertificate(const std::string& cert) = 0;
  virtual Json::Value GetCertificate(const std::string& hash) = 0;

};

#endif // SGXD_ABSTRACTREGSERVER_H