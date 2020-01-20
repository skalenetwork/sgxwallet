//
// Created by kladko on 12/24/19.
//

#include "CSRManagerServer.h"
#include "RPCException.h"
#include "sgxwallet_common.h"

#include <iostream>
#include <fstream>

#include <jsonrpccpp/server/connectors/httpserver.h>

#include "spdlog/spdlog.h"


CSRManagerServer *cs = nullptr;
jsonrpc::HttpServer *hs3 = nullptr;


CSRManagerServer::CSRManagerServer(AbstractServerConnector &connector,
    serverVersion_t type):abstractCSRManagerServer(connector, type){}


Json::Value GetUnsignedCSRsImpl(){
  spdlog::info("Enter GetUnsignedCSRsImpl");
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  //result["hashes"] =;

  try{
    std::vector<std::string> hashes_vect = csrDb->writeKeysToVector1(MAX_CSR_NUM);
    for (int i = 0; i < hashes_vect.size(); i++){
      result["hashes"][i] = hashes_vect.at(i);
    }
  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;

  }

  return result;
}

Json::Value SignByHashImpl(const std::string& hash, int status){
  Json::Value result;
  result["errorMessage"] = "";

  try{
    if ( !(status == 0 || status == 2)){
      throw RPCException(-111, "Invalid csr status");
    }

    std::string csr_db_key = "CSR:HASH:" + hash;
    std::shared_ptr<std::string> csr_ptr = csrDb->readString(csr_db_key);
    if (csr_ptr == nullptr){
      throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "HASH DOES NOT EXIST IN DB");
    }

    if (status == 0) {
      std::string csr_name = "cert/" + hash + ".csr";
      std::ofstream outfile(csr_name);
      outfile << *csr_ptr << std::endl;
      outfile.close();
      if (access(csr_name.c_str(), F_OK) != 0) {
        csrDb->deleteKey(csr_db_key);
        throw RPCException(FILE_NOT_FOUND, "Csr does not exist");
      }

      std::string signClientCert = "cd cert && ./create_client_cert " + hash;

      if (system(signClientCert.c_str()) == 0) {
        spdlog::info("CLIENT CERTIFICATE IS SUCCESSFULLY GENERATED");
      } else {
        spdlog::info("CLIENT CERTIFICATE GENERATION FAILED");
        csrDb->deleteKey(csr_db_key);
        std::string status_db_key = "CSR:HASH:" + hash + "STATUS:";
        csrStatusDb->deleteKey(status_db_key);
        csrStatusDb->writeDataUnique(status_db_key, "-1");
        throw RPCException(FAIL_TO_CREATE_CERTIFICATE, "CLIENT CERTIFICATE GENERATION FAILED");
        //exit(-1);
      }
    }

    csrDb->deleteKey(csr_db_key);
    std::string status_db_key = "CSR:HASH:" + hash + "STATUS:";
    csrStatusDb->deleteKey(status_db_key);
    csrStatusDb->writeDataUnique(status_db_key, std::to_string(status));

    result["status"] = status;

  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
  }

  return result;
}


Json::Value CSRManagerServer::GetUnsignedCSRs(){
  std::lock_guard<std::recursive_mutex> lock(m);
  return GetUnsignedCSRsImpl();
}

Json::Value CSRManagerServer::SignByHash(const std::string& hash, int status){
   std::lock_guard<std::recursive_mutex> lock(m);
   return SignByHashImpl(hash, status);
}

int init_csrmanager_server(){
  hs3 = new jsonrpc::HttpServer(BASE_PORT + 2);
  hs3 -> BindLocalhost();
  cs = new CSRManagerServer(*hs3, JSONRPC_SERVER_V2); // server (json-rpc 2.0)

  if (!cs->StartListening()) {
    spdlog::info("CSR manager server could not start listening");
    exit(-1);
  }
  else {
    spdlog::info("CSR manager server started on port {}", BASE_PORT + 2);
  }
  return 0;
};