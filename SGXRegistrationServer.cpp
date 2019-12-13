//
// Created by kladko on 12/9/19.
//

#include <iostream>
#include <fstream>
#include <sstream>


#include <jsonrpccpp/server/connectors/httpserver.h>

#include <stdio.h>

#include "sgxwallet_common.h"

#include "RPCException.h"
#include "LevelDB.h"

#include <thread>
#include <time.h>

#include <functional>

#include "SGXRegistrationServer.h"

SGXRegistrationServer *sr = nullptr;
HttpServer *hs2 = nullptr;

bool cert_created = false;

void set_cert_created1(bool b){
  sleep(10);
  cert_created = b;
}


SGXRegistrationServer::SGXRegistrationServer(AbstractServerConnector &connector,
                                 serverVersion_t type)
    : AbstractRegServer(connector, type), is_cert_created(false) {}


Json::Value SignSertificateImpl(const std::string& cert){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  try{

  std::ofstream outfile ("cert/test.csr");
  outfile << cert << std::endl;
  outfile.close();
  result["result"] = true;
  std::thread thr(set_cert_created1, true);
  thr.detach();


 // std::thread timeout_thr (std::bind(&SGXRegistrationServer::set_cert_created, this, true));

  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["result"] = false;
  }

  return result;
}

Json::Value GetSertificateImpl(const std::string& hash){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  std::string cert;
  try{
    if (!cert_created){
      result["status"] = 1;
      result["cert"] = "";
    }
    else {
      std::ifstream infile("cert/test_cert.crt");
      if (!infile.is_open()) {
        throw RPCException(FILE_NOT_FOUND, "Certificate does not exist");
      } else {
        ostringstream ss;
        ss << infile.rdbuf();
        cert = ss.str();

        infile.close();
        result["cert"] = cert;
        result["status"] = 0;
      }
    }
  } catch (RPCException &_e) {
    std::cerr << " err str " << _e.errString << std::endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["status"] = 1;
  }

  return result;
}


Json::Value SGXRegistrationServer::SignCertificate(const std::string& cert){
  lock_guard<recursive_mutex> lock(m);
  return SignSertificateImpl(cert);
}

Json::Value SGXRegistrationServer::GetCertificate(const std::string& hash){
  lock_guard<recursive_mutex> lock(m);
  return GetSertificateImpl(hash);
}

void SGXRegistrationServer::set_cert_created(bool b){
  sleep(100);
  is_cert_created = b;
}



int init_registration_server() {

  std::string certPath = "cert/SGXCACertificate.crt";
  std::string keyPath = "cert/SGXCACertificate.key";

  if (access(certPath.c_str(), F_OK) != 0){
    std::cerr << "CERTIFICATE IS GOING TO BE CREATED" << std::endl;

    std::string genCert = "cd cert && ./self-signed-tls -c=US -s=California -l=San-Francisco -o=\"Skale Labs\" -u=\"Department of Software Engineering\" -n=\"SGXCACertificate\" -e=info@skalelabs.com";

    if (system(genCert.c_str()) == 0){
      std::cerr << "CERTIFICATE IS SUCCESSFULLY GENERATED" << std::endl;
    }
    else{
      std::cerr << "CERTIFICATE GENERATION FAILED" << std::endl;
      exit(-1);
    }
  }

  hs2 = new HttpServer(1027);
  sr = new SGXRegistrationServer(*hs2,
                                 JSONRPC_SERVER_V2); // hybrid server (json-rpc 1.0 & 2.0)

  if (!sr->StartListening()) {
    cerr << "Registration server could not start listening" << endl;
    exit(-1);
  }
  return 0;
}