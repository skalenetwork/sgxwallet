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

    @file SGXRegistrationServer.cpp
    @author Stan Kladko
    @date 2019
*/

#include <iostream>
#include <fstream>
#include <sstream>

#include <third_party/cryptlite/sha256.h>
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
                                 serverVersion_t type, bool auto_sign)
    : AbstractRegServer(connector, type), is_cert_created(false), cert_auto_sign(auto_sign) {}


Json::Value SignSertificateImpl(const std::string& cert, bool auto_sign = false){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  try{
    //std::hash = cryptlite::sha256::hash_hex(cert);

    std::cerr << " going to create csr" << std::endl;



  std::ofstream outfile ("cert/client.csr");
  outfile << cert << std::endl;
  outfile.close();
  std::string csrPath = "cert/client.csr";
  if (access(csrPath.c_str(), F_OK) != 0){
    throw RPCException(FILE_NOT_FOUND, "Csr does not exist");
  }
  result["result"] = true;
  std::thread thr(set_cert_created1, true);
  thr.detach();



 // std::thread timeout_thr (std::bind(&SGXRegistrationServer::set_cert_created, this, true));

  if (auto_sign) {
    std::string genCert = "cd cert && ./create_client_cert";

        if (system(genCert.c_str()) == 0){
          std::cerr << "CLIENT CERTIFICATE IS SUCCESSFULLY GENERATED" << std::endl;
        }
        else{
          std::cerr << "CLIENT CERTIFICATE GENERATION FAILED" << std::endl;
          exit(-1);
        }
  }
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
      std::ifstream infile("cert/client.crt");
      if (!infile.is_open()) {
        throw RPCException(FILE_NOT_FOUND, "Certificate does not exist");
      } else {
        ostringstream ss;
        ss << infile.rdbuf();
        cert = ss.str();

        infile.close();

        system("cd cert && rm -rf client.crt");

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
  std::cerr << "Enter SignCertificate " << std::endl;
  lock_guard<recursive_mutex> lock(m);
  return SignSertificateImpl(cert, cert_auto_sign);
}

Json::Value SGXRegistrationServer::GetCertificate(const std::string& hash){
  lock_guard<recursive_mutex> lock(m);
  return GetSertificateImpl(hash);
}

void SGXRegistrationServer::set_cert_created(bool b){
  sleep(100);
  is_cert_created = b;
}



int init_registration_server(bool sign_automatically) {

//  std::string certPath = "cert/SGXCACertificate.crt";
//  std::string keyPath = "cert/SGXCACertificate.key";
//
//  if (access(certPath.c_str(), F_OK) != 0){
//    std::cerr << "CERTIFICATE IS GOING TO BE CREATED" << std::endl;
//
//    std::string genCert = "cd cert && ./self-signed-tls -c=US -s=California -l=San-Francisco -o=\"Skale Labs\" -u=\"Department of Software Engineering\" -n=\"SGXCACertificate\" -e=info@skalelabs.com";
//
//    if (system(genCert.c_str()) == 0){
//      std::cerr << "CERTIFICATE IS SUCCESSFULLY GENERATED" << std::endl;
//    }
//    else{
//      std::cerr << "CERTIFICATE GENERATION FAILED" << std::endl;
//      exit(-1);
//    }
//  }

  hs2 = new HttpServer(1031);
  sr = new SGXRegistrationServer(*hs2,
                                 JSONRPC_SERVER_V2, sign_automatically); // hybrid server (json-rpc 1.0 & 2.0)

  if (!sr->StartListening()) {
    cerr << "Registration server could not start listening" << endl;
    exit(-1);
  }
  return 0;
}