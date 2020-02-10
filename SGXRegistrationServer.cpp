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
#include "LevelDB.h"

#include "spdlog/spdlog.h"
#include "common.h"

int DEBUG_PRINT = 0;
int is_sgx_https = 1;
int is_aes = 0;
bool autoconfirm = false;

SGXRegistrationServer *regs = nullptr;
HttpServer *hs2 = nullptr;

bool cert_created = false;

void set_cert_created1(bool b){
  sleep(10);
  cert_created = b;
}

SGXRegistrationServer::SGXRegistrationServer(AbstractServerConnector &connector,
                                 serverVersion_t type, bool auto_sign)
    : AbstractRegServer(connector, type), is_cert_created(false), cert_auto_sign(auto_sign) {}


Json::Value signCertificateImpl(const string& csr, bool auto_sign = false){
  Json::Value result;
  result["status"] = 0;
  result["errorMessage"] = "";
  try{
    spdlog::info("enter signCertificateImpl");

    string status = "1";
    string hash = cryptlite::sha256::hash_hex(csr);
    if ( !auto_sign) {
      string db_key = "CSR:HASH:" + hash;
      LevelDB::getCsrStatusDb()->writeDataUnique(db_key, csr);
    }

    if (auto_sign) {
      string csr_name = "cert/" + hash + ".csr";
      ofstream outfile(csr_name);
      outfile << csr << endl;
      outfile.close();
      if (access(csr_name.c_str(), F_OK) != 0) {
        throw RPCException(FILE_NOT_FOUND, "Csr does not exist");
      }

      string genCert = "cd cert && ./create_client_cert " + hash;

      if (system(genCert.c_str()) == 0){
          spdlog::info("CLIENT CERTIFICATE IS SUCCESSFULLY GENERATED");
          status = "0";
      }
      else{
          spdlog::info("CLIENT CERTIFICATE GENERATION FAILED");
          string status_db_key = "CSR:HASH:" + hash + "STATUS:";
          LevelDB::getCsrStatusDb()->writeDataUnique(status_db_key, to_string(FAIL_TO_CREATE_CERTIFICATE));
          throw RPCException(FAIL_TO_CREATE_CERTIFICATE, "CLIENT CERTIFICATE GENERATION FAILED");
          //exit(-1);
      }
    }

    result["result"] = true;
    result["hash"] = hash;

    string db_key = "CSR:HASH:" + hash + "STATUS:";
    LevelDB::getCsrStatusDb()->writeDataUnique(db_key, status);

  } catch (RPCException &_e) {
    cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
    result["result"] = false;
  }

  return result;
}

Json::Value GetSertificateImpl(const string& hash){
  Json::Value result;

  string cert;
  try{
    string db_key = "CSR:HASH:" + hash + "STATUS:";
    shared_ptr<string> status_str_ptr = LevelDB::getCsrStatusDb()->readString(db_key);
    if (status_str_ptr == nullptr){
       throw RPCException(KEY_SHARE_DOES_NOT_EXIST, "Data with this name does not exist in csr db");
    }
    int status = atoi(status_str_ptr->c_str());

    if ( status == 0){
      string crt_name = "cert/" + hash + ".crt";
      //if (access(crt_name.c_str(), F_OK) == 0){
        ifstream infile(crt_name);
        if (!infile.is_open()) {
          string status_db_key = "CSR:HASH:" + hash + "STATUS:";
          LevelDB::getCsrStatusDb()->deleteKey(status_db_key);
          LevelDB::getCsrStatusDb()->writeDataUnique(status_db_key, to_string(FILE_NOT_FOUND));
          throw RPCException(FILE_NOT_FOUND, "Certificate does not exist");
        } else {
          ostringstream ss;
          ss << infile.rdbuf();
          cert = ss.str();

          infile.close();
          string remove_crt = "cd cert && rm -rf " + hash + ".crt && rm -rf " + hash + ".csr";
          if(system(remove_crt.c_str()) == 0){
              //cerr << "cert removed" << endl;
              spdlog::info(" cert removed ");

          }
          else{
              spdlog::info(" cert was not removed ");
          }

      }
    }

    result["status"] = status;
    result["cert"] = cert;

  } catch (RPCException &_e) {
    cerr << " err str " << _e.errString << endl;
    result["status"] = _e.status;
    result["errorMessage"] = _e.errString;
  }

  return result;
}


Json::Value SGXRegistrationServer::signCertificate(const string& csr){
  spdlog::info("Enter signCertificate ");
  lock_guard<recursive_mutex> lock(m);
  return signCertificateImpl(csr, cert_auto_sign);
}

Json::Value SGXRegistrationServer::getCertificate(const string& hash){
  lock_guard<recursive_mutex> lock(m);
  return GetSertificateImpl(hash);
}

void SGXRegistrationServer::set_cert_created(bool b){
  sleep(100);
  is_cert_created = b;
}



int init_registration_server(bool sign_automatically) {

//  string certPath = "cert/SGXCACertificate.crt";
//  string keyPath = "cert/SGXCACertificate.key";
//
//  if (access(certPath.c_str(), F_OK) != 0){
//    cerr << "CERTIFICATE IS GOING TO BE CREATED" << endl;
//
//    string genCert = "cd cert && ./self-signed-tls -c=US -s=California -l=San-Francisco -o=\"Skale Labs\" -u=\"Department of Software Engineering\" -n=\"SGXCACertificate\" -e=info@skalelabs.com";
//
//    if (system(genCert.c_str()) == 0){
//      cerr << "CERTIFICATE IS SUCCESSFULLY GENERATED" << endl;
//    }
//    else{
//      cerr << "CERTIFICATE GENERATION FAILED" << endl;
//      exit(-1);
//    }
//  }

  hs2 = new HttpServer(BASE_PORT + 1);
  regs = new SGXRegistrationServer(*hs2,
                                 JSONRPC_SERVER_V2, sign_automatically); // hybrid server (json-rpc 1.0 & 2.0)

  if (!regs->StartListening()) {
    spdlog::info("Registration server could not start listening");
    exit(-1);
  }
  else {
    spdlog::info("Registration server started on port {}", BASE_PORT + 1);
  }



  return 0;
}

