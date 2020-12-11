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

    @file sgx_util.cpp
    @author Stan Kladko
    @date 2019
*/

#include <iostream>
#include <cstring>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include "stubclient.h"

#include <unistd.h>

int print_hashes(){
    jsonrpc::HttpClient client("http://localhost:1028");
    StubClient c(client, jsonrpc::JSONRPC_CLIENT_V2);
    std::cout << "Client inited" << std::endl;
    std::cout << c.getUnsignedCSRs() << std::endl;
    exit(0);
}

void sign_by_hash(std::string & hash, int status){
    jsonrpc::HttpClient client("http://localhost:1028");
    StubClient c(client, jsonrpc::JSONRPC_CLIENT_V2);
    std::cout << "Client inited" << std::endl;
    std::cout << c.signByHash(hash, status) << std::endl;
    exit(0);
}

void getAllKeysInfo() {
    jsonrpc::HttpClient client("http://localhost:1030");
    StubClient c(client, jsonrpc::JSONRPC_CLIENT_V2);
    std::cout << "Info client inited" << std::endl;
    std::cout << c.getAllKeysInfo()["allKeys"] << std::endl;
    exit(0);
}

void getLatestCreatedKey() {
    jsonrpc::HttpClient client("http://localhost:1030");
    StubClient c(client, jsonrpc::JSONRPC_CLIENT_V2);
    std::cout << "Info client inited" << std::endl;
    Json::Value lastCreatedKey = c.getLatestCreatedKey();
    std::cout << "Last created key name: " << lastCreatedKey["keyName"] << std::endl;
    std::cout << "Last created key creation time: " << lastCreatedKey["creationTime"] << std::endl;
    exit(0);
}

void getServerConfiguration() {
    jsonrpc::HttpClient client("http://localhost:1030");
    StubClient c(client, jsonrpc::JSONRPC_CLIENT_V2);
    std::cout << "Info client inited" << std::endl;
    Json::Value response = c.getServerConfiguration();
    std::cout << "OPTION autoConfitm certificates switched to " << response["autoConfitm"] << '\n';
    std::cout << "OPTION logLevel switched to " << response["logLevel"] << '\n';
    std::cout << "OPTION enterBackupKey switched to " << response["enterBackupKey"] << '\n';
    std::cout << "OPTION useHTTPS switched to " << response["useHTTPS"] << '\n';
    std::cout << "OPTION autoSign certificates switched to " << response["autoSign"] << '\n';
    std::cout << "OPTION checkCerts switched to " << response["checkCerts"] << '\n';
    std::cout << "OPTION generateTestKeys switched to " << response["generateTestKeys"] << '\n';
    exit(0);
}

void isKeyExists(const std::string& key) {
    jsonrpc::HttpClient client("http://localhost:1030");
    StubClient c(client, jsonrpc::JSONRPC_CLIENT_V2);
    std::cout << "Info client inited" << std::endl;
    if (c.isKeyExist(key)) {
        std::cout << "Key with name " << key << "presents in server database.";
    } else {
        std::cout << "Key with name " << key << "does not exist in server's database.";
    }
    exit(0);
}

int main(int argc, char *argv[]) {
  int opt;

  if (argc > 1 && strlen(argv[1]) == 1) {
    fprintf(stderr, "option is too short %s\n", argv[1]);
    exit(1);
  }

  if (argc == 1) {
    std::cout << "You may use following flags:" << std::endl;
    std::cout << " -p print all unsigned csr hashes " << std::endl;
    std::cout << " -s [hash] sign csr by hash" << std::endl;
    std::cout << " -r [hash] reject csr by hash" << std::endl;
    std::cout << " -a print all keys" << std::endl;
    std::cout << " -l print latest created key" << std::endl;
    std::cout << " -c print server's config" << std::endl;
    std::cout << " -i [name] check if key with such name presents in database" << std::endl;
    exit(0);
  }
  std::string hash;
  while ((opt = getopt(argc, argv, "ps:r:alci:")) != -1) {
      switch (opt) {
          case 'p': print_hashes();
                    break;
          case 's': hash = optarg;
                    sign_by_hash(hash, 0);
                    break;
          case 'r': hash = optarg;
                    sign_by_hash(hash, 2);
                    break;
          case '?': // fprintf(stderr, "unknown flag\n");
                    exit(1);
      }
  }

  return 0;
}

