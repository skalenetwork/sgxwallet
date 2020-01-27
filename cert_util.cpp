//
// Created by kladko on 12/27/19.
//

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

int main(int argc, char *argv[]) {

  int opt;

  if (argc > 1 && strlen(argv[1]) == 1) {
    fprintf(stderr, "option is too short %s\n", argv[1]);
    exit(1);
  }

  if (argc == 1) {
    std::cout << "You may use following flags:" << std::endl;
    std::cout << " -p  print all unsigned csr hashes " << std::endl;
    std::cout << " -s [hash] sign csr by hash" << std::endl;
    std::cout << " -r [hash] reject csr by hash" << std::endl;
    exit(0);
  }
     std::string hash;
      while ((opt = getopt(argc, argv, "ps:r:")) != -1) {
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

