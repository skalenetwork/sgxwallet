/*

Modifications Copyright (C) 2019 SKALE Labs

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#include "sgxwallet.h"
#include "BLSCrypto.h"
#include "ServerInit.h"

#include <stdbool.h>

void usage() {
  fprintf(stderr, "usage: sgxwallet\n");
  exit(1);
}

sgx_launch_token_t token = {0};
sgx_enclave_id_t eid;
sgx_status_t status;
int updated;

int main(int argc, char *argv[]) {

  bool check_client_cert = true;
  bool sign_automatically = false;
  int opt;

  if (argc > 1 && strlen(argv[1])==1){
    fprintf(stderr, "option is too short %s\n", argv[1]);
    exit(1);
  }

  while ((opt = getopt(argc, argv, "csh")) != -1) {
    switch (opt) {
    case 'h':
      if (strlen(argv[1]) == 2 ) {
        fprintf(stderr, "-c  client certificate will not be checked\n");
        fprintf(stderr, "-s  client certificate will be signed automatically\n");
        exit(0);
      } else {
        fprintf(stderr, "unknown flag %s\n", argv[1]);
        exit(1);
      }
    case 'c':
      check_client_cert = false;
      break;
    case 's':
      sign_automatically = true;
      break;
    case '?': // fprintf(stderr, "unknown flag\n");
      exit(1);
    default:
      break;
    }
  }
  init_all(check_client_cert, sign_automatically);

  while (true) {
      sleep(10);
  }

  return 0;
}
