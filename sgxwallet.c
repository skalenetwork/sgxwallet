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

#include <stdbool.h>

#include "BLSCrypto.h"
#include "ServerInit.h"

#include "SEKManager.h"
#include "SGXWalletServer.h"
#include "sgxwallet.h"


void usage() {
    fprintf(stderr, "usage: sgxwallet\n");
    exit(1);
}

sgx_launch_token_t token = {0};
sgx_enclave_id_t eid;
sgx_status_t status;
int updated;

void printUsage() {
    fprintf(stderr, "Available flags:\n");
    fprintf(stderr, "-c  do not verify client certificate\n");
    fprintf(stderr, "-s  sign client certificate without human confirmation \n");
    fprintf(stderr, "-d  turn on debug output\n");
    fprintf(stderr, "-v  verbose mode: turn on debug output\n");
    fprintf(stderr, "-vv  detailed verbose mode: turn on debug and trace outputs\n");
    fprintf(stderr, "-n  launch SGXWalletServer using http (not https)\n");
    fprintf(stderr, "-b  Restore from back up (you will need to enter backup key) \n");
    fprintf(stderr, "-y  Do not ask user to acknowledge receipt of backup key \n");
}

enum log_level {L_TRACE = 0, L_DEBUG = 1, L_INFO = 2,L_WARNING = 3,  L_ERROR = 4 };

int main(int argc, char *argv[]) {

    bool encryptKeysOption  = false;
    bool useHTTPSOption = true;
    bool printDebugInfoOption = false;
    bool printTraceInfoOption = false;
    bool autoconfirmOption = false;
    bool checkClientCertOption = true;
    bool autoSignClientCertOption = false;

    int opt;

    if (argc > 1 && strlen(argv[1]) == 1) {
        printUsage();
        exit(1);
    }




    while ((opt = getopt(argc, argv, "cshd0abyvVn")) != -1) {
        switch (opt) {
            case 'h':
                printUsage();
                exit(0);
            case 'c':
                checkClientCertOption = false;
                break;
            case 's':
                autoSignClientCertOption = true;
                break;
            case 'd':
                printDebugInfoOption = true;
                break;
            case 'v':
                printDebugInfoOption = true;
                break;
            case 'V':
                printDebugInfoOption = true;
                printTraceInfoOption = true;
                break;
            case '0':
                useHTTPSOption = false;
                break;
            case 'n':
                useHTTPSOption = false;
                break;                
            case 'a':
                encryptKeysOption = false;
                break;
            case 'b':
                encryptKeysOption = true;
                break;
            case 'y':
                autoconfirmOption = true;
                break;
            default:
                printUsage();
                exit(1);
                break;
        }
    }

    setFullOptions(printDebugInfoOption, printTraceInfoOption, useHTTPSOption, autoconfirmOption, encryptKeysOption);

    uint32_t  enclaveLogLevel = L_INFO;

    if (printTraceInfoOption) {
        enclaveLogLevel = L_TRACE;
    } else if (printDebugInfoOption) {
        enclaveLogLevel = L_DEBUG;
    }

    initAll(enclaveLogLevel, checkClientCertOption, autoSignClientCertOption);

    while (true) {
        sleep(10);
    }

    return 0;
}
