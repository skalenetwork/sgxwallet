/*
    Copyright (C) 2018-2019 SKALE Labs

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

    @file ZMQClient.h
    @author Stan Kladko
    @date 2021
*/

#ifndef SGXWALLET_ZMQCLIENT_H
#define SGXWALLET_ZMQCLIENT_H

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "third_party/spdlog/spdlog.h"

#include <zmq.hpp>
#include "zhelpers.hpp"
#include <jsonrpccpp/client.h>
#include "ZMQMessage.h"

#define REQUEST_TIMEOUT     10000    //  msecs, (> 1000!)

class ZMQClient {
private:

    EVP_PKEY* pkey = 0;
    EVP_PKEY* pubkey = 0;
    X509* x509Cert = 0;

    bool sign = true;
    string certFileName = "";
    string certKeyName = "";
    string certificate = "";
    string key = "";

    recursive_mutex mutex;

    zmq::context_t ctx;

    string url;

    // generate random identity

    map<uint64_t , shared_ptr <zmq::socket_t>> clientSockets;

    shared_ptr <ZMQMessage> doRequestReply(Json::Value &_req);

    string doZmqRequestReply(string &_req);

    uint64_t getProcessID();

    static string readFileIntoString(const string& _fileName);

public:

    ZMQClient(const string &ip, uint16_t port, bool _sign, const string&  _certPathName,
              const string& _certKeyName);

    void reconnect();

    static pair<EVP_PKEY*, X509*>  readPublicKeyFromCertStr(const string& _cert);

    static string signString(EVP_PKEY* _pkey, const string& _str);

    static void verifySig(EVP_PKEY* _pubkey, const string& _str, const string& _sig);

    string blsSignMessageHash(const std::string &keyShareName, const std::string &messageHash, int t, int n);

    string ecdsaSignMessageHash(int base, const std::string &keyName, const std::string &messageHash);

};


#endif //SGXWALLET_ZMQCLIENT_H
