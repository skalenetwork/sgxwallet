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

    @file SGXWalletServer.hpp
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_SGXWALLETSERVER_HPP
#define SGXWALLET_SGXWALLETSERVER_HPP


#include "abstractstubserver.h"
#include <mutex>


using namespace jsonrpc;
using namespace std;

class SGXWalletServer : public AbstractStubServer {


    SGXWalletServer *server = nullptr;
    std::recursive_mutex m;

public:
    SGXWalletServer(AbstractServerConnector &_connector, serverVersion_t _type);

    virtual Json::Value
    importBLSKeyShare(const std::string &_keyShare, const std::string &_keyShareName, int _t, int _n, int index);

    virtual Json::Value
    blsSignMessageHash(const std::string &_keyShareName, const std::string &_messageHash, int _t, int _n, int _signerIndex);

    virtual Json::Value importECDSAKey(const std::string &_key, const std::string &_keyName);

    virtual Json::Value generateECDSAKey();

    virtual Json::Value renameECDSAKey(const std::string &_keyName, const std::string &_tmpKeyName);

    virtual Json::Value ecdsaSignMessageHash(int _base, const std::string &_keyShareName, const std::string &_messageHash);

    virtual Json::Value getPublicECDSAKey(const std::string &_keyName);

    virtual Json::Value generateDKGPoly(const std::string &_polyName, int _t);

    virtual Json::Value getVerificationVector(const std::string &_polynomeName, int _t, int _n);

    virtual Json::Value getSecretShare(const std::string &_polyName, const Json::Value &_publicKeys, int t, int n);

    virtual Json::Value
    dkgVerification(const std::string &publicShares, const std::string &ethKeyName, const std::string &SecretShare,
                    int t, int n, int index);

    virtual Json::Value
    createBLSPrivateKey(const std::string &blsKeyName, const std::string &ethKeyName, const std::string &polyName,
                        const std::string &SecretShare, int t, int n);

    virtual Json::Value getBLSPublicKeyShare(const std::string &blsKeyName);

    virtual Json::Value complaintResponse(const std::string &polyName, int ind);

    virtual Json::Value multG2(const std::string &x);

    virtual Json::Value isPolyExists(const std::string &polyName);

    virtual Json::Value getServerStatus();

    static shared_ptr<string> readFromDb(const string &name, const string &prefix = "");

    static void writeDataToDB(const string &Name, const string &value);

    static void writeKeyShare(const string &_keyShareName, const string &value, int index, int n, int t);

    static shared_ptr<std::string> readKeyShare(const string &_keyShare);

    static Json::Value
    importBLSKeyShareImpl(const std::string &keyShare, const std::string &keyShareName, int t, int n, int index);

    static Json::Value
    blsSignMessageHashImpl(const std::string &keyShareName, const std::string &messageHash, int t, int n,
                           int signerIndex);

    static Json::Value importECDSAKeyImpl(const std::string &_key, const std::string &_keyName);

    static Json::Value generateECDSAKeyImpl();

    static Json::Value renameECDSAKeyImpl(const std::string &KeyName, const std::string &tempKeyName);

    static Json::Value ecdsaSignMessageHashImpl(int base, const std::string &keyName, const std::string &messageHash);

    static Json::Value getPublicECDSAKeyImpl(const std::string &keyName);

    static Json::Value generateDKGPolyImpl(const std::string &polyName, int t);

    static Json::Value getVerificationVectorImpl(const std::string &polyName, int t, int n);

    static Json::Value getSecretShareImpl(const std::string &polyName, const Json::Value &publicKeys, int t, int n);

    static Json::Value
    dkgVerificationImpl(const std::string &publicShares, const std::string &ethKeyName, const std::string &SecretShare,
                        int t, int n, int index);

    static Json::Value
    createBLSPrivateKeyImpl(const std::string &blsKeyName, const std::string &ethKeyName, const std::string &polyName,
                            const std::string &SecretShare, int t, int n);

    static Json::Value getBLSPublicKeyShareImpl(const std::string &blsKeyName);

    static Json::Value complaintResponseImpl(const std::string &polyName, int ind);

    static Json::Value multG2Impl(const std::string &x);

    static Json::Value isPolyExistsImpl(const std::string &polyName);

    static Json::Value getServerStatusImpl();

    static void printDB();

    static int initHttpServer();

    static int initHttpsServer(bool _checkCerts);
};

#endif //SGXWALLET_SGXWALLETSERVER_HPP