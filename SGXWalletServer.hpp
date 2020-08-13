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


#include <jsonrpccpp/server/connectors/httpserver.h>

#include "abstractstubserver.h"

using namespace jsonrpc;
using namespace std;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

class SGXWalletServer : public AbstractStubServer {
    static shared_ptr<SGXWalletServer> server;
    static shared_ptr<HttpServer> httpServer;
public:
    static const char* getVersion() {
        return TOSTRING(SGXWALLET_VERSION);
    }

    SGXWalletServer(AbstractServerConnector &_connector, serverVersion_t _type);

    virtual Json::Value
    importBLSKeyShare(const string &_keyShare, const string &_keyShareName, int _t, int _n, int index);

    virtual Json::Value
    blsSignMessageHash(const string &_keyShareName, const string &_messageHash, int _t, int _n,
                       int _signerIndex);

    virtual Json::Value importECDSAKey(const string &_key, const string &_keyName);

    virtual Json::Value generateECDSAKey();

    virtual Json::Value renameECDSAKey(const string &_keyName, const string &_tmpKeyName);

    virtual Json::Value
    ecdsaSignMessageHash(int _base, const string &_keyShareName, const string &_messageHash);

    virtual Json::Value getPublicECDSAKey(const string &_keyName);

    virtual Json::Value generateDKGPoly(const string &_polyName, int _t);

    virtual Json::Value getVerificationVector(const string &_polynomeName, int _t, int _n);

    virtual Json::Value getSecretShare(const string &_polyName, const Json::Value &_publicKeys, int t, int n);

    virtual Json::Value
    dkgVerification(const string &_publicShares, const string &ethKeyName, const string &SecretShare,
                    int t, int n, int index);

    virtual Json::Value
    createBLSPrivateKey(const string &blsKeyName, const string &ethKeyName, const string &polyName,
                        const string &SecretShare, int t, int n);

    virtual Json::Value getBLSPublicKeyShare(const string &blsKeyName);

    virtual Json::Value complaintResponse(const string &polyName, int ind);

    virtual Json::Value multG2(const string &x);

    virtual Json::Value isPolyExists(const string &polyName);

    virtual Json::Value getServerStatus();

    virtual Json::Value getServerVersion();

    virtual Json::Value deleteBlsKey( const std::string& name );

    static shared_ptr<string> readFromDb(const string &name, const string &prefix = "");

    static void writeDataToDB(const string &Name, const string &value);

    static void writeKeyShare(const string &_keyShareName, const string &_value, int _index, int _n, int _t);

    static Json::Value
    importBLSKeyShareImpl(const string &_keyShare, const string &_keyShareName, int t, int n, int _index);

    static Json::Value
    blsSignMessageHashImpl(const string &_keyShareName, const string &_messageHash, int t, int n,
                           int _signerIndex);

    static Json::Value importECDSAKeyImpl(const string &_key, const string &_keyName);

    static Json::Value generateECDSAKeyImpl();

    static Json::Value renameECDSAKeyImpl(const string &_keyName, const string &_tempKeyName);

    static Json::Value ecdsaSignMessageHashImpl(int _base, const string &keyName, const string &_messageHash);

    static Json::Value getPublicECDSAKeyImpl(const string &_keyName);

    static Json::Value generateDKGPolyImpl(const string &_polyName, int _t);

    static Json::Value getVerificationVectorImpl(const string &_polyName, int _t, int _n);

    static Json::Value getSecretShareImpl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n);

    static Json::Value
    dkgVerificationImpl(const string &_publicShares, const string &_ethKeyName, const string &_secretShare,
                        int _t, int _n, int _index);

    static Json::Value
    createBLSPrivateKeyImpl(const string &_blsKeyName, const string &_ethKeyName, const string &_polyName,
                            const string &_secretShare, int _t, int _n);

    static Json::Value getBLSPublicKeyShareImpl(const string &_blsKeyName);

    static Json::Value complaintResponseImpl(const string &_polyName, int _ind);

    static Json::Value multG2Impl(const string &_x);

    static Json::Value isPolyExistsImpl(const string &_polyName);

    static Json::Value getServerStatusImpl();

    static Json::Value getServerVersionImpl();

    static Json::Value deleteBlsKeyImpl(const std::string& name);

    static void printDB();

    static int initHttpServer();

    static int initHttpsServer(bool _checkCerts);
};

#endif //SGXWALLET_SGXWALLETSERVER_HPP
