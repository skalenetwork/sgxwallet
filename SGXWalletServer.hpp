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
    along with sgxwallet. If not, see <https://www.gnu.org/licenses/>.

    @file SGXWalletServer.hpp
    @author Stan Kladko
    @date 2019
*/

#ifndef SGXWALLET_SGXWALLETSERVER_HPP
#define SGXWALLET_SGXWALLETSERVER_HPP


#include "mutex"
#include "memory"

#include <jsonrpccpp/server/connectors/httpserver.h>

#include "abstractstubserver.h"

using namespace jsonrpc;
using namespace std;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)


class SGXWalletServer : public AbstractStubServer {
    static shared_ptr<SGXWalletServer> server;
    static shared_ptr<HttpServer> httpServer;

    static map<string,string> blsRequests;
    static recursive_mutex blsRequestsLock;
    static map<string,string> ecdsaRequests;
    static recursive_mutex ecdsaRequestsLock;

    static void checkForDuplicate(map <string, string> &_map, recursive_mutex &_m, const string &_key,
    const string &_value);

public:

    static bool verifyCert(string& _certFileName);

    static const char* getVersion() {
        return TOSTRING(SGXWALLET_VERSION);
    }

    SGXWalletServer(AbstractServerConnector &_connector, serverVersion_t _type);

    virtual Json::Value
    importBLSKeyShare(const string &_keyShare, const string &_keyShareName);

    virtual Json::Value
    blsSignMessageHash(const string &_keyShareName, const string &_messageHash, int _t, int _n);

    virtual Json::Value importECDSAKey(const std::string& keyShare,
                                       const std::string& keyShareName);

    virtual Json::Value generateECDSAKey();

    virtual Json::Value
    ecdsaSignMessageHash(int _base, const string &_keyShareName, const string &_messageHash);

    virtual Json::Value getPublicECDSAKey(const string &_keyName);

    virtual Json::Value generateDKGPoly(const string &_polyName, int _t);

    virtual Json::Value getVerificationVector(const string &_polynomeName, int _t);

    virtual Json::Value getSecretShare(const string &_polyName, const Json::Value &_publicKeys, int t, int n);

    virtual Json::Value
    dkgVerification(const string &_publicShares, const string &ethKeyName, const string &SecretShare,
                    int t, int n, int index);

    virtual Json::Value
    createBLSPrivateKey(const string &blsKeyName, const string &ethKeyName, const string &polyName,
                        const string &SecretShare, int t, int n);

    virtual Json::Value getBLSPublicKeyShare(const string &blsKeyName);

    virtual Json::Value calculateAllBLSPublicKeys(const Json::Value& publicShares, int t, int n);

    virtual Json::Value complaintResponse(const string &polyName, int t, int n, int ind);

    virtual Json::Value multG2(const string &x);

    virtual Json::Value isPolyExists(const string &polyName);

    virtual Json::Value getServerStatus();

    virtual Json::Value getServerVersion();

    virtual Json::Value deleteBlsKey( const std::string& name );

    virtual Json::Value getSecretShareV2(const string &_polyName, const Json::Value &_publicKeys, int t, int n);

    virtual Json::Value dkgVerificationV2(const string &_publicShares, const string &ethKeyName, const string &SecretShare, int t, int n, int index);

    virtual Json::Value createBLSPrivateKeyV2(const std::string& blsKeyName, const std::string& ethKeyName, const std::string& polyName, const std::string & SecretShare, int t, int n);

    virtual Json::Value getDecryptionShares(const std::string& blsKeyName, const Json::Value& publicDecryptionValues);

    static shared_ptr<string> readFromDb(const string &name, const string &prefix = "");

    static shared_ptr <string> checkDataFromDb(const string &name, const string &prefix = "");

    static void writeDataToDB(const string &Name, const string &value);

    static void writeKeyShare(const string &_keyShareName, const string &_value);

    static Json::Value
    importBLSKeyShareImpl(const string &_keyShare, const string &_keyShareName);

    static Json::Value
    blsSignMessageHashImpl(const string &_keyShareName, const string &_messageHash, int t, int n);

    static Json::Value importECDSAKeyImpl(const string &_keyShare, const string &_keyShareName);

    static Json::Value generateECDSAKeyImpl();

    static Json::Value ecdsaSignMessageHashImpl(int _base, const string &keyName, const string &_messageHash);

    static Json::Value getPublicECDSAKeyImpl(const string &_keyName);

    static Json::Value generateDKGPolyImpl(const string &_polyName, int _t);

    static Json::Value getVerificationVectorImpl(const string &_polyName, int _t);

    static Json::Value getSecretShareImpl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n);

    static Json::Value
    dkgVerificationImpl(const string &_publicShares, const string &_ethKeyName, const string &_secretShare,
                        int _t, int _n, int _index);

    static Json::Value
    createBLSPrivateKeyImpl(const string &_blsKeyName, const string &_ethKeyName, const string &_polyName,
                            const string &_secretShare, int _t, int _n);

    static Json::Value getBLSPublicKeyShareImpl(const string &_blsKeyName);

    static Json::Value calculateAllBLSPublicKeysImpl(const Json::Value& publicShares, int t, int n);

    static Json::Value complaintResponseImpl(const string &_polyName, int t, int n, int _ind);

    static Json::Value multG2Impl(const string &_x);

    static Json::Value isPolyExistsImpl(const string &_polyName);

    static Json::Value getServerStatusImpl();

    static Json::Value getServerVersionImpl();

    static Json::Value deleteBlsKeyImpl(const std::string& name);

    static Json::Value getSecretShareV2Impl(const string &_polyName, const Json::Value &_pubKeys, int _t, int _n);

    static Json::Value dkgVerificationV2Impl(const string &_publicShares, const string &_ethKeyName, const string &_secretShare, int _t, int _n, int _index);

    static Json::Value createBLSPrivateKeyV2Impl(const std::string& blsKeyName, const std::string& ethKeyName, const std::string& polyName, const std::string & SecretShare, int t, int n);

    static Json::Value getDecryptionSharesImpl(const std::string& KeyName, const Json::Value& publicDecryptionValues);

    static void printDB();

    static void initHttpServer();

    static void initHttpsServer(bool _checkCerts);

    static int exitServer();

    static void createCertsIfNeeded();
};

#endif //SGXWALLET_SGXWALLETSERVER_HPP
