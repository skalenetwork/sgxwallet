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
    @author Sveta Rogova
    @date 2019
*/

#ifndef SGXWALLET_SGXWALLETSERVER_HPP
#define SGXWALLET_SGXWALLETSERVER_HPP




#include "abstractstubserver.h"
#include <mutex>



using namespace jsonrpc;
using namespace std;

class SGXWalletServer : public AbstractStubServer {


    SGXWalletServer* server = nullptr;
    std::recursive_mutex m;

public:
    SGXWalletServer(AbstractServerConnector &connector, serverVersion_t type);

    virtual Json::Value importBLSKeyShare(const std::string& keyShare, const std::string& keyShareName, int t, int n, int index);
    virtual Json::Value blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash, int t, int n, int signerIndex);

    virtual Json::Value importECDSAKey(const std::string& key, const std::string& keyName);
    virtual Json::Value generateECDSAKey();
    virtual Json::Value renameECDSAKey(const std::string& KeyName, const std::string& tempKeyName);
    virtual Json::Value ecdsaSignMessageHash(int base, const std::string& keyShareName, const std::string& messageHash);
    virtual Json::Value getPublicECDSAKey(const std::string& keyName);

    virtual Json::Value generateDKGPoly(const std::string& polyName, int t);
    virtual Json::Value getVerificationVector(const std::string& polyName, int t, int n);
    virtual Json::Value getSecretShare(const std::string& polyName, const Json::Value& publicKeys, int t, int n);
    virtual Json::Value DKGVerification(const std::string& publicShares, const std::string& EthKeyName, const std::string& SecretShare, int t, int n, int index);
    virtual Json::Value CreateBLSPrivateKey(const std::string & BLSKeyName, const std::string& EthKeyName, const std::string& polyName, const std::string & SecretShare, int t, int n);
    virtual Json::Value GetBLSPublicKeyShare(const std::string & BLSKeyName);
    virtual Json::Value ComplaintResponse(const std::string& polyName, int ind);
    virtual Json::Value MultG2(const std::string & x);
    virtual Json::Value getServerStatus();

};

shared_ptr<string> readFromDb(const string & name, const string & prefix = "");
void writeDataToDB(const string & Name, const string &value);

void writeKeyShare(const string &_keyShareName, const string &value, int index, int n, int t);
shared_ptr<std::string> readKeyShare(const string& _keyShare);

Json::Value importBLSKeyShareImpl(const std::string& keyShare, const std::string& keyShareName, int t, int n, int index);
Json::Value blsSignMessageHashImpl(const std::string& keyShareName, const std::string& messageHash, int t, int n, int signerIndex);

Json::Value importECDSAKeyImpl(const std::string& key, const std::string& keyName);
Json::Value generateECDSAKeyImpl();
Json::Value renameECDSAKeyImpl(const std::string& KeyName, const std::string& tempKeyName);
Json::Value ecdsaSignMessageHashImpl(int base, const std::string& keyName, const std::string& messageHash);
Json::Value getPublicECDSAKeyImpl(const std::string& keyName);

Json::Value generateDKGPolyImpl(const std::string& polyName, int t);
Json::Value getVerificationVectorImpl(const std::string& polyName, int t, int n);
Json::Value getSecretShareImpl(const std::string& polyName, const Json::Value& publicKeys, int t, int n);
Json::Value DKGVerificationImpl(const std::string& publicShares, const std::string& EthKeyName, const std::string& SecretShare, int t, int n, int index);
Json::Value CreateBLSPrivateKeyImpl(const std::string & BLSKeyName, const std::string& EthKeyName, const std::string& polyName, const std::string & SecretShare, int t, int n);
Json::Value GetBLSPublicKeyShareImpl(const std::string & BLSKeyName);
Json::Value ComplaintResponseImpl(const std::string& polyName, int ind);
Json::Value MultG2Impl(const std::string & x);
Json::Value getServerStatusImpl();

#endif //SGXWALLET_SGXWALLETSERVER_HPP