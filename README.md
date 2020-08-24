<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SGXWallet: SKALE SGX-based hardware crypto wallet

[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

## Intro

**SGXWallet** is a next generation hardware secure crypto wallet that is based on **Intel SGX** technology. It currently supports **Ethereum** and **SKALE**, and will support **Bitcoin** in the future.

**SGXWallet** runs as a network server. Clients connect to the server, authenticate to it using 
TLS 1.0 protocol with client certificates, and then issue requests to the server to generate crypto 
keys and perform cryptographic operations. The keys are generated inside the secure SGX enclave and never
leave the enclave un-encrypted.  

The server provides an initial registration service to issue client certificates to the clients.
The administrator manually approves each registration.

**SGXWallet** has been tested on **Ubuntu Linux 18.04**.

## An important note about production readiness

The SGXWallet server is still in active development and therefore should be regarded as _alpha software_. The development is still subject to security hardening, further testing, and breaking changes.  **This server has not yet been reviewed or audited for security.**  Please see [SECURITY.md](SECURITY.md) for reporting policies.

![Build SGXWallet](https://github.com/skalenetwork/sgxwallet/workflows/Build,%20test%20and%20push%20sgxwallet%20container/badge.svg)
![Build SGXWallet sim mode](https://github.com/skalenetwork/sgxwallet/workflows/Build,%20test%20and%20push%20sim%20mode%20container/badge.svg)

## Running SGXWallet

### Clone this repo

As you probably suspect, the first thing to do is to clone this repository and all it is sub-repositories. 

```shell
git clone https://github.com/skalenetwork/sgxwallet.git --recurse-submodules
```

### Try in simulation mode

The easiest way to try the SGXWallet server is to run a docker container in insecure simulation mode that emulates an SGX processor. Once familiar with the server, enable sgx on the machine and run it in secure production mode.

First install docker-compose:

```shell
sudo apt-get install docker.io docker-compose
```

Then run SGXWallet using docker-compose

```shell
cd run_sgx_sim; sudo docker-compose up
```

Note: SGXWallet requires docker-compose for correct operation. Always use docker-compose and avoid using raw docker tools.

> :warning: **simulation mode is only for trying SGXWallet.** In production, SGXWallet must be on a server that supports SGX. Never run a production SGXWallet in simulation mode.  

## Admin guide

If you are a SKALE validator and want to run SGXWallet for testnet or mainnet usage, you need
 a SGX-capable server.  
Please refer to Admin guide for details on how to setup SGXWallet in a secure hardware mode 
 [docs/admin-guide.md](docs/admin-guide.md).

## Developer guide

If you are a SKALE developer and want to build SGXWallet from source, please refer to Developer
guide [docs/developer-guide.md](docs/developer-guide.md).

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for information on how to contribute.

## Libraries used by this project

-   [Intel-SGX-SSL by Intel](https://github.com/intel/intel-sgx-ssl)
-   [LevelDB by Google](https://github.com/google/leveldb)
-   [libBLS by SKALE Labs](https://github.com/skalenetwork/libBLS)
-   [libff by SCIPR-LAB](http://www.scipr-lab.org/)
-   [Linux SGX Driver by Intel](https://github.com/intel/linux-sgx-driver)
-   [SGX-GMP by Intel](https://github.com/intel/sgx-gmp)
-   [SGX Software Enable by Intel](https://github.com/intel/sgx-software-enable)

## License

[![License](https://img.shields.io/github/license/skalenetwork/sgxwallet.svg)](LICENSE)

All contributions to SGXWallet are made under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.en.html). See [LICENSE](LICENSE).

Copyright (C) 2019-Present SKALE Labs.
