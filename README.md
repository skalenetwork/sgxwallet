# sgxwallet: SKALE SGX-based hardware crypto wallet

[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

## Intro

**sgxwallet** is a next generation hardware secure crypto wallet that is based on **Intel SGX** technology. It currently supports **Ethereum** and **SKALE**, and will support **Bitcoin** in the future.

**sgxwallet** runs as a network server.  Clients connect to the server, authenticate to it using 
TLS 1.0 protocol with client certificates, and then issue requests to the server to generate crypto 
keys and perform cryptographic operations. The keys are generated inside the secure SGX enclave and never
leave the enclave unencrypted.  

The server provides an initial registration service to issue client certificates to the clients.
The administrator manually approves each registration.

**sgxwallet** has been tested on **Ubuntu Linux 18.04**.

## An important note about production readiness

The sgxwallet server is still in active development and therefore should be regarded as _alpha software_. The development is still subject to security hardening, further testing, and breaking changes.  **This server has not yet been reviewed or audited for security.**  Please see [SECURITY.md](SECURITY.md) for reporting policies.

![Build, test and push sgxwallet container](https://github.com/skalenetwork/sgxwallet/workflows/Build,%20test%20and%20push%20sgxwallet%20container/badge.svg)
![Build, test and push sim mode container](https://github.com/skalenetwork/sgxwallet/workflows/Build,%20test%20and%20push%20sim%20mode%20container/badge.svg)

## Running sgxwallet

### Try in simulation mode

The easiest way to try the sgxwallet server is to run a docker container in insecure simulation mode that emulates an SGX processor. Once you are familiar with the server, you can enable sgx on your machine and run it in secure production mode.

First install docker-compose if you dont have it [Docker](https://linuxize.com/post/how-to-install-and-use-docker-compose-on-ubuntu-18-04/).

Then run sgxwallet using docker compose

```bash
$ cd run_sgx; sudo docker-compose up

```

### SKALE Network usage

To setup sgxwallet container for testnets or mainnet usage, you must use docker-compose to configure the sgxwallet container. Please see [docs/configuring.md](docs/configuring.md).

## Building

See [docs/building.md](docs/building.md).

## Documentation

See [docs](docs) for sgxwallet documentation.

## Contributing

See [contributing](CONTRIBUTING.md) for information on how to contribute.

## Libraries

-   [Intel-SGX-SSL by Intel](https://github.com/intel/intel-sgx-ssl)
-   [LevelDB by Google](https://github.com/google/leveldb)
-   [libBLS by SKALE Labs](https://github.com/skalenetwork/libBLS)
-   [libff by SCIPR-LAB](http://www.scipr-lab.org/)
-   [Linux SGX Driver by Intel](https://github.com/intel/linux-sgx-driver)
-   [SGX-GMP by Intel](https://github.com/intel/sgx-gmp)
-   [SGX Software Enable by Intel](https://github.com/intel/sgx-software-enable)

## License

[![License](https://img.shields.io/github/license/skalenetwork/sgxwallet.svg)](LICENSE)

All contributions to sgxwallet are made under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.en.html). See [LICENSE](LICENSE).

Copyright (C) 2019-Present SKALE Labs.
