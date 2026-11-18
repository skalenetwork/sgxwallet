# Changelog

All notable changes to this project will be documented in this file.

## [1.11.0] - Unreleased (beta)

Ubuntu 24.04 migration; enclave and test suite improvements.

### Breaking Changes

| Change | Description |
| --- | --- |
| Ubuntu 24.04 | All Docker images and CI runners move from Ubuntu 22.04 to 24.04. The legacy `libssl1.1` and `libprocps-dev` packages are no longer installed. |
| Opt-in test build | Test binaries and test-only enclave calls are built only with `./configure --enable-tests`. |
| Stricter DKG V2 share input | `createBLSPrivateKey` (V2) rejects a shares string that is not an exact multiple of 192 hex characters, and rejects invalid public key points, instead of ignoring the extra input. |

### Added

- Unified Catch2 test suite with unit and integration tests for DKG, BLS,
  ECDSA, key management, backup, threshold encryption, ZMQ auth, server health and DB re-encryption,
  replacing `testw.cpp`/`testw.py` ([#530](https://github.com/skalenetwork/sgxwallet/pull/530))

### Changed

- Move to Ubuntu 24.04, remove the libff dependency and update libBLS ([#541](https://github.com/skalenetwork/sgxwallet/pull/541))
- Update enclave ECDSA signing and randomness ([#532](https://github.com/skalenetwork/sgxwallet/pull/532), [skalenetwork/internal-support#1481](https://github.com/skalenetwork/internal-support/issues/1481))
- Set `DisableDebug` to 1 in the default enclave configuration ([#534](https://github.com/skalenetwork/sgxwallet/pull/534), [#533](https://github.com/skalenetwork/sgxwallet/issues/533))
- Remove unnecessary debug prints ([#538](https://github.com/skalenetwork/sgxwallet/pull/538), [#537](https://github.com/skalenetwork/sgxwallet/issues/537))
- Clean shutdown: `exitAll()` destroys the enclave and closes the databases, and the ZMQ server
  can be restarted after exit ([#530](https://github.com/skalenetwork/sgxwallet/pull/530))
- CI: build Docker images on pull requests and publish only after merge to `develop` or `beta`;
  remove the legacy CLA workflow ([#556](https://github.com/skalenetwork/sgxwallet/pull/556), [#555](https://github.com/skalenetwork/sgxwallet/issues/555))
- Update CODEOWNERS ([#539](https://github.com/skalenetwork/sgxwallet/pull/539))

### Fixed

- Fix crash on a fresh start without an `sgx_data/` folder: create certificates only after the
  data folder is initialized, and report clear errors when it cannot be created
  ([#554](https://github.com/skalenetwork/sgxwallet/pull/554), [#553](https://github.com/skalenetwork/sgxwallet/issues/553))

## [1.10.4] - 2026-10-07

### Added

- Add `getServerOptions` to report the options the server runs with, and
  `getIssuedCertificatesInfo` to report the number of issued client certificates and the newest
  one ([#547](https://github.com/skalenetwork/sgxwallet/pull/547), [#546](https://github.com/skalenetwork/sgxwallet/pull/546))

### Fixed

- Fix `sgx_util -c` printing autoSign and checkCerts swapped; key listings and counts now include
  ZMQ key-ownership rows ([#547](https://github.com/skalenetwork/sgxwallet/pull/547))
