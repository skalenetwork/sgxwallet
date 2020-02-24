# SKALE sgxwallet Prerequisites

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

sgxwallet depends on several freely available
software components. These must be installed and configured before
compiling sgxwallet.
This document describes how to get and compile these required components.

# Table of Contents

-   [Recommend Host System](#recommended-host-system)
-   [Docker](#docker)
-   [Intel® Software Guard Extensions (Intel SGX)](#sgx)
-   [Troubleshooting Installation](#troubleshooting-installation)

## Recommended host system

sgxwallet should be ran on Ubuntu 18.04. Sgxwallet has been tested on Ubuntu 18.04.

Sgxwallet may run on other Linux distributions, but the installation process is likely to be more complicated, and the use of other distributions is not supported by their respective communities at this time.

## Docker

Docker may be used instead of building sgxwallet directly (standalone mode) and is recommended. If you build using Docker, you need to install Docker Engine and Docker Compose if it is not already installed.

### To install Docker CE Engine:

```bash
sudo apt-get install -y apt-transport-https ca-certificates
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install -y docker-ce

```

To verify a correct installation, run `sudo docker run hello-world`

### To install Docker Compose:

```bash
sudo curl -L \
   https://github.com/docker/compose/releases/download/1.24.1/docker-compose-`uname -s`-`uname -m` \
   -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

```

To verify a correct installation, run `docker-compose version`

For details on Docker installation, see <https://docs.docker.com/engine/installation/linux/ubuntu> and <https://docs.docker.com/compose/install/#install-compose>

## Intel® Software Guard Extensions (Intel SGX)

Sgxwallet is intended to be run on Intel SGX-enabled platforms. However, it can also be run in "simulator mode" on platforms that do not have hardware support for Intel SGX. Support for other hardware-based Trusted Execution Environments (TEEs) can be added by submitting a Pull Request.

### Intel SGX SDK

The Intel SGX SDK is required for both Intel SGX hardware platform and Intel SGX simulator mode.
The following instructions download the Intel SGX SDK 2.5 and installs it in
`/opt/intel/sgxsdk/` :

```bash
sudo mkdir -p /opt/intel
cd /opt/intel
sudo wget https://download.01.org/intel-sgx/linux-2.5/rhel7.4-server/sgx_linux_x64_psw_2.5.100.49891.bin
echo "yes" | sudo bash ./sgx_linux_x64_sdk_2.5.100.49891.bin

```

This installs the Intel SGX SDK in the recommended location,
`/opt/intel/sgxsdk` .
The Intel SGX OpenSSL library expects the SDK to be here by default.

After installing, source the Intel SGX SDK activation script to set
`$SGX_SDK`, `$PATH`, `$PKG_CONFIG_PATH`, and `$LD_LIBRARY_PATH`.
Append this line to your login shell script (`~/.bashrc` or similar):

```bash
source /opt/intel/sgxsdk/environment
echo "source /opt/intel/sgxsdk/environment" >>~/.bashrc

```

To learn more about Intel SGX read the
[Intel SGX SDK documentation](https://software.intel.com/en-us/sgx-sdk/documentation)
or visit the [Intel SGX homepage](https://software.intel.com/en-us/sgx).
Downloads are listed at
[Intel SGX Downloads for Linux](https://01.org/intel-software-guard-extensions/downloads).

### Intel SGX in Hardware Mode

If you plan to run this on Intel SGX-enabled hardware, you will need to
install the Intel SGX driver and install additional packages
for both standalone and docker builds.
You need to install the Intel SGX driver whether you build Avalon standalone
or using Docker.

Before installing Intel SGX software, install these packages:

```bash
sudo apt-get install -y libelf-dev cpuid

```

Verify your processor supports Intel SGX with:
`cpuid | grep SGX:`

Verify Intel SGX is enabled in BIOS.
Enter BIOS by pressing the BIOS key during boot.
The BIOS key varies by manufacturer and could be F10, F2, F12, F1, DEL, or ESC.
Usually Intel SGX is disabled by default.
If disabled, enter BIOS and find the Intel SGX feature
(it is usually under the "Advanced" or "Security" menu),
enable Intel SGX, save your BIOS settings, and exit BIOS.

Download and install libsgx-enclave-common version 2.5.101:

```bash
wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/libs/libsgx-enclave-common/libsgx-enclave-common_2.5.101.50123-bionic1_amd64.deb
sudo dpkg -i libsgx-enclave-common_2.5.101.50123-bionic1_amd64.deb

```

### Intel SGX in Simulator-mode

If running only in simulator mode (no hardware support), you only
need the Intel SGX SDK.

`SGX_MODE` is optional. If set, it must be set to `SIM` (the default).
Verify `SGX_MODE` is not set, or is set to `SIM`, with `echo $SGX_MODE` .

## Troubleshooting Installation

-   If the message  `intel_sgx: SGX is not enabled` appears in `/var/log/syslog`
    Intel SGX needs to be enabled in BIOS

-   If you are running in Intel SGX hardware mode, make sure you have device
    `/dev/isgx` (and not `/dev/sgx`). Review the Intel SGX device driver
    installation instructions above. If you have `/dev/sgx` the
    device driver must be removed first

-   If you are running in Intel SGX hardware mode, you need to modify
    the `ias_api_key` in `config/tcs_config.toml` with your
    IAS Subscription key obtained in the instructions above
