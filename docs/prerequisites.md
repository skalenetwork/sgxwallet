# SKALE sgxwallet Prerequisites

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

sgxwallet depends on several freely available
software components. These must be installed and configured before
running sgxwallet.
This document describes how to install and configure these required components.


## Recommended host system

sgxwallet should be ran on Ubuntu 18.04. Sgxwallet has been tested on Ubuntu 18.04.

Sgxwallet may run on other Linux distributions, 
but the installation process is likely to be more complicated, 
and the use of other distributions is not supported by their respective communities at this time.


### Install Docker engine ngine:

Docker engine is pre-installed on Ubuntu 18.04.  You can re-install it as 
described below

```bash
sudo apt-get install -y docker-io
```

To verify a correct installation, run `sudo docker run hello-world`

### Install Docker Compose:

```bash
sudo apt-get install -y docker-compose
```

To verify a correct installation, run `docker-compose version`

For details on Docker installation, see <https://docs.docker.com/engine/installation/linux/ubuntu> and <https://docs.docker.com/compose/install/#install-compose>


### Check your machine supports SGX

Install these packages:

```bash
sudo apt-get install -y libelf-dev cpuid

```

Verify your processor supports Intel SGX with:
`cpuid | grep SGX:`


### Verify Intel SGX is enabled in BIOS

Verify Intel SGX is enabled in BIOS.
Enter BIOS by pressing the BIOS key during boot.
The BIOS key varies by manufacturer and could be F10, F2, F12, F1, DEL, or ESC.
Usually Intel SGX is disabled by default.
If disabled, enter BIOS and find the Intel SGX feature
(it is usually under the "Advanced" or "Security" menu),
enable Intel SGX, save your BIOS settings, and exit BIOS.

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
