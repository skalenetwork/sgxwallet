<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SKALE SGXWallet Prerequisites

SGXWallet depends on several freely available software components. These must be installed and configured before
running SGXWallet.
This document describes how to install and configure these required components.

## Recommended host system

-   Ubuntu 18.04
-   At least 8GB RAM
-   Swap size equals to half of RAM size

Sgxwallet may run on other Linux distributions, 
but the installation process is likely to be more complicated, 
and the use of other distributions is not supported by their respective communities at this time.


### Install Docker engine

Docker engine is pre-installed on Ubuntu 18.04.  You can re-install it as 
described below

```bash
sudo apt-get install -y docker-io
```

To verify a correct installation, run `sudo docker run hello-world`

### Install Docker Compose

```bash
sudo apt-get install -y docker-compose
```

To verify a correct installation, run `docker-compose version`

For details on Docker installation, see <https://docs.docker.com/engine/installation/linux/ubuntu> and <https://docs.docker.com/compose/install/#install-compose>

### Verify Internet connection

Intel SGX automatically downloads enclave whitelist updates from

```
http://whitelist.trustedservices.intel.com/SGX/LCWL/Linux/sgx_white_list_cert.bin
```

Verify that your network and firewall configuration allows connections to this URL by
running 

```
curl  -I http://whitelist.trustedservices.intel.com/SGX/LCWL/Linux/sgx_white_list_cert.bin
```

 If you need to set advanced options, such as outgoing network proxy, edit "/etc/aesmd.conf" file in
 the sgxwallet docker container.  


 #endif" 

### Verify SGX support

Install cpuid and libelf-dev packages:

```bash
sudo apt-get install -y libelf-dev cpuid
```

Verify processor support of Intel SGX:

```bash
cpuid | grep SGX:
```

The printout should read: `SGX: Software Guard Extensions supported = true`
