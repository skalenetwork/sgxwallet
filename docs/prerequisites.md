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


###  Verify thatyour machine supports SGX

Install cpuid and libelf-dev packages:

```bash
sudo apt-get install -y libelf-dev cpuid
```

Verify your processor supports Intel SGX with:

```bash
cpuid | grep SGX:
```

The printout shoud read  `SGX: Software Guard Extensions supported = true`






