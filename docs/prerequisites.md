<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SKALE Sgxwallet Prerequisites

Sgxwallet depends on several freely available software components. These must be installed and configured before running sgxwallet.
This document describes how to install and configure these required components.

## Recommended Hardware

A single core can support up to 50 BLS signatures per second. If the Sgxwallet server is supporting multiple validator nodes, ensure sufficient number of cores are available on the server to support signature throughput of all connected nodes.

A single node supporting one SKALE chain requires approximately 20 BLS signatures per second.

## Recommended host system

Sgxwallet has been tested and should be run on Ubuntu 18.04.

Sgxwallet may run on other Linux distributions, 
but the installation process is likely to be more complicated, 
and the use of other distributions is not supported by their respective communities at this time.

### Install Docker engine

Docker engine is pre-installed on Ubuntu 18.04.  You can re-install it as 
described below

```shell
sudo apt-get install -y docker-io
```

To verify a correct installation, run `sudo docker run hello-world`

### Install Docker Compose

```shell
sudo apt-get install -y docker-compose
```

To verify a correct installation, run `docker-compose version`

For details on Docker installation, see <https://docs.docker.com/engine/installation/linux/ubuntu> and <https://docs.docker.com/compose/install/#install-compose>

### Verify SGX support

Install cpuid and libelf-dev packages:

```shell
sudo apt-get install -y libelf-dev cpuid
```

Verify processor support of Intel SGX:

```shell
cpuid | grep SGX:
```

The printout should read: `SGX: Software Guard Extensions supported = true`
