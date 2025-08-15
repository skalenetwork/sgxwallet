<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# Run in hardware secure mode

-   [Increase max process limit](#increase-max-process-limit)
-   [Docker Compose configuration](#docker-compose-configuration)
-   [Run sgxwallet in secure mode](#run-sgxwallet-in-secure-mode)
-   [Start, stop and upgrade sgxwallet containers](#start-stop-and-upgrade-sgxwallet-containers)
-   [Logging](#logging)

## Increase max process limit

sgxwallet requires setting Linux ulimit to at least 65535.

To display you current limit, run

```
ulimit -n
```

If you current ulimit is less than 65535, please set it to 65535 by editing /etc/systemd/system.conf
and setting

```
DefaultLimitNOFILE=65535
```

Then reboot and check ulimit again.


## Docker Compose configuration

Install docker-compose:

```bash
sudo apt-get install docker.io docker-compose
```

Edit `docker-compose.yml` as needed with the appropriate devices, ports, command flags, and healthcheck.

### Devices

On Linux kernel >= 5.11, the device name should be /sgx/enclave

Otherwise, it is usually set to `/dev/mei0`.
Please make sure to specify the correct device in `docker-compose.yml` .

### Ports

sgxwallet operates on the following network ports:

-   1026 (https)
-   1027 (http for initial SSL certification signing)
-   1028 (localhost for admin )
-   1029 (http only operation)
-   1030 (localhost for informational requests)
-   1031 (zmq)

If operating with a firewall, please make sure these ports are open so clients are able to connect to the server.

### Command Flags

| Flag     | Description |
|----------|-------------|
| `-h`     | Display help message with available flags. |
| `-c`     | Skip client certificate verification. |
| `-s`     | Automatically sign client certificates without requiring human confirmation. |
| `-d`     | Enable debug-level output. |
| `-v`     | Enable verbose mode: turn on debug output |
| `-V`     | Enable detailed verbose mode (includes both debug and trace-level output). |
| `-n`     | Start the SGXWalletServer using HTTP instead of HTTPS. |
| `-b`     | Restore from a backup. Requires entry of the backup key. |
| `-y`     | Do not ask user to acknowledge receipt of backup key. |
| `-e`     | Check whether one who is trying to access the key is the same user who created it (Ownership is checked via SSL certificate for now. Deleting old SSL     certificates and trying to access the keys created before will cause the error!) |
| `-T`     | Generate test keys. |
| `-t<N>`  | Set the thread pool size (`<N>`) for intra-request parallelization in SGX operations that support it (e.g., `getDecryptionShares`). `N` must be an integer within the range \([1, 32]\) <br>**Example:** `-t8` for 8 threads, `-t16` for 16 threads. |

### Healthcheck

Healthcheck devices should match the same devices specified under `devices`.

Note: All docker-compose commands herein need to be issued from `run_sgx` directory. If running in simulation mode, use `run_sgx_sim`.

Note: sgxwallet places all its data into the `sgx_data` directory, which is created when sgxwallet is initialized.
**This directory must be backed up. Do not remove this directory!**

## Run sgxwallet in secure mode

```bash
cd run_sgx; sudo docker-compose up -d
```

The server should display: "SGX Server started".

If not, confirm that the SGX device drivers are correctly configured to the machine.

## Start, stop and upgrade sgxwallet containers

To run the server as a daemon, do

```bash
sudo docker-compose up -d
```

To stop/start the server do

```bash
sudo docker-compose stop
sudo docker-compose start
```

To view server logs do

```bash
sudo docker-compose logs
```

To upgrade sgxwallet to a different version:

1.  First stop the container:

```bash
sudo docker-compose stop
```

2.  Edit `docker-compose.yml` with the appropriate container tag:

```yaml
image: skalenetwork/sgxwallet:<TAG>
```

3.  Pull and start the container:

```bash
sudo docker-compose pull
sudo docker-compose up
```

## Logging

By default, sgxwallet will log into default Docker logs, which are rotated into four files 10M each.
To send logs to an external syslog service, edit docker compose YAML file to specify logging configuration as

```yaml
logging:
  driver: syslog
  options:
    syslog-address: "tcp://SYSLOG_SERVER_IP:PORT"

```

See docker-compose documentation for more options.
