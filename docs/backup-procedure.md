<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SGXWallet Backup Procedure

When SGXWallet is initialized, the server will print the backup key. 
**This key must be securely recorded and stored.**
Be sure to store this key in a safe place, then go into a docker container and securely remove it with the following command:

```shell
docker exec -it <SGX_CONTAINER_NAME> bash && apt-get install secure-delete && srm -vz backup_key.txt
```

Replication backup is recommended to support the SGXWallet backup strategy, as data in the `sgx_data` directory will frequently change. Below are general instructions for a testing backup and recovery process.

## Backup SGXWallet (manual copy)

1.  Stop the container:

```shell
docker-compose down
```

2.  Copy the entire `sgx_data` directory.

## Recover from backup

1.  Edit the `docker-compose.yml` and add the `-b` flag to recover from backup.

```yaml
command: -s -y -d -b
```

2.  Edit the `docker-compose.yml` and add `stdin_open: true` option. For example:

```yaml
version: "3"
services:
  sgxwallet:
    image: skalenetwork/<sgxwallet_image>:<tag>
    stdin_open: true
```

3.  Copy the backed up `sgx_data` directory to the recovery `sgx_data` directory.
4.  Execute:

```shell
docker-compose up -d
```

5.  Open another terminal window and run `docker attach container_name` there.

6.  Enter the backup key when prompted.
7.  Edit the `docker-compose.yml` file, remove the `-b` flag and `stdin_open: true` option.
