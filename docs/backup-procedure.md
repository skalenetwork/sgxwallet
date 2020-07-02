<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SGXWallet Backup Procedure

When SGXWallet is initialized, the server will print the backup key. 
**This key must be securely recorded and stored.**
The key will be stored in file "backup_key.txt". Remove it once you store it in a safe place with following command:
```bash
sudo apt-get install secure-delete && srm -vz backup_key.txt
```

Master-Slave replication is recommended to support the SGXWallet backup strategy. Below are general instructions for a basic backup and recovery process.

## Backup SGXWallet (manual copy)

1.  Stop the container:

```bash
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
    image: skalenetwork/sgxwallet:latest
    stdin_open: true
```

3.  Copy the backed up `sgx_data` directory to the recovery `sgx_data` directory.
4.  Execute:

```bash
docker-compose up -d
```

5.  Open another terminal window and run `docker attach container_name` there.

6.  Enter the backup key when prompted.
7.  Edit the `docker-compose.yml` file, remove the `-b` flag and `stdin_open: true` option.
