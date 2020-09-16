<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SGXWallet Backup Procedure

When SGXWallet is initialized, the server will write the backup key into `sgx_data/sgxwallet_backup_key.txt`.
**This key must be securely recorded and stored.**
Be sure to store this key in a safe place, then go into a docker container and securely remove it with the following command:

```bash
docker exec -it <SGX_CONTAINER_NAME> bash && srm -vz ./sgx_data/sgxwallet_backup_key.txt
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

2.  Copy the backed up `sgx_data` directory to the recovery `sgx_data` directory.
3.  Create file `sgx_data/sgxwallet_backup_key.txt` in the recovery directory and write the backup key into it.
4.  Execute:

```bash
docker-compose up -d
```

5.  Edit the `docker-compose.yml` file, remove the `-b` flag.
