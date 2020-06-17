<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# SGXWallet Backup Procedure

When SGXWallet is initialized, the server will print the backup key. 
**This key must be securely recorded and stored.**

## Backup SGXWallet

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
3.  Execute:

```bash
docker-compose up
```

4.  Enter the backup key when prompted.
5.  Edit the `docker-compose.yml` file and remove the `-b` flag.
