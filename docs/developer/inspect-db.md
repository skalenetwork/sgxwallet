<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

# Inspecting SGXWallet DB with sgx_util

`sgx_util` is a small local CLI that queries SGXWallet internal admin/info JSON-RPC endpoints.
It is useful for checking pending CSRs and inspecting key metadata in the local database.

## Prerequisites

- Build sgxwallet (the `sgx_util` binary is built together with other binaries):

```bash
./autoconf.bash
./configure
make
```

- Start `sgxwallet` locally.
- Ensure localhost ports are reachable:
	- `1028` (CSR admin endpoint)
	- `1030` (info endpoint)

## Usage

Run from the repository root:

```bash
./sgx_util [flag]
```

If you run without arguments, `sgx_util` prints the available flags.

In Docker-based production setups, run `sgx_util` from inside the running
`sgxwallet` container so `localhost:1028` and `localhost:1030` resolve to the
service endpoints inside the same container.

Example with Docker Compose:

```bash
docker compose exec sgxwallet ./sgx_util -a
```

If your environment uses legacy Compose syntax:

```bash
docker-compose exec sgxwallet ./sgx_util -a
```

## Flags

| Flag | Argument | Description | Endpoint |
|------|----------|-------------|----------|
| `-p` | none | Print all unsigned CSR hashes | `localhost:1028` |
| `-s` | CSR hash | Sign CSR by hash | `localhost:1028` |
| `-r` | CSR hash | Reject CSR by hash | `localhost:1028` |
| `-a` | none | Print all key names and total key count | `localhost:1030` |
| `-l` | none | Print latest created key and creation time | `localhost:1030` |
| `-n` | none | Print number of keys in DB | `localhost:1030` |
| `-c` | none | Print server configuration flags | `localhost:1030` |
| `-i` | key name | Check whether a key exists in DB | `localhost:1030` |

## Examples

Print pending unsigned CSRs:

```bash
./sgx_util -p
```

Approve a CSR by hash:

```bash
./sgx_util -s <csr_hash>
```

Reject a CSR by hash:

```bash
./sgx_util -r <csr_hash>
```

Print all key names and total number of keys:

```bash
./sgx_util -a
```

Check if a key exists:

```bash
./sgx_util -i <key_name>
```

Show server configuration reported by info server:

```bash
./sgx_util -c
```

## Notes

- `sgx_util` is intended for local/admin use and connects to hardcoded localhost ports.
- In production, this usually means running it in the `sgxwallet` container.
- It executes one action per call and exits immediately after printing output.
- If `sgxwallet` is not running (or ports are unavailable), the command fails with a JSON-RPC/connection error.
