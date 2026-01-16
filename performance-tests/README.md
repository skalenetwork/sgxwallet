# SGX Wallet Performance Tests

Python scripts to measure the performance of the `sgxwallet` server.

## Prerequisites

1.  A running `sgxwallet` instance (local or remote).
2.  Python 3.8+

## Setup

```bash
cd performance-tests
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Available Tests

| Script | Operation | Description |
|--------|-----------|-------------|
| `getDecryptedShares.py` | `getDecryptionShares` | Threshold decryption (batched) |
| `blsSign.py` | `blsSignMessageHash` | BLS signature |
| `ecdsaSign.py` | `ecdsaSignMessageHash` | ECDSA signature |

## Running Tests

### Local Development

If `sgxwallet` is running locally (e.g., `./sgxwallet -s -y -d`), no certificates needed:

```bash
source venv/bin/activate

# Decryption shares (batched)
python3 getDecryptedShares.py --ip 127.0.0.1

# BLS signing
python3 blsSign.py --ip 127.0.0.1

# ECDSA signing
python3 ecdsaSign.py --ip 127.0.0.1
```

### Remote / Production

For remote instances with TLS, copy certificates first:
```bash
IP=<your-sgxwallet-ip>
scp root@$IP:/root/sgxwallet/sgx_data/cert_data/SGXServerCert.crt ./sgx.crt
scp root@$IP:/root/sgxwallet/sgx_data/cert_data/SGXServerCert.key ./sgx.key
```

## Common CLI Options

All tests support these options:

| Option | Description | Default |
|--------|-------------|---------|
| `--ip` | SGX wallet IP address (required) | - |
| `--batch-sizes` | Comma-separated batch sizes for serial test | `64,128,256,512,1024` |
| `--parallel-threads` | Comma-separated thread counts for parallel test | `1,2,4,8,11,16` |
| `--iterations` | Number of iterations per data point | `3` |
| `--parallel-batch-size` | Fixed batch size per request in parallel test | `500` |

### Test-Specific Options

**BLS Sign:**
| Option | Description | Default |
|--------|-------------|---------|
| `-t` | Threshold value | `2` |
| `-n` | Total nodes | `3` |

**ECDSA Sign:**
| Option | Description | Default |
|--------|-------------|---------|
| `--base` | Numeric base for message hash | `16` |

## Note on the results

For the `getDecryptionShares` call, the server does **intra-parallelization** of each request. Multiple concurrent requests compete for the same thread pool, so adding client-side parallelism doesn't improve throughput.
That is, a single request achieves more or less the same throughput as multiple concurrent requests.

## Output

Plots are saved to `plots/` directory.