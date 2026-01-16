# SGXWallet Performance Benchmarks

> Performance measured on Intel Core i7-10510U CPU @ 1.80 GHz (8 cores), SGX simulation mode, MCL backend.

## BLS Sign Performance

| Threads | Throughput (ops/sec) |
|---------|---------------------|
| 1       | ~3,650              |
| 2       | ~4,375              |
| 4       | ~5,375              |
| 8       | ~5,420 (peak)       |
| 16      | ~5,050              |

**Notes:** Peak throughput at 8 threads. Beyond 8 threads, contention reduces performance.

---

## ECDSA Sign Performance

| Threads | Throughput (ops/sec) |
|---------|---------------------|
| 1       | ~255                |
| 2       | ~267                |
| 4       | ~199                |
| 8       | ~274 (peak)         |
| 16      | ~255                |

**Notes:** ECDSA uses GMP-based ECC (not MCL). Performance limited by enclave crypto overhead.

---

## getDecryptionShares Performance

### By Thread Count (fixed batch size)

| Threads | Throughput (ops/sec) |
|---------|---------------------|
| 1       | ~10,900 (peak)      |
| 2       | ~9,250              |
| 4       | ~9,200              |
| 8       | ~10,000             |
| 11      | ~9,800              |
| 16      | ~10,250             |

### By Batch Size (single thread)

| Batch Size | Throughput (items/sec) |
|------------|------------------------|
| 32         | ~12,500 (peak)         |
| 64         | ~9,000                 |
| 128        | ~9,100                 |
| 256        | ~8,500                 |
| 512        | ~8,850                 |
| 1024       | ~9,550                 |

**Notes:** `getDecryptionShares` processes ciphertexts batch-internally in parallel. Adding client-side parallelism does not improve throughput — single-threaded requests achieve near-peak performance.

---

## Summary

| Operation            | Peak Throughput | Optimal Config       |
|----------------------|-----------------|----------------------|
| BLS Sign             | ~5,420 ops/sec  | 8 threads           |
| ECDSA Sign           | ~274 ops/sec    | 8 threads           |
| getDecryptionShares  | ~12,500 ops/sec | 1 thread, batch=32  |