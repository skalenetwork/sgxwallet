# SGXWallet Performance Benchmarks

> Performance measured on Intel Core i7-10510U CPU @ 1.80 GHz (8 cores), SGX simulation mode, MCL backend.

## BLS Sign Performance

| Threads | Throughput (ops/sec) |
|---------|--------------------- |
| 1       | ~6200                |
| 2       | ~5700                |
| 4       | ~6300     (PEAK)     |
| 8       | ~6100                |
| 16      | ~5000                |

**Notes:** Times are very variable. Some runs it may reach ~8k, others 4k. Mean is around 6k.

---

## ECDSA Sign Performance

| Threads | Throughput (ops/sec) |
|---------|---------------------|
| 1       | ~250  (PEAK)        |
| 2       | ~180                |
| 4       | ~145                |
| 8       | ~150                |
| 16      | ~70                 |

**Notes:** ECDSA uses GMP-based ECC (not MCL).

---

## getDecryptionShares Performance

### By Thread Count (fixed batch size)

| Threads | Throughput (ops/sec)|
|---------|---------------------|
| 1       | ~6,750              |
| 2       | ~7,200              |
| 4       | ~6,900              |
| 8       | ~7,300              |
| 11      | ~7,600              |
| 16      | ~7,800              |

### By Batch Size (Fixed max concurrency)

| Batch Size | Throughput (items/sec) |
|------------|------------------------|
| 64         | ~5,100                 |
| 128        | ~8,600                 |
| 256        | ~7,500                 |
| 512        | ~6,800                 |
| 1024       | ~6,800                 |

**Notes:** `getDecryptionShares` processes ciphertexts batch-internally in parallel. Adding client-side parallelism does not improve throughput — single-threaded requests achieve near-peak performance.

---

## Summary

| Operation            | Peak Throughput |
|----------------------|-----------------|
| BLS Sign             | ~6.000 ops/sec  |
| ECDSA Sign           | ~250 ops/sec    |
| getDecryptionShares  | ~7,200 ops/sec  |