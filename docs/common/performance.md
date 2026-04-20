# SGXWallet Performance Benchmarks (Hardware Mode)

> Performance measured on Intel(R) Xeon(R) E-2286G CPU @ 4.00GHz, using Hardware mode
> 6 physical cores, 12 logical cores

## BLS Sign Performance

~ 7000 signatures/s

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

### By Batch Size (Fixed max concurrency, MCL-0-s)

| Batch Size | Throughput (items/sec) | Approx Mean Time (ms) | Approx times in previous LIBFF version (ms) |
|------------|------------------------|-----------------------|---------------------------------------------|
| 64         | ~6,106                 | ~10.48                | ~45.79                                      |
| 128        | ~6,875                 | ~18.62                | ~84.94                                      |
| 256        | ~7,548                 | ~33.92                | ~172.44                                     |
| 512        | ~7,788                 | ~65.74                | ~352.49                                     |
| 1024       | ~7,885                 | ~129.87               | ~707.35                                     |

**Notes:** `getDecryptionShares` processes ciphertexts batch-internally in parallel. Adding client-side parallelism does not improve throughput — single-threaded requests achieve near-peak performance.

---

## Summary

| Operation            | Peak Throughput |
|----------------------|-----------------|
| BLS Sign             | ~7.000 ops/sec  |
| ECDSA Sign           | ~250 ops/sec    |
| getDecryptionShares  | ~7,200 ops/sec  |
