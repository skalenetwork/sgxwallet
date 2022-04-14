SGWallet performance measured on Intel Core i7-10510U CPU @ 1.80 GHz * 8.

BLS sign operations:
- simulation mode:
    - 50 BLS sign operations / per sec if sending requests via 5 threads
    - 62 BLS sign operations / per sec if sending requests via 10 threads
    - 69 BLS sign operations / per sec if sending requests via 15 threads
- release mode:
    - 43 BLS sign operations / per sec if sending requests via 5 threads
    - 52 BLS sign operations / per sec if sending requests via 10 threads
    - 60 BLS sign operations / per sec if sending requests via 15 threads

ECDSA sign operations:
- simulation mode:
    - 47 ECDSA sign operations / per sec if sending requests via 5 threads
    - 50 ECDSA sign operations / per sec if sending requests via 10 threads
    - 52 ECDSA sign operations / per sec if sending requests via 15 threads
- release mode:
    - 37 ECDSA sign operations / per sec if sending requests via 5 threads
    - 48 ECDSA sign operations / per sec if sending requests via 10 threads
    - 52 ECDSA sign operations / per sec if sending requests via 15 threads