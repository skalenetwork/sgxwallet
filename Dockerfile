FROM ubuntu:22.04

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    secure-delete \
    python3-pip \
    && pip3 install --upgrade --no-cache-dir pip \
    && pip3 install --no-cache-dir requests torpy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install libssl1.1 dependency
RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb \
    && dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb \
    && rm -f libssl1.1_1.1.1f-1ubuntu2_amd64.deb

# Copy pre-built SGX wallet binary and runtime files
COPY sgxwallet /usr/src/sdk/sgxwallet
COPY secure_enclave/secure_enclave.signed.so /usr/src/sdk/secure_enclave/secure_enclave.signed.so
COPY docker/start.sh /usr/src/sdk/start.sh
COPY docker/check_firewall.py /usr/src/sdk/check_firewall.py

# Create required directories
RUN mkdir -p /usr/src/sdk/sgx_data

WORKDIR /usr/src/sdk

# Mark as hardware mode
RUN touch /var/hwmode

ENTRYPOINT ["/usr/src/sdk/start.sh"]
