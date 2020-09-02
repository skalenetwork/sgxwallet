FROM skalenetwork/sgxwallet_base:latest

# Setup base tools.
RUN apt-get update && apt-get install -y curl secure-delete && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN cp -f secure_enclave/secure_enclave.config.xml.release secure_enclave/secure_enclave.config.xml

COPY . /usr/src/sdk
WORKDIR /usr/src/sdk

# Setup hardware mode flag for entry point script.
RUN touch /var/hwmode

# Test signing key generation
RUN cd scripts && ./generate_signing_key.bash

RUN ./autoconf.bash && \
    ./configure --with-sgx-build=release && \
    bash -c "make -j$(nproc)" && \
    ccache -sz && \
    mkdir -p /usr/src/sdk/sgx_data

RUN cd scripts && ./sign_enclave.bash

# The entry point script.
COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
