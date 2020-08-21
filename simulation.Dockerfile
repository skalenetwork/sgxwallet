# This is the base container of SGXWallet to pull in.
FROM skalenetwork/sgxwallet_base:latest

RUN apt update && apt install -y curl

RUN ccache -sz

# /usr/src/sdk is made available to use as a location for the SGX SDK.
COPY . /usr/src/sdk
WORKDIR /usr/src/sdk

# Configure build and make SGXWallet.
RUN ./autoconf.bash && \
    ./configure --enable-sgx-simulation && \
    bash -c "make -j$(nproc)" && \
    ccache -sz && \
    mkdir -p /usr/src/sdk/sgx_data

# The entry point script.
COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
