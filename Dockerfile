# This is the base container of SGXWallet to pull in.
FROM skalenetwork/sgxwallet_base:latest

# /usr/src/sdk is made available to use as a location for the SGX SDK.
COPY . /usr/src/sdk
RUN apt update && apt install -y curl
WORKDIR /usr/src/sdk

# Setup hardware mode flag for entry point script.
RUN touch /var/hwmode

# Configure build and make SGXWallet.
RUN ./autoconf.bash && \
    ./configure && \
    bash -c "make -j$(nproc)" && \
    ccache -sz && \
    mkdir -p /usr/src/sdk/sgx_data

# The entry point script.
COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
