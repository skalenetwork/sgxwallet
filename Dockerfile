FROM skalenetwork/sgxwallet_base:latest

COPY . /usr/src/sdk
WORKDIR /usr/src/sdk

# Install dependencies and Python packages in one layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    secure-delete \
    python3-pip \
    && pip3 install --upgrade --no-cache-dir pip \
    && pip3 install --no-cache-dir requests torpy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Build application
RUN touch /var/hwmode \
    && ./autoconf.bash \
    && ./configure \
    && make -j$(nproc) \
    && ccache -sz \
    && mkdir -p /usr/src/sdk/sgx_data

# Copy runtime scripts
COPY docker/start.sh ./
COPY docker/check_firewall.py ./

# Cleanup to reduce image size
RUN rm -rf /usr/src/sdk/sgx-sdk-build/ \
    && rm -f /opt/intel/sgxsdk/lib64/*_sim.so \
    && find /usr/src/sdk -name "*.o" -type f -delete \
    && ccache -C

ENTRYPOINT ["/usr/src/sdk/start.sh"]
