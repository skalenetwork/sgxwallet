# Stage 1: Builder
FROM ubuntu:22.04 as builder

# ---- Install build packages ----
COPY scripts/install_packages.sh /install_packages.sh
RUN chmod +x /install_packages.sh && /install_packages.sh

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb && \
    dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb

# ---- Build Intel SGX SDK & PSW ----
RUN git clone -b sgx_2.25 --depth 1 https://github.com/intel/linux-sgx && \
    cd linux-sgx && make -j$(nproc) preparation

WORKDIR /linux-sgx
COPY . .

RUN make sdk_install_pkg_no_mitigation

WORKDIR /opt/intel
RUN sh -c 'echo yes | /linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin'

WORKDIR /linux-sgx
RUN make -j$(nproc) psw_install_pkg

# Stage 2: Final
FROM ubuntu:22.04

# ---- Install build packages ----
COPY scripts/install_packages.sh /install_packages.sh
RUN chmod +x /install_packages.sh && /install_packages.sh && rm -rf /var/lib/apt/lists/*

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb && \
    dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb && rm -f libssl1.1_*.deb

# ---- Install Intel SGX SDK & PSW ----
WORKDIR /opt/intel
COPY --from=builder /opt/intel/sgxsdk /opt/intel/sgxsdk

COPY --from=builder /linux-sgx/linux/installer/bin/sgx_linux_x64_psw*.bin .
RUN ./sgx_linux_x64_psw*.bin --no-start-aesm && rm -f sgx_linux_x64_psw*.bin

# ---- Set up project source ----
COPY . /usr/src/sdk
RUN ls /usr/src/sdk/autoconf.bash
WORKDIR /usr/src/sdk

# ---- Install development & runtime packages ----
RUN apt update && \
    apt install -yq apt-utils && \
    apt install -yq --no-install-recommends ca-certificates perl \
        alien uuid-dev libxml2-dev ccache \
        yasm libprocps-dev \
        libgnutls28-dev libgcrypt20-dev \
        curl secure-delete python3-pip && \
    ln -s /usr/bin/ccache /usr/local/bin/clang && \
    ln -s /usr/bin/ccache /usr/local/bin/clang++ && \
    ln -s /usr/bin/ccache /usr/local/bin/gcc && \
    ln -s /usr/bin/ccache /usr/local/bin/g++ && \
    ln -s /usr/bin/ccache /usr/local/bin/cc && \
    ln -s /usr/bin/ccache /usr/local/bin/c++ && \
    apt clean && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --upgrade pip && pip3 install --no-cache-dir requests torpy

# ---- Build dependencies, project, and clean up ----
RUN cd scripts && ./build_deps.py && \
    wget --progress=dot:mega -O - https://github.com/intel/dynamic-application-loader-host-interface/archive/072d233296c15d0dcd1fb4570694d0244729f87b.tar.gz | tar -xz && \
    cd dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b && \
    cmake . -DCMAKE_BUILD_TYPE=Release -DINIT_SYSTEM=SysVinit && make -j$(nproc) install && \
    cd /usr/src/sdk && rm -rf scripts/dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b && \
    ./autoconf.bash && \
    touch /var/hwmode && \
    ./configure && \
    make -j$(nproc) && \
    make -C tests/backward_compatibility api_validator && \
    ccache -sz && mkdir -p sgx_data && \
    # ---- Remove build artifacts to minimize image size ---- \
    rm -rf \
        libBLS/deps/boost_1_* libBLS/deps/openssl libBLS/deps/curl \
        libBLS/deps/gmp-6.1.2 libBLS/deps/libff libBLS/deps/jsoncpp \
        libBLS/deps/libjson-rpc-cpp libBLS/deps/libjson-rpc-cpp-develop \
        libBLS/deps/libmicrohttpd libBLS/deps/argtable2 libBLS/deps/zlib \
        libBLS/deps/pre_downloaded "libBLS/deps/*.tar.*" \
        libBLS/deps/deps_inst/x86_or_x64/include \
        libBLS/deps/deps_inst/x86_or_x64/share \
        libBLS/deps/deps_inst/x86_or_x64/bin \
        libBLS/build libBLS/test libBLS/docs \
        libzmq leveldb cppzmq rapidjson third_party \
        linux-sgx-driver intel-sgx-ssl jsonrpc \
        gmp-build tgmp-build sgx-gmp sgx-sdk-build \
        docs performance-tests \
        .deps secure_enclave/.deps autom4te.cache config.log \
        /opt/intel/sgxsdk/include /opt/intel/sgxsdk/SampleCode \
        /install_packages.sh /tmp/* /root/.cache && \
    find . -name '*.o' -delete 2>/dev/null; \
    find . -name '.git' -type d -exec rm -rf {} + 2>/dev/null; \
    rm -f /opt/intel/sgxsdk/lib64/*_sim.so; \
    strip --strip-unneeded sgxwallet testw sgx_util tests/backward_compatibility/api_validator 2>/dev/null; \
    true

COPY docker/start.sh ./
COPY docker/check_firewall.py ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
