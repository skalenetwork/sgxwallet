FROM ubuntu:bionic

COPY . /usr/src/sdk
RUN ls /usr/src/sdk/autoconf.bash
WORKDIR /usr/src/sdk

COPY docker/install-psw.patch ./

# Reduce space, install requirements, and build SGXWallet
RUN apt-get update && \
    apt-get install -yq apt-utils && \
    apt-get install -yq --no-install-recommends \
        alien \
        autoconf \
        automake \
        bison \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        curl \
        debhelper \
        flex \
        git \
        libboost-all-dev \
        libcurl4-openssl-dev \
        libjsonrpccpp-dev \
        libjsonrpccpp-tools \
        libprocps-dev \
        libprotobuf10 \
        libprotobuf-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        ocaml \
        ocamlbuild \
        protobuf-compiler \
        python \
        python-yaml \
        telnet  \
        texinfo \
        uuid-dev \
        vim \
        wget \
        yasm && \
       ln -s /usr/bin/ccache /usr/local/bin/clang && \
       ln -s /usr/bin/ccache /usr/local/bin/clang++ && \
       ln -s /usr/bin/ccache /usr/local/bin/gcc && \
       ln -s /usr/bin/ccache /usr/local/bin/g++ && \
       ln -s /usr/bin/ccache /usr/local/bin/cc && \
       ln -s /usr/bin/ccache /usr/local/bin/c++ && \
       git clone -b sgx_2.5 --depth 1 https://github.com/intel/linux-sgx && \
       cd linux-sgx && \
       patch -p1 -i ../install-psw.patch && \
       ./download_prebuilt.sh 2> /dev/null && \
       make -s -j$(nproc) sdk_install_pkg psw_install_pkg && \
       ./linux/installer/bin/sgx_linux_x64_sdk_2.5.100.49891.bin --prefix=/opt/intel && \
       ./linux/installer/bin/sgx_linux_x64_psw_2.5.100.49891.bin && \
       cd .. && rm -rf linux-sgx/ && cd scripts && ./build_deps.py && \
       wget --progress=dot:mega -O - https://github.com/intel/dynamic-application-loader-host-interface/archive/072d233296c15d0dcd1fb4570694d0244729f87b.tar.gz | tar -xz && \
       cd dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b && \
       cmake . -DCMAKE_BUILD_TYPE=Release -DINIT_SYSTEM=SysVinit && \
       make install && \
       cd .. && rm -rf dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b && \
       cd /usr/src/sdk && \
       ./autoconf.bash && \
       ./configure  && \
       bash -c "make -j$(nproc)"
