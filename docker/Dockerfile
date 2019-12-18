FROM ubuntu:bionic

WORKDIR /usr/src/sdk

RUN apt-get update && apt-get install -yq --no-install-recommends python-yaml vim telnet git ca-certificates build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev libssl-dev libcurl4-openssl-dev protobuf-compiler git libprotobuf-dev alien cmake debhelper uuid-dev libxml2-dev
RUN apt install -y libprotobuf10 yasm cmake flex bison  libprocps-dev ccache autoconf texinfo libssl-dev libboost-all-dev libjsonrpccpp-dev libjsonrpccpp-tools

COPY install-psw.patch ./

RUN git clone -b sgx_2.5 --depth 1 https://github.com/intel/linux-sgx && \
    cd linux-sgx && \
    patch -p1 -i ../install-psw.patch && \
    ./download_prebuilt.sh 2> /dev/null && \
    make -s -j$(nproc) sdk_install_pkg psw_install_pkg && \
    ./linux/installer/bin/sgx_linux_x64_sdk_2.5.100.49891.bin --prefix=/opt/intel && \
    ./linux/installer/bin/sgx_linux_x64_psw_2.5.100.49891.bin && \
    cd .. && rm -rf linux-sgx/


# For debug purposes
# COPY jhi.conf /etc/jhi/jhi.conf

###RUN git clone --recurse-submodules https://76b7983ebf14269178b99eff5b2be4b4b56fe7a5:@github.com/skalenetwork/sgxwallet.git
RUN git clone --recurse-submodules --single-branch --branch feature/SKALE-1850-remove-extra-dependencies-from-SGX https://76b7983ebf14269178b99eff5b2be4b4b56fe7a5:@github.com/skalenetwork/sgxwallet.git
WORKDIR  sgxwallet
#RUN cd sgx-software-enable && make && ./sgx_enable
RUN cd scripts; ./build.py
### RUN autoreconf -vif
### RUN automake
RUN autoreconf -vif
RUN libtoolize --force
RUN aclocal
RUN autoheader || true
RUN automake --force-missing --add-missing
RUN autoconf
RUN ./configure
### RUN cd libBLS; cmake -H. -Bbuild; cmake --build build -- -j$(nproc);
RUN make
RUN wget --progress=dot:mega -O - https://github.com/intel/dynamic-application-loader-host-interface/archive/072d233296c15d0dcd1fb4570694d0244729f87b.tar.gz | tar -xz && \
    cd dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b && \
    cmake . -DCMAKE_BUILD_TYPE=Release -DINIT_SYSTEM=SysVinit && \
    make install && \
    cd .. && rm -rf dynamic-application-loader-host-interface-072d233296c15d0dcd1fb4570694d0244729f87b

COPY start.sh ./
