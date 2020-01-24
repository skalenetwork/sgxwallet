FROM skalenetwork/sgxwallet_base:latest
WORKDIR /usr/src/sdk

COPY *.cpp ./
COPY *.h ./
COPY *.txt ./
COPY *.c ./
COPY *.am ./
COPY *.hpp ./
COPY *.sh ./
COPY *.m4 ./
COPY *.gmp ./
COPY *.ac ./
COPY *.json ./
COPY docker ./docker
COPY build-aux ./build-aux
COPY  cert ./cert
COPY jsonrpc ./jsonrpc
COPY leveldb ./leveldb
COPY m4 ./m4
COPY scripts ./scripts
COPY secure_enclave ./secure_enclave
COPY spdlog ./spdlog


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

RUN mkdir /user/src/sdk/sgx_data

COPY docker/start.sh ./
ENTRYPOINT ["/usr/src/sdk/start.sh"]
