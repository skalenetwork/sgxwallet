#!/bin/bash

# This script is also used by docker files to install
# the required packages for building the project.

apt update
apt install -y --no-install-recommends build-essential \
    ca-certificates \
    ocaml \
    ocamlbuild \
    automake \
    autoconf \
    libtool \
    wget \
    python-is-python3 \
    libssl-dev \
    git \
    cmake \
    perl \
    libcurl4-openssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    debhelper \
    reprepro \
    unzip \
    pkgconf \
    liblzma-dev \
    libboost-dev \
    libboost-system-dev \
    libboost-thread-dev \
    libtbb-dev \
    lsb-release \
    libsystemd0 \
    clang \
    llvm