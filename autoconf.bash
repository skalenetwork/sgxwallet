#!/bin/bash

# Bootstrap Autotools build system.
# This script generates/updates the generated build machinery from:
#   - configure.ac (Autoconf input)
#   - Makefile.am  (Automake input)
# and installs helper macro files/scripts required by libtool/autotools.

set -e

# Scans configure.ac and m4/ local folder to collect all m4 macros into aclocal.m4 
# so autoconf can expand them.
# Picks up macros from ./m4 (see AC_CONFIG_MACRO_DIRS([m4])) and system aclocal dirs.
aclocal

# Convert Makefile.am -> Makefile.in, and install helper scripts if missing:
#    - compile, missing, depcomp, install-sh, etc.
automake --force-missing --add-missing

autoconf