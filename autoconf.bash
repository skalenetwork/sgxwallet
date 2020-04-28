#!/bin/bash
libtoolize --force
aclocal
autoheader || true
automake --force-missing --add-missing
autoconf