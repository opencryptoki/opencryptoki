#!/bin/sh
set -x
aclocal
libtoolize --force
automake --add-missing -c
autoconf
