#!/bin/sh
set -x
aclocal
libtoolize --force -c
automake --add-missing -c
autoconf
