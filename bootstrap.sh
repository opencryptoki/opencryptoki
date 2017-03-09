#!/bin/sh
#
# COPYRIGHT (c) International Business Machines Corp. 2001-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
#

#set -x
aclocal
libtoolize --force -c
automake --add-missing -c
autoconf
