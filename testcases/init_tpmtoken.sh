#!/usr/bin/expect -f
#
# COPYRIGHT (c) International Business Machines Corp. 2010-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
#

spawn tpmtoken_init -y
set timeout 1
expect {
    "Enter the TPM security officer password: " { send "76543210\r"}
}

set timeout 10

expect {
    "Enter new password: "      { send "76543210\r" }
}

expect {
    "Confirm password: "        { send "76543210\r" }
}

expect {
    "Enter new password: "      { send "01234567\r" }
}

expect {
    "Confirm password: "        { send "01234567\r" }
}
