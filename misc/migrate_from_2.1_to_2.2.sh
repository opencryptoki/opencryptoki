#!/bin/sh

# This script should be run after installing openCryptoki version 2.2.x on a
# machine where openCryptoki version 2.1.x has already been installed.

# Make sure that no copies of pkcsslotd are running
ps -ef | grep pkcsslotd | grep sbin &> /dev/null
RES=$?
if [ $RES = 0 ]; then
    killall pkcsslotd
fi

# Copy files from /etc/pkcs11/ to /var/lib/opencryptoki/
if [ -e "/etc/pkcs11" ]; then
    mkdir -p /var/lib/opencryptoki
    cp -aR /etc/pkcs11/* /var/lib/opencryptoki/
    cp -a /etc/pkcs11/.slotpid /var/lib/opencryptoki/
fi

# Run startup script
/usr/sbin/pkcs11_startup

# Restart pkcsslotd if it was running before this script was run
if [ $RES = 0 ]; then
    /usr/sbin/pkcsslotd
fi