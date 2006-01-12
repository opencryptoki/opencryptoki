#!/bin/sh

# Move files from /etc/pkcs11 to /var/lib/
if [ -e "/etc/pkcs11" ]; then
    mkdir -p /var/lib/opencryptoki
    cp -R /etc/pkcs11/* /var/lib/opencryptoki/
fi
