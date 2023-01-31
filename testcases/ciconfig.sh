#!/bin/bash

OCKCONFDIR="$1"
EPCONFDIR="$2"
CCACONFDIR="$3"

LATESTCEXP="CEX7P"

CCA_SYM_MKVP="5776993D2741EB4A"
CCA_AES_MKVP="E9A49A58CD039BED"
CCA_APKA_MKVP="5F2F27AAA2D59B4A"
EP11_WKVP="8b991263e3a8f4e4be0d5ec8f0a4df9e"

USENEWFORMAT=/bin/false

# Usage: addslot slot-num stdll slot-name [confname]
function addslot() {
    cat <<EOF >> "${OCKCONFDIR}/opencryptoki.conf"
slot $1
{
stdll = $2
tokname = $3
EOF
    if $USENEWFORMAT; then
        echo "tokversion = 3.12" >> "${OCKCONFDIR}/opencryptoki.conf"
    fi
    if [ "x$4" != "x" ]; then
       echo "confname = $4" >> "${OCKCONFDIR}/opencryptoki.conf"
    fi
    echo "}" >> "${OCKCONFDIR}/opencryptoki.conf"
}

# Usage: genep11cfg num configline
function genep11cfg() {
    cat <<EOF > "${EPCONFDIR}/ep11tok${1}.conf"
${2}
APQN_ANY
EOF
}

# Usage: genlatestep11cfg num configline
# Return: 0 if successful
function genlatestep11cfg() {
    local res=1
    
    lszcrypt | grep "$LATESTCEXP" | perl -ne '/([0-9a-fA-F]+)\.([0-9a-fA-F]+)\s.*/ && print "0x$1 0x$2\n"' > tmp.apqns
    if test -s tmp.apqns; then
        echo ${2}
        echo "APQN_WHITELIST" > "${EPCONFDIR}/ep11tok${1}.conf"
        cat tmp.apqns >> "${EPCONFDIR}/ep11tok${1}.conf"
        echo "END" >> "${EPCONFDIR}/ep11tok${1}.conf"
        res=0
    fi
    rm -f tmp.apqns
    return $res
}

# Usage: genccamkvpcfg num
function genccamkvpcfg() {
    cat <<EOF > "${CCACONFDIR}/ccatok${1}.conf"
version cca-0
EXPECTED_MKVPS {
  SYM = "$CCA_SYM_MKVP"
  AES = "$CCA_AES_MKVP"
  APKA = "$CCA_APKA_MKVP"
}
EOF
}

if test $(($(date +%j)%2)) == 1; then
    USENEWFORMAT=/bin/true
    echo "Using FIPS compliant token store"
else
    echo "Using legacy token store"
fi

# initialize opencryptoki.conf
echo "version opencryptoki-3.19" > "${OCKCONFDIR}/opencryptoki.conf"

# enable full statistics
echo "statistics (on,implicit,internal)" >> "${OCKCONFDIR}/opencryptoki.conf"

# ICA token
addslot 10 libpkcs11_ica.so ica0
addslot 11 libpkcs11_ica.so ica1

# CCA token
genccamkvpcfg 20
addslot 20 libpkcs11_cca.so cca0 ccatok20.conf
addslot 21 libpkcs11_cca.so cca1

# SW token
addslot 30 libpkcs11_sw.so sw0
addslot 31 libpkcs11_sw.so sw1

# EP11 token
# 0:
# APQN_ANY
# EXPECTED_WKVP "wkvp"
genep11cfg 40 "EXPECTED_WKVP \"$EP11_WKVP\""
addslot 40 libpkcs11_ep11.so ep0 ep11tok40.conf

# 1:
# FORCE_SENSITIVE
# APQN_ANY
genep11cfg 41 "FORCE_SENSITIVE"
addslot 41 libpkcs11_ep11.so ep1 ep11tok41.conf

# 2:
# STRICT_MODE
# APQN_ANY
# later appended: VHSM_MODE

#genep11cfg 42 "STRICT_MODE"
#addslot 42 libpkcs11_ep11.so ep2 ep11tok42.conf

# 3:
# OPTIMIZE_SINGLE_PART_OPERATIONS
# APQN_ANY
genep11cfg 43 "OPTIMIZE_SINGLE_PART_OPERATIONS"
addslot 43 libpkcs11_ep11.so ep3 ep11tok43.conf

# 4:
# DIGEST_LIBICA OFF
# APQN_ANY
genep11cfg 44 "DIGEST_LIBICA OFF"
addslot 44 libpkcs11_ep11.so ep4 ep11tok44.conf

# 5: latest (CEX7 only)
# PKEY_MODE ENABLE4NONEXTR
if genlatestep11cfg 45 "PKEY_MODE ENABLE4NONEXTR"; then
    addslot 45 libpkcs11_ep11.so ep5 ep11tok45.conf
fi
