#!/bin/bash
#
#
#   Copyright (C) International Business Machines  Corp., 2008
#
#   This program is free software;  you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY;  without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
#   the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program;  if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#
# NAME
#	ocktests.sh
#
# DESCRIPTION
#	Simple Bash script that checks the enviroment in which the ock-tests will run
#	and starts them.
#
# ALGORITHM
#	None.
#
# USAGE
#
# HISTORY
#	Rajiv Andrade <srajiv@linux.vnet.ibm.com>
#
# RESTRICTIONS
#	None.
##


LOGFILE="$PWD/ock-tests.log"
ERR_SUMMARY="$PWD/ock-tests.err"
TCSD="/usr/sbin/tcsd"
PKCONF="/var/lib/opencryptoki/pk_config_data"
PKCSCONFBIN="/usr/sbin/pkcsconf"
TESTCONF="$PWD/ock-tests.config"
OCKDIR="/var/lib/opencryptoki"
STDLLDIR="/usr/lib/pkcs11/stdll"
CONFSTART="/usr/sbin/pkcs11_startup"
TEST="./driver/driver"

usage()
{
	cat <<-END >&2
	usage: ./ock_tests.sh [-s <slot>] [-l <logfile>] [-n] [-h]
		-l	  logfile to redirect output to (default is command line)
		-h	  display this help
		-q	  run quietly - display only total number of tests passed/failed
		-s <slot> slot against which the testcases will run
		-n	  don't stop in case one of the testcases fail
	END
	exit -1
}


while getopts s:lhc:n arg
do
	case $arg in
		h)
			usage
			;;
		l)
			LOGGING=1
			touch $LOGFILE
			;;
		c)
			TESTCONF="$OPTARG"
			touch $TESTCONF
			;;
		n)	
			NO_STOP="-nostop"
			;;
		s)
			SLOT="$OPTARG"
			;;
	esac
done

check_slots()
{
	[ -d $OCKDIR ] || echo "$OCKDIR not present"

	#pkcsslotd running?
	if [ -z "`pgrep pkcsslotd`" ]
	then 
		echo "Error: pkcsslotd not started"
		exit -1
	fi

	#Are all the tokens listed in pk_config_data loaded?
	for i in $( cat $PKCONF | awk -F \| '{print $3}' )
	do
		if [ -z "`$PKCSCONFBIN -s | grep $i`" ]
		then
			echo "Warning: Token not loaded: $i"
		
			if [ -n "`echo $i | grep -i TPM`" ]
			then
				[ -n "`pgrep tcsd`" ] || echo " TCSD not running"
				[ -n "`lsmod | grep tpm`" ] || echo " TPM kernel module not loaded"
			fi
			echo
		fi
	done
}

check_files()
{
	#Not implemented yet
	#[ -e $TESTCONF ] || touch $TESTCONF #echo "Config file missing"
	
	#Is the TCSD present?
	if [ `grep -c -i tpm $PKCONF` > 0 ] && [ ! -e $TCSD ] 
	then
		echo "Error: TCSD not present"
		exit -1
	fi
	

	#Checks if for each token in $PKCFONF there is a .so file.
	if [ -e $PKCONF ] 
	then
		for i in $( cat $PKCONF | awk -F \| '{print $13}' )
		do
			if [ ! -e $STDLLDIR/$i ]
			then
				echo "Error: $i not present"
				exit -1
			fi
		done

	else
		echo "Error: pk_config_data is missing"
		exit -1
	fi
}

check_environment_vars()
{

	if [ `env | grep -c PKCS11` -lt 2 ] 
	then
		[ -n "`env | grep PKCS11_SO_PIN`" ] ||	echo "Error: PKCS11_SO_PIN not set"
		[ -n "`env | grep PKCS11_USER_PIN`" ] ||  echo "Error: PKCS11_USER_PIN not set"
		exit -1
	fi
	
	i=`env | grep PKCSLIB | sed "s/PKCSLIB=//"`

	if [ -z "$i" ]
	then
		echo "Warning: PKCSLIB not set."
		echo " It should point to libopencryptoki.so or PKCS11_API.so"
	elif [ -z "`echo $i | grep libopencryptoki.so`" ] && [ -z "`echo $i | grep PKCS11_API.so`" ]
	then
		echo "Error: PKCSLIB pointing to a wrong .so file"
		exit -1
	elif [ "basename `ls $i`" != "libopencryptoki.so" ] && [ "basename `ls $i`" != "PKCS11_API.so" ]
	then
		echo "Error: File pointed by PKCSLIB doesn't exist"
		exit -1
	fi

}
run_tests()
{
	
	for i in $( $PKCSCONFBIN -t | grep Info: | awk {'print $2'} | sed 's/#//' ) 
	do
		if [ -z "$SLOT" ] || [ "$SLOT" = "$i" ]
		then
			if [ $LOGGING -eq 1 ]
			then
				$TEST -slot $i $NO_STOP 2>&1 >> $LOGFILE
			else
				$TEST -slot $i $NO_STOP  2>&1 >/dev/tty 
			fi
		fi
	done
}

check_slots
check_files
check_environment_vars
run_tests
exit 0

