#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2012-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
#

while getopts "s:p:l:" option
do
 case $option in
"s")
	slotid="$OPTARG"
	;;
"p")
	procnum="$OPTARG"
	;;
"l")
	loopcount="$OPTARG"
	;;
[?])
	echo "Usage: -s <slotid> -p <num_of_processes> -l <loopcount>"
	exit
	;;
esac
done

if [ -z $slotid ] || [ -z $procnum ] || [ -z $loopcount ]; then
	echo "Usage: -s <slotid> -p <num_of_processes> -l <loopcount>"
	exit
fi

while [ $procnum -gt 0 ]
do
	echo "Starting child process #$procnum"
	(./spinlock_child.sh -s $slotid -l $loopcount;) &
	let procnum=procnum-1
done

wait
echo "Exiting parent loop"
