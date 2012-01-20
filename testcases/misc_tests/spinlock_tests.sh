#!/bin/bash
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
