#!/bin/bash
#


while getopts ":s:l:" option
do
  case $option in
"s")
	slotid="$OPTARG"
	;;
"l")
	loopcount="$OPTARG"
	;;
[?])
	echo "Usage: -s <slotid> -l loopcount"
	;;
esac
done

i="0"
echo $$
while [ $i -lt $loopcount ]
do
	./obj_mgmt_lock_tests -slot $slotid
	i=$[$i+1]
done
