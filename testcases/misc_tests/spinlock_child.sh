#!/bin/bash
#
# COPYRIGHT (c) International Business Machines Corp. 2012-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
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
