#!/bin/sh
#
# COPYRIGHT (c) International Business Machines Corp. 2010-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
#

for j in S A E; do
	echo "---"
	echo "CLEARING 'NEW' register for key type '$j'"
	panel.exe -c -t $j
	echo "Exit value was '$?'"
	for i in F M L; do
		echo "  LOADING key type '$j', key part '$i'"
		if [ "$j" = "E" ]; then
			panel.exe -l -t $j -p $i 0202020202020202020202020202020202020202020202020202020202020202
		else
			panel.exe -l -t $j -p $i 020202020202020202020202020202020202020202020202
		fi
		echo "  Exit value was '$?'"
	done
	echo "SETTING new key"
	panel.exe -s -t $j
	echo "Exit value was '$?'"
done
