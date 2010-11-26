#!/bin/sh
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
