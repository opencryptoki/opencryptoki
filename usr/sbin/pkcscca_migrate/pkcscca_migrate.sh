#!/bin/sh
#
# Script to aid the migration app for an openCryptoki CCA token
#
# Steps:
# 1. Back up the entire data store
# 2. Attempt migration
# 3. If migration fails, restore the backup
#
# This will support two versions of openCryptoki, 2.1.7 and the SLES10
# version. The differences are in the location of the executables and
# data store.
#
# Author: Kent Yoder <yoder1@us.ibm.com>
#

# The openCryptoki 2.1.7 location
CONF_LOC_1=/usr/lib/pkcs11/methods/pkcsconf64
# The openCryptoki SLES10 location
CONF_LOC_2=/usr/sbin/pkcsconf64

# The openCryptoki 2.1.7 location
STORE_LOC_1=/etc/pkcs11/ccatok
# The openCryptoki SLES10 location
STORE_LOC_2=/var/lib/opencryptoki/ccatok

SO_PIN=
USER_PIN=
SLOT_ID=
PKCSCONF=
MIGRATION_APP=/usr/sbin/pkcscca_migrate
TAR=/bin/tar
BACKUP_DIRNAME="`pwd`"
BACKUP_FILENAME="pkcs11_cca_data_backup_`date +%Y%m%d_%H%M%S`.tar.gz"
BACKUP_FILE="$BACKUP_DIRNAME/$BACKUP_FILENAME"
DATA_STORE=


usage()
{
	echo "Usage: $0 <options>"
	echo
	echo "Options:"
	echo
	echo "--slot-id <num>     The slot of the token you wish to migrate"
	echo "--dry-run           Perform the steps without actually writing the migrated data"
	echo "-v                  Increase the verbosity of the migration utility"
	echo

	exit 255
}

backup()
{
	echo "Backing up the data store before we migrate"

	cd $DATA_STORE
	# Backup the old store before we begin
	$TAR zcf $BACKUP_FILE .
	cd -

	if ! test -f $BACKUP_FILE; then
		echo "Unable to perform backup to $BACKUP_FILE"
		exit 7
	fi
	echo "Wrote backup file: $BACKUP_FILE"
}

restore()
{
	echo "Restoring from backup..."

	cd $DATA_STORE
	rm -rf ./*
	$TAR zxf $BACKUP_FILE
	cd -

	echo "Restore complete."
}

migrate()
{
	#
	# Get the USER and SO pins
	#
	read -s -p "Please enter this token's USER PIN: " USER_PIN
	echo
	read -s -p "Please enter this token's SO PIN: " SO_PIN
	echo

	#
	# Double check the user's entered slot id
	#
	$PKCSCONF -s -c $SLOT_ID

	read -p "About to migrate this token. Continue? [y/N] " RESP
	if test "x$RESP" != "xy" && test "x$RESP" != "xY"; then
		echo "Aborted by user."
		exit 6
	fi

	#
	# Backup before we begin
	#
	backup

	#
	# Do the migration using the app
	#
	echo "Migrating..."
	set -x
	$MIGRATION_APP $DRY_RUN $VERBOSE -c $SLOT_ID -d $DATA_STORE -s $SO_PIN -u $USER_PIN
	RC=$?
	set +x

	if test $RC -ne 0; then
		echo "Migration failed with return code $RC, restoring from backup."
		restore

		#
		# XXX Give the user some advice based on the error code
		#
		echo
		echo "Migration failed."
		echo
		exit $RC
	fi

	echo "Success"
	exit 0
}



#
# Program execution begins here
#

P11GROUP=0
for G in `groups` ; do
	if test "x$G" == "xpkcs11"; then
		P11GROUP=1
	fi
done

if test $EUID -ne 0 && test $P11GROUP -eq 0; then
	echo "It appears that you're not root or a member of the pkcs11 group."
	echo "You may run into trouble when trying to migrate some internal data used by openCryptoki."
	read -p "Would you like to try anyway? [y/N]? " RESP

	if test "x$RESP" != "xy" && test "x$RESP" != "xY"; then
		echo "Aborted."
		exit 1
	fi
fi

# Find the correct pkcsconf64
if test -x $CONF_LOC_1; then
	PKCSCONF=$CONF_LOC_1
elif test -x $CONF_LOC_2; then
	PKCSCONF=$CONF_LOC_2
else
	echo "Couldn't find pkcsconf64 executable! The following locations were checked:"
	echo "$CONF_LOC_1"
	echo "$CONF_LOC_2"
	echo "Exiting."
	exit 2
fi

# Find the correct data store location
if test -d $STORE_LOC_1; then
	DATA_STORE=$STORE_LOC_1
elif test -d $STORE_LOC_2; then
	DATA_STORE=$STORE_LOC_2
else
	echo "Couldn't find data store to archive! The following locations were checked:"
	echo "$STORE_LOC_1"
	echo "$STORE_LOC_2"
	echo "Exiting."
	exit 3
fi

while test "x$1" != "x"; do
	case "$1" in
		--slot-id)
			if test "x$2" == "x"; then
				usage
			fi
			SLOT_ID=$2

			shift 2
			;;

		--dry-run)
			DRY_RUN="-n"

			shift
			;;

		-v)
			VERBOSE="${VERBOSE:-"-"}v"

			shift
			;;

		*)
			usage
			;;
	esac
done

# Get a list of valid slot numbers
SLOTS=`$PKCSCONF -s | awk '/Slot #/ {print $2 " "}'`

if test "x$SLOT_ID" != "x"; then
	if test "x${SLOTS/"\#$SLOT_ID "/}" == "x$SLOTS"; then
		echo "Slot $SLOT_ID is not a valid slot number."
		exit 4
	fi
else
	# No slot provided, display active slots for user to choose from

	echo "A slot id was not provided, below is a list of the available pkcs11 slots:"
	echo
	$PKCSCONF -s
	echo

	while : ; do
		read -p "Which slot would you like to migrate (enter \"x\" to exit)? " RESP
		test "x$RESP" == "x" && continue
		test "x$RESP" == "xx" && exit 5

		SLOT_ID=$RESP
		if test "x${SLOTS/"\#$SLOT_ID "/}" == "x$SLOTS"; then
			echo "Slot $SLOT_ID is not a valid slot number."
			continue
		fi
		break
	done
fi

# All is well, begin at migrate
migrate
