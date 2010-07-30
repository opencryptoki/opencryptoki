#!/bin/sh
#
# digest_test.sh - script to test PKCS#11 digest algorithms using oc-digest
#
# usage: digest_test.sh [-slot <slot id>]
#
# Author: Kent Yoder <key@linux.vnet.ibm.com>
#
# This script will do the following for each digest type in the $digest_types
#  array:
#
# 1. Check that the algorithm is supported in the slot being tested
# 2. generate a set of files to test based on the block size of the algorithm
# 3. Hash those files using oc-digest and validate the output
# 4. delete the test files
#
#  TO ADD A NEW ALGORITHM TO TEST TO THIS SCRIPT:
# 1. increment num_digest_types below
# 2. add new entries for your alg into the $digest_types, $digest_sizes and
#    $validators arrays below
# 3. that's it
#

#set -x

# num_digest_types should be the number of items in the $digest_types,
# $digest_sizes and $validators arrays below. This script will loop from
# 0 .. ($num_digest_types - 1)
num_digest_types=5

# algorithms to test - these are strings that are valid to pass to the -t
#  option of oc-digest
#
digest_types[0]="sha1"
digest_types[1]="sha256"
digest_types[2]="sha384"
digest_types[3]="sha512"
digest_types[4]="md5"

# the block sizes of each algorithm - we use these to base the size of
#  some of thest files on
#
digest_sizes[0]=20
digest_sizes[1]=32
digest_sizes[2]=48
digest_sizes[3]=64
digest_sizes[4]=16

# an external program to validate each type of hash
validators[0]="sha1sum -c"
validators[1]="sha256sum -c"
validators[2]="sha384sum -c"
validators[3]="sha512sum -c"
validators[4]="md5sum -c"

# default slot is 0, but -slot argument will override
SLOT_ID=0

# return codes
CKR_OK=0
CKR_MECHANISM_INVALID=112

# a list which will be populated with an array of indexes of algorithms
# supported by this token. This array will determine which algs are tested
digest_types_to_test=

FILE_NAMES=
# always test a 0 and 1 byte file, all other file sizes to test are based on
# the block size of the algorithm being tested
FILE_SIZES_INITIALIZER="0 1"
FILE_SIZES=${FILE_SIZES_INITIALIZER}

# return code to the command line
GLOBAL_RC=0

#
# run a test
#
# $1 - algorithm to test
# $2 - filename to test
# $3 - (optional) validator to use
#
function run_test
{
	if test "x$3" == "x"; then
		./oc-digest/oc-digest -slot $SLOT_ID -t $1 $2
	else
		./oc-digest/oc-digest -slot $SLOT_ID -t $1 $2 | $3
	fi

	return $?
}

function exit_with_code
{
	exit $1
}

#
# given a block size, generate test files
#
# $1 = block size
function generate_testfiles
{
	HASH_BLOCK_SIZE=$1
	# This is the list of file sizes to test for each digest algorithm
	FILE_SIZES="$FILE_SIZES $HASH_BLOCK_SIZE"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE + 1 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE - 1 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE / 2 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 2 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 4 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 8 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 16 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 5 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 10 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 100 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 1000 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 1024 ))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 1024 + 1))"
	FILE_SIZES="$FILE_SIZES $(( $HASH_BLOCK_SIZE * 1024 - 1))"

	for FILE_SIZE in $FILE_SIZES
	do
		FILE_NAME="${FILE_SIZE}_byte_file"

		if test $FILE_SIZE -eq 0; then
			touch $FILE_NAME
		else
			dd if=/dev/urandom of=$FILE_NAME count=1 bs=$FILE_SIZE >/dev/null 2>&1
		fi

		RC=$?
		if test $RC -ne 0; then
			echo "error generating $FILE_NAME"
			return $RC
		fi
	done
}

#
# given a block size, run tests on a set of files
#
# $1 = index of $digest_types to test
function run_tests
{
	INDEX=$1
	for FILE_SIZE in $FILE_SIZES
	do
		FILE_NAME="${FILE_SIZE}_byte_file"
		run_test ${digest_types[$INDEX]} ${FILE_NAME} "${validators[$INDEX]}"
		RC=$?
		if test $RC -ne 0; then
			echo "error testing ${digest_types[$INDEX]} $FILE_NAME"
			if test $NOSTOP -eq 0; then
				GLOBAL_RC=$RC
				return
			fi
		fi
	done
}

#
# delete test files
#
function cleanup_testfiles
{
	for FILE_SIZE in $FILE_SIZES
	do
		FILE_NAME="${FILE_SIZE}_byte_file"
		rm -f ./$FILE_NAME
	done
}

function usage
{
	echo "usage: $1 [-slot <slot id>] [-nostop]"
	exit -1
}

#
# main()
#

#
# Check for -slot, -nostop params
#
while test "x$1" != "x"; do
	if test "x$1" == "x-slot"; then
		if test "x$2" != "x"; then
			shift
			SLOT_ID=$1
			shift
			continue
		else
			usage $0
		fi
	elif test "x$1" == "x-nostop"; then
		shift
		NOSTOP=1
	else
		usage $0
	fi
done

#
# for each of the digest types, try to hash some random file as a test to
# see if that algorithm is supported on this token
#
for i in $(seq 0 $(( $num_digest_types - 1 )))
do
	echo "Testing if slot $SLOT_ID supports ${digest_types[$i]}..."
	run_test ${digest_types[$i]} /bin/ls
	RC=$?
	if test $RC -eq $CKR_MECHANISM_INVALID; then
		# this alg isn't supported on this token, test the next alg
		echo "nope."
		continue
	elif test $RC -eq $CKR_OK; then
		# this alg is supported, add it to the list to test
		echo "yes. ${digest_types[$i]} will be tested."
		digest_types_to_test="$digest_types_to_test $i"
	else
		# error, exit as user intervention is required
		echo "Error ($RC) while determining if ${digest_types[$i]} is supported"
		exit_with_code $RC
	fi
done

# generate files to test and run the testcases
for i in $digest_types_to_test
do
	echo "Testing ${digest_types[$i]}..."
	generate_testfiles ${digest_sizes[$i]}
	RC=$?
	if test $RC -ne 0; then
		GLOBAL_RC=$RC
		cleanup_testfiles
	else
		run_tests $i
	fi
	cleanup_testfiles
	FILE_SIZES=${FILE_SIZES_INITIALIZER}
done

exit $GLOBAL_RC
