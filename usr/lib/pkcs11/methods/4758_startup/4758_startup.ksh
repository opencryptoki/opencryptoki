#!/usr/bin/ksh

#
#
# $Header: /cvsroot/opencryptoki/opencryptoki/usr/lib/pkcs11/methods/4758_startup/Attic/4758_startup.ksh,v 1.1 2005/01/18 16:09:00 kyoder Exp $
#


#
#             Common Public License Version 0.5

#             THE ACCOMPANYING PROGRAM IS PROVIDED UNDER THE TERMS OF
#             THIS COMMON PUBLIC LICENSE ("AGREEMENT"). ANY USE,
#             REPRODUCTION OR DISTRIBUTION OF THE PROGRAM CONSTITUTES
#             RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT.
#
#             1. DEFINITIONS
#
#             "Contribution" means: 
#                   a) in the case of the initial Contributor, the
#                   initial code and documentation distributed under
#                   this Agreement, and 
#
#                   b) in the case of each subsequent Contributor:
#                   i) changes to the Program, and
#                   ii) additions to the Program;
#
#                   where such changes and/or additions to the Program
#                   originate from and are distributed by that
#                   particular Contributor. A Contribution 'originates'
#                   from a Contributor if it was added to the Program
#                   by such Contributor itself or anyone acting on such
#                   Contributor's behalf. Contributions do not include
#                   additions to the Program which: (i) are separate
#                   modules of software distributed in conjunction with
#                   the Program under their own license agreement, and
#                   (ii) are not derivative works of the Program.
#
#
#             "Contributor" means any person or entity that distributes
#             the Program.
#
#             "Licensed Patents " mean patent claims licensable by a
#             Contributor which are necessarily infringed by the use or
#             sale of its Contribution alone or when combined with the
#             Program. 
#
#             "Program" means the Contributions distributed in
#             accordance with this Agreement.
#
#             "Recipient" means anyone who receives the Program under
#             this Agreement, including all Contributors.
#
#             2. GRANT OF RIGHTS
#
#                   a) Subject to the terms of this Agreement, each
#                   Contributor hereby grants Recipient a
#                   non-exclusive, worldwide, royalty-free copyright
#                   license to reproduce, prepare derivative works of,
#                   publicly display, publicly perform, distribute and
#                   sublicense the Contribution of such Contributor, if
#                   any, and such derivative works, in source code and
#                   object code form.
#
#                   b) Subject to the terms of this Agreement, each
#                   Contributor hereby grants Recipient a
#                   non-exclusive, worldwide, royalty-free patent
#                   license under Licensed Patents to make, use, sell,
#                   offer to sell, import and otherwise transfer the
#                   Contribution of such Contributor, if any, in source
#                   code and object code form. This patent license
#                   shall apply to the combination of the Contribution
#                   and the Program if, at the time the Contribution is
#                   added by the Contributor, such addition of the
#                   Contribution causes such combination to be covered
#                   by the Licensed Patents. The patent license shall
#                   not apply to any other combinations which include
#                   the Contribution. No hardware per se is licensed
#                   hereunder.
#
#                   c) Recipient understands that although each
##                   Contributor grants the licenses to its
#                   Contributions set forth herein, no assurances are
#                   provided by any Contributor that the Program does
#                   not infringe the patent or other intellectual
#                   property rights of any other entity. Each
#                   Contributor disclaims any liability to Recipient
#                   for claims brought by any other entity based on
#                   infringement of intellectual property rights or
#                   otherwise. As a condition to exercising the rights
#                   and licenses granted hereunder, each Recipient
#                   hereby assumes sole responsibility to secure any
#                   other intellectual property rights needed, if any.
#
#                   For example, if a third party patent license is
#                   required to allow Recipient to distribute the
#                   Program, it is Recipient's responsibility to
#                   acquire that license before distributing the
#                   Program.
#
#                   d) Each Contributor represents that to its
#                   knowledge it has sufficient copyright rights in its
#                   Contribution, if any, to grant the copyright
#                   license set forth in this Agreement.
#
#             3. REQUIREMENTS
#
#             A Contributor may choose to distribute the Program in
#             object code form under its own license agreement, provided
#             that:
#                   a) it complies with the terms and conditions of
#                   this Agreement; and
#
#                   b) its license agreement:
#                   i) effectively disclaims on behalf of all
#                   Contributors all warranties and conditions, express
#                   and implied, including warranties or conditions of
#                   title and non-infringement, and implied warranties
#                   or conditions of merchantability and fitness for a
#                   particular purpose;
#
#                   ii) effectively excludes on behalf of all
#                   Contributors all liability for damages, including
#                   direct, indirect, special, incidental and
#                   consequential damages, such as lost profits;
#
#                   iii) states that any provisions which differ from
#                   this Agreement are offered by that Contributor
#                   alone and not by any other party; and
#
#                   iv) states that source code for the Program is
#                   available from such Contributor, and informs
#                   licensees how to obtain it in a reasonable manner
#                   on or through a medium customarily used for
#                   software exchange.
#
#             When the Program is made available in source code form:
#                   a) it must be made available under this Agreement;
#                   and
#                   b) a copy of this Agreement must be included with
#                   each copy of the Program. 
#
#             Contributors may not remove or alter any copyright notices
#             contained within the Program.
#
#             Each Contributor must identify itself as the originator of
#             its Contribution, if any, in a manner that reasonably
#             allows subsequent Recipients to identify the originator of
#             the Contribution. 
#
#
#             4. COMMERCIAL DISTRIBUTION
#
#             Commercial distributors of software may accept certain
#             responsibilities with respect to end users, business
#             partners and the like. While this license is intended to
#             facilitate the commercial use of the Program, the
#             Contributor who includes the Program in a commercial
#             product offering should do so in a manner which does not
#             create potential liability for other Contributors.
#             Therefore, if a Contributor includes the Program in a
#             commercial product offering, such Contributor ("Commercial
#             Contributor") hereby agrees to defend and indemnify every
#             other Contributor ("Indemnified Contributor") against any
#             losses, damages and costs (collectively "Losses") arising
#             from claims, lawsuits and other legal actions brought by a
#             third party against the Indemnified Contributor to the
#             extent caused by the acts or omissions of such Commercial
#             Contributor in connection with its distribution of the
#             Program in a commercial product offering. The obligations
#             in this section do not apply to any claims or Losses
#             relating to any actual or alleged intellectual property
#             infringement. In order to qualify, an Indemnified
#             Contributor must: a) promptly notify the Commercial
#             Contributor in writing of such claim, and b) allow the
#             Commercial Contributor to control, and cooperate with the
#             Commercial Contributor in, the defense and any related
#             settlement negotiations. The Indemnified Contributor may
#             participate in any such claim at its own expense.
#
#
#             For example, a Contributor might include the Program in a
#             commercial product offering, Product X. That Contributor
#             is then a Commercial Contributor. If that Commercial
#             Contributor then makes performance claims, or offers
#             warranties related to Product X, those performance claims
#             and warranties are such Commercial Contributor's
#             responsibility alone. Under this section, the Commercial
#             Contributor would have to defend claims against the other
#             Contributors related to those performance claims and
#             warranties, and if a court requires any other Contributor
#             to pay any damages as a result, the Commercial Contributor
#             must pay those damages.
#
#
#             5. NO WARRANTY
#
#             EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, THE
#             PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
#             WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR
#             IMPLIED INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OR
#             CONDITIONS OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR
#             FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is solely
#             responsible for determining the appropriateness of using
#             and distributing the Program and assumes all risks
#             associated with its exercise of rights under this
#             Agreement, including but not limited to the risks and
#             costs of program errors, compliance with applicable laws,
#             damage to or loss of data, programs or equipment, and
#             unavailability or interruption of operations. 
#
#             6. DISCLAIMER OF LIABILITY
#             EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, NEITHER
#             RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY
#             FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
#             OR CONSEQUENTIAL DAMAGES (INCLUDING WITHOUT LIMITATION
#             LOST PROFITS), HOWEVER CAUSED AND ON ANY THEORY OF
#             LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#             (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
#             OF THE USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE
#             OF ANY RIGHTS GRANTED HEREUNDER, EVEN IF ADVISED OF THE
#             POSSIBILITY OF SUCH DAMAGES.
#
#             7. GENERAL
#
#             If any provision of this Agreement is invalid or
#             unenforceable under applicable law, it shall not affect
#             the validity or enforceability of the remainder of the
#             terms of this Agreement, and without further action by the
#             parties hereto, such provision shall be reformed to the
#             minimum extent necessary to make such provision valid and
#             enforceable.
#
#
#             If Recipient institutes patent litigation against a
#             Contributor with respect to a patent applicable to
#             software (including a cross-claim or counterclaim in a
#             lawsuit), then any patent licenses granted by that
#             Contributor to such Recipient under this Agreement shall
#             terminate as of the date such litigation is filed. In
#             addition, If Recipient institutes patent litigation
#             against any entity (including a cross-claim or
#             counterclaim in a lawsuit) alleging that the Program
#             itself (excluding combinations of the Program with other
#             software or hardware) infringes such Recipient's
#             patent(s), then such Recipient's rights granted under
#             Section 2(b) shall terminate as of the date such
#             litigation is filed.
#
#             All Recipient's rights under this Agreement shall
#             terminate if it fails to comply with any of the material
#             terms or conditions of this Agreement and does not cure
#             such failure in a reasonable period of time after becoming
#             aware of such noncompliance. If all Recipient's rights
#             under this Agreement terminate, Recipient agrees to cease
#             use and distribution of the Program as soon as reasonably
#             practicable. However, Recipient's obligations under this
#             Agreement and any licenses granted by Recipient relating
#             to the Program shall continue and survive. 
#
#             Everyone is permitted to copy and distribute copies of
#             this Agreement, but in order to avoid inconsistency the
#             Agreement is copyrighted and may only be modified in the
#             following manner. The Agreement Steward reserves the right
#             to publish new versions (including revisions) of this
#             Agreement from time to time. No one other than the
#             Agreement Steward has the right to modify this Agreement.
#
#             IBM is the initial Agreement Steward. IBM may assign the
#             responsibility to serve as the Agreement Steward to a
#             suitable separate entity. Each new version of the
#             Agreement will be given a distinguishing version number.
#             The Program (including Contributions) may always be
#             distributed subject to the version of the Agreement under
#             which it was received. In addition, after a new version of
#             the Agreement is published, Contributor may elect to
#             distribute the Program (including its Contributions) under
#             the new version. Except as expressly stated in Sections
#             2(a) and 2(b) above, Recipient receives no rights or
#             licenses to the intellectual property of any Contributor
#             under this Agreement, whether expressly, by implication,
#             estoppel or otherwise. All rights in the Program not
#             expressly granted under this Agreement are reserved.
#
#
#             This Agreement is governed by the laws of the State of New
#             York and the intellectual property laws of the United
#             States of America. No party to this Agreement will bring a
#             legal action under this Agreement more than one year after
#             the cause of action arose. Each party waives its rights to
#             a jury trial in any resulting litigation. 
#
#
#
#*/
#
#/* (C) COPYRIGHT International Business Machines Corp. 2001          */



# Get the operating System....  Everything else falls into that
OS = `uname -s`

# Get a list of crypto adapters and set error code to 0

if [ $OS -eq "AIX" ]
then
CARDS=`ODMDIR=/etc/objrepos /usr/sbin/lsdev -Cc adapter | /usr/bin/grep crypt | /usr/bin/cut -d " " -f1`
ERRORS=0
STATCOMMAND=/usr/lib/pkcs11/methods/4758_status
STDLLDIR=/usr/lib/pkcs11/stdll
METHDIR=/usr/lib/pkcs11/methods
CONFDIR=/etc/pkcs11
fi
if [ $OS -eq "Linux" ]
then
CARDS=`ls /dev/crypt* | sed s?\/dev\/??g`
ERRORS=0
STATCOMMAND=/usr/lib/pkcs11/methods/4758_status
STDLLDIR=/usr/lib/pkcs11/stdll
METHDIR=/usr/lib/pkcs11/methods
CONFDIR=/etc/pkcs11
CONFFILE=pk_config_data
rm $CONFDIR/$CONFFILE
fi


# For each card run the status command and if successful
# create the odm stanza for the file

if [ $OS -eq "AIX" ]
then
if [ -x $STATCOMMAND ]
then
for i in $CARDS
do
   $METHDIR/4758_status -c $i
   RC=$?
   if [ $RC -lt 100 ]
   then
      ERRORS=1
      MINOR=`echo $i | cut -f 2 -d "t"`
      ODMDIR=$CONFDIR/ /usr/bin/odmdelete -o ck_slot -q "Correlator = $MINOR"> /dev/null 2>&1
   elif [ $RC = 101 ]
     then
       $METHDIR/leeds_slot $i deep
   elif [ $RC = 102 ]
     then
       /usr/sbin/lsgroup pkcs11 > /dev/null 2>&1
       if [ $? -ne 0 ]
         then
	   /usr/bin/mkgroup pkcs11
       fi
       $METHDIR/leeds_slot $i shallow
   else
      exit -2
   fi
done
fi
else 
echo "Don't do deep for linux yet"
for i in $CARDS
do
    $METHDIR/4758_status -c $i
    RC=$?
    if [ $RC = 101 ]
    then
	$METHDIR/leeds_slot $i deep
    elif [ $RC = 102 ]
    then
	# SAB XXX Need to get the groups created elsewhere
	# actually we should build the correlator list here
	# and pass the list in all at once
	if [ $CORRLIST ]
	then
	    CORRLIST="${i}"
	else
	    CORRLIST="${CORRLIST},${i}"
	fi
	$METHDIR/leeds_slot $i shallow
    fi
done
fi  # AIX only for now


if [ $OS -eq "Linux" ]
then
    $METHDIR/leeds_slot  $CORRLIST shallow

fi


# SAB Now add the Soft token if it exists
#  For this we will always delete the SW tok from ODM and then
# add it if the file exists....

# SAB We need to delete the SW tok from the config file here XXX
if [ $OS -eq "AIX" ]
then
	   ODMDIR=$CONFDIR /usr/bin/odmdelete -o ck_slot -q "SlotDll = $STDLLDIR/PKCS11_SW.so" >/dev/null 2>&1
elif [ $OS -eq "Linux" ]
then
	# actually we don't need to do this since we regen the whole
	# file
	# remove the entry XXX FIXME
fi
	
if [[ -f $STDLLDIR/PKCS11_SW.so ]]
then
    $METHDIR/leeds_slot 0  soft
fi

if [[ -f $STDLLDIR/PKCS11_ICA.so ]]
then
    $METHDIR/leeds_slot 0  ica
fi

if [ $OS -eq "AIX" ]
then
# go through the slot database and remove entries for which there is no adapter
DEEP_SLOTS=`ODMDIR=$CONFDIR/ /usr/bin/odmget -q "SlotDll = $STDLLDIR/PKCS11_4758.so" ck_slot | grep Correlator | cut -f 3 -d " " | cut -f 2 -d "\""`
for J in $DEEP_SLOTS
do
   test -e "/dev/crypt$J"
   if [ $? -ne 0 ]
   then
      ODMDIR=$CONFDIR/ /usr/bin/odmdelete -o ck_slot -q "Correlator = $J"> /dev/null 2>&1
   fi
done

SHALLOW_COR=`ODMDIR=$CONFDIR/ /usr/bin/odmget -q "SlotDll = $STDLLDIR/PKCS11_LW.so" ck_slot | grep Correlator | cut -f 3 -d " " | cut -f 2 -d "\""`
SHALLOW_SLOTS=`echo $SHALLOW_COR | tr "," " "`

for K in $SHALLOW_SLOTS
do
   test -e "/dev/crypt$K"
   if [ $? -ne 0 ]
   then
      SHALLOW_NUM=`echo $SHALLOW_SLOTS | wc -w | awk '{ print $1 }'`

      # see if we are deleting the only one
      if [ $SHALLOW_NUM = 1 ]
      then
      # if so delete the stanza, otherwise use the odmchange command
        ODMDIR=$CONFDIR/ /usr/bin/odmdelete -o ck_slot -q "Correlator = $K"> /dev/null 2>&1
      else
      # there are more than one adapters only delete the corrlator for k
        # first delete the number and the preceding comma if present
	SHALLOW_COR=`echo $SHALLOW_COR | sed -e "s/,*$K//"`

	# the above command will cover all but the case where the deleted
	# element was first in the list.  If it was we now have a comma
	# at the beginning, if a comma start the line--delete it.
	SHALLOW_COR=`echo $SHALLOW_COR | sed -e "s/^,//"`

	# replace the current Correlator with the new one, since there is
	# only one LW entry this search will work fine.
	echo ck_slot: Correlator = \"$SHALLOW_COR\" | ODMDIR=$CONFDIR /usr/bin/odmchange -o ck_slot -q "SlotDll = $STDLLDIR/PKCS11_LW.so"
      fi
   fi
done
fi  # AIX only

# If any errors were encountered return -1 otherwise
# return 0

if [ $ERRORS -ne 0 ]
then
  exit -1
fi

exit 0
