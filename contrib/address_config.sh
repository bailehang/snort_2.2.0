#!/bin/sh
# address_config.sh -v0.2
# Handy script for laptop users that change their
# IP address frequently. This automates the
# process of updating your Snort rules file.
# You might find his litle script can be usefull, enjoy...
# Sten Kalenda Apeldoorn The Netherlands
# ------------------ MODIFY HERE ---------------------------------------
IF0=eth0
MASK="24"
SNORTDIR="/usr/local/bin"
SNORTLIBDIR="$SNORTDIR/snortlib"
SNORTLOGDIR="/var/log/snort"
# ------------------ DO NOT CHANGE BELOW -------------------------------
if [ ! -d "$SNORTLIBDIR" ] ; then
   echo Directory $SNORTLIBDIR not found
   exit
fi
cd $SNORTLIBDIR
if [ ! -e "$SNORTLOGDIR" ] ; then
   mkdir $SNORTLOGDIR
   chmod 700 $SNORTLOGDIR
fi
MYIP=`/sbin/ifconfig $IF0|sed -n -e "s/^[ ]*inet addr\:\([0-9.]*\).*$/\1/p"`
CHG=s\/10\.1\.1\.0\\/24/$MYIP\\/$MASK/g
cat snort-lib | sed $CHG > snort-lib_run

$SNORTDIR/snort -D -A fast -c $SNORTLIBDIR/snort-lib_run

