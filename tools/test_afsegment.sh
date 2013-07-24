#!/bin/sh
# Test the afsegment command

# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012

export PATH=$srcdir:../tools:../../tools:.:$PATH
BLANK_BASE=`mktemp -t blankXXXXX`
BLANK_RAW=$BLANK_BASE.raw
BLANK_AFF=$BLANK_BASE.aff
unset AFFLIB_PASSPHRASE

echo === Putting a new metadata segment into blank.aff  ===

/bin/rm -f $BLANK_AFF

cp /dev/null $BLANK_RAW
affcopy $BLANK_RAW $BLANK_AFF
affsegment -ssegname=testseg1 $BLANK_AFF
if [ x"testseg1" = x`affsegment -p segname $BLANK_AFF` ] ; then 
  echo affsegment worked!
else
  echo affsegment does not work properly
  exit 1
fi
/bin/rm -f $BLANK_RAW $BLANK_AFF

