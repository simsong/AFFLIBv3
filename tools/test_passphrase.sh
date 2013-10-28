#!/bin/sh
#
# test the passphrase tools

# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012
export PATH=$srcdir:../tools:../../tools:.:$PATH

echo === testing `affcrypto -V` ===
echo === MAKING THE TEST FILES ==
unset AFFLIB_PASSPHRASE

BLANK_BASE=`mktemp -t blankXXXXX`
BLANK_AFF=$BLANK_BASE.aff
BLANK_ISO=$BLANK_BASE.raw
BLANK_ENCRYPTED_AFF=${BLANK_BASE}_encrypted.aff
WORDS=`mktemp -t wordsXXXX`

rm -f $BLANK_ISO $BLANK_AFF $BLANK_ENCRYPTED_AFF $WORDS
test_make_random_iso.sh $BLANK_ISO || (echo Cannot run test_make_random_iso.sh && exit -1)

if [ ! -r $BLANK_ISO ]; then
  echo CANNOT CREATE $BLANK_ISO
  echo Permission error prevents test from continuing. 
  exit 0
fi

affconvert -o $BLANK_AFF $BLANK_ISO || exit 1
affconvert -o file://:passphrase@/$BLANK_ENCRYPTED_AFF $BLANK_ISO || exit 1

if [ ! -r $BLANK_ENCRYPTED_AFF ]; then
  echo CANNOT CREATE $BLANK_ENCRYPTED_AFF 
  echo Permission error prevents test from continuing. 
  exit 0
fi


# Make sure affcrypto reports properly for with and with no encrypted segments
if (affcrypto $BLANK_AFF | grep " 0 encrypted" > /dev/null ) ; then 
  echo $BLANK_ENCRYPTED_AFF properly created
else  
   echo ENCRYPTED SEGMENTS IN $BLANK_ENCRYPTED_AFF --- STOP
   exit 1 
fi 

# Now test affcrypto
echo Encrypted segment count: `affcrypto -j $BLANK_ENCRYPTED_AFF`
if [ `affcrypto -j $BLANK_ENCRYPTED_AFF` = "0" ]; then 
  echo NO ENCRYPTED SEGMENTS IN $BLANK_ENCRYPTED_AFF --- STOP
  exit 1 
else
  echo $BLANK_ENCRYPTED_AFF properly created
fi

echo "sleepy" > $WORDS
echo "dopey" >> $WORDS
echo "doc" >> $WORDS
echo "passphrase" >> $WORDS
echo "foobar" >> $WORDS
if [ "`affcrypto -k -f $WORDS $BLANK_ENCRYPTED_AFF|grep correct|grep passphrase`"x = x ] ; then
  echo affcrypto did not find the right passphrase
  exit 1
else 
   echo affcrypto found the correct pasphrase 
fi

rm $BLANK_ISO $BLANK_AFF $BLANK_ENCRYPTED_AFF $WORDS

echo ALL TESTS PASS
exit 0
