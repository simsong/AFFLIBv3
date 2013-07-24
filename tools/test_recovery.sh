#!/bin/sh
# 
# test the signing tools
#
# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012

export PATH=$srcdir:../tools:../../tools:.:$PATH

RECOVERY_BASE=`mktemp -t recoveryXXXX`
RECOVERY_KEY=$RECOVERY_BASE.key
RECOVERY_BAK=$RECOVERY_BASE.bak
RECOVERY_ISO=$RECOVERY_BASE.raw
RECOVERY_AFM=$RECOVERY_BASE.afm
RECOVERY_PEM=$RECOVERY_BASE.pem

/bin/rm -f $RECOVERY_KEY $RECOVERY_BAK $RECOVERY_ISO $RECOVERY_AFM

unset AFFLIB_PASSPHRASE

test_make_random_iso.sh $RECOVERY_ISO

echo ==== AFRECOVERY TEST ===
echo Make an X509 key

SUBJECT="/CN=Mr. Recovery/emailAddress=recovery@investiations.com"
openssl req -x509 -newkey rsa:1024 -keyout $RECOVERY_PEM -out $RECOVERY_PEM -nodes -subj "$SUBJECT"


if [ ! -r $RECOVERY_ISO ]; then
   echo $RECOVERY_ISO was not created.
   printenv
   echo current directory: `pwd`
   exit 0
fi


cp $RECOVERY_ISO $RECOVERY_BAK
echo ===========
echo Step 1: SIGNING $RECOVERY_ISO 
if ! affsign -k $RECOVERY_PEM $RECOVERY_ISO ; then exit 1 ; fi
ls -l $RECOVERY_ISO $RECOVERY_AFM
echo ===========
echo Step 2: VERIFYING SIGNATURE
if ! affverify $RECOVERY_AFM ; then exit 1 ; fi
echo ===========
echo Step 3: CORRUPTING FILE recovery.raw
dd if=/dev/random of=$RECOVERY_ISO count=1 skip=1 conv=notrunc
echo ===========
echo Step 4: ATTEMPTING RECOVERY
if ! affrecover $RECOVERY_AFM ; then exit 1 ; fi
echo ==========
echo Step 5: MAKING SURE THAT THE MD5 HAS NOT CHANGED
if ! cmp $RECOVERY_BAK $RECOVERY_ISO ; then echo file changed ; exit 1 ; fi
echo MD5 has not changed
echo ==========
echo Step 6: See if Digital Signature is still good
if ! affverify $RECOVERY_AFM ; then echo signature no longer good ; exit 1 ; fi
echo Signature still good
echo ALL TESTS PASS
/bin/rm -f $RECOVERY_KEY $RECOVERY_BAK $RECOVERY_ISO $RECOVERY_AFM $RECOVERY_PEM
