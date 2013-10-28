#!/bin/sh
# 
# test the PKI sealing tools

# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012

BASE=`mktemp -t testfileXXXX`
SEALING_KEY=$BASE.sealing.key
SEALING_PEM=$BASE.sealing.pem
EVIDENCE_ISO=$BASE.evidence.raw
EVIDENCE_AFF=$BASE.evidence.aff

/bin/rm -f $SEALING_KEY $SEALING_PEM $EVIDENCE_ISO $EVIDENCE_AFF
unset AFFLIB_PASSPHRASE
unset AFFLIB_DECRYPTING_PRIVATE_KEYFILE

echo === MAKING THE TEST FILES ===

export PATH=$srcdir:../tools:../../tools:.:$PATH
test_make_random_iso.sh $EVIDENCE_ISO

echo Making X.509 key

openssl req -x509 -newkey rsa:1024 -keyout $SEALING_KEY -out $SEALING_PEM -nodes -subj "/C=US/ST=California/L=Remote/O=Country Govt./OU=Sherif Dept/CN=Mr. Agent/emailAddress=agent@investiations.com"

# One way to do this should be to set an environment variable and do an affcopy
# Another way should be to make the AFF file and then encrypt it with affcrypto.

# Make the aff file and encrypt it with affcrypto
if ! affconvert $EVIDENCE_ISO ; then exit 1 ; fi
if ! affcrypto -e -C $SEALING_PEM $EVIDENCE_AFF ; then exit 1 ; fi

# Make sure we can't read it without specifying a keyfile
echo This should generate an error:
if affcompare $EVIDENCE_ISO $EVIDENCE_AFF ; then
  echo ERROR - could read encrypted file without decryption key.
  exit 1
fi
echo Could not read encrypted file without setting decryption key --- CORRECT BEHAVIOR

echo Now set the AFFLIB_DECRYPTING_PRIVATE_KEYFILE and see if we can 
echo read the file...
export AFFLIB_DECRYPTING_PRIVATE_KEYFILE=$SEALING_KEY
# Make sure we can't read it without specifying a keyfile
if ! affcompare $EVIDENCE_ISO $EVIDENCE_AFF ;  then
  echo ERROR - could not read encrypted once decryption key was set.
  exit 1
fi
echo Could read encrypted file once decryption key was sety --- CORRECT BEHAVIOR

#Add passphrase to aff file encrypted with $SEALING_PEM
echo Now attempting to add a passphrase  to the aff file that was encrypted for a private key.

if ! affcrypto -S -K $SEALING_KEY -N mypassword $EVIDENCE_AFF ; then
  echo ERROR - could not add passphrase.
  exit 1
fi
echo Successfully added passphrase to aff file -- CORRECT BEHAVIOR

#Make sure we cannot read the file with a wrong passphrase

echo Verify that password was added to aff file.  Should read passphrase correct.
affcrypto -p mypassword $EVIDENCE_AFF



echo Recreating AFFILE to remove encryption
rm -f $EVIDENCE_AFF
if ! affconvert $EVIDENCE_ISO ; then exit 1 ; fi
unset AFFLIB_DECRYPTING_PRIVATE_KEYFILE

echo encrypting AFFILE with passphrase
if ! affcrypto -e -N mypassword $EVIDENCE_AFF ; then
    echo ERROR - could not encrypt with passphrase.
    exit 1
fi

echo Adding public key encryption to AFFILE encrypted with passphrase
if ! affcrypto -A -p mypassword -C $SEALING_PEM $EVIDENCE_AFF ; then
    echo ERROR - could not add public key 
fi

# Same tests as above now done to test the encryption 
#    addition that was done in reverse
# Make sure we can't read it without specifying a keyfile
echo This should generate an error:
if affcompare $EVIDENCE_ISO $EVIDENCE_AFF ; then
  echo ERROR - could read encrypted file without decryption key.
  exit 1
fi
echo Could not read encrypted file without setting decryption key --- CORRECT BEHAVIOR

echo Now set the AFFLIB_DECRYPTING_PRIVATE_KEYFILE and see if we can 
echo read the file...
export AFFLIB_DECRYPTING_PRIVATE_KEYFILE=$SEALING_KEY
# Make sure we can't read it without specifying a keyfile
if ! affcompare $EVIDENCE_ISO $EVIDENCE_AFF ;  then
  echo ERROR - could not read encrypted once decryption key was set.
  exit 1
fi
echo Could read encrypted file once decryption key was sety --- CORRECT BEHAVIOR

if test "x"$1 = "x--keep" ; then
  echo will not erase $EVIDENCE_ISO $EVIDENCE_AFF $SEALING_KEY $SEALING_PEM
else
  echo Erasing temporary files.
  rm -f $EVIDENCE_ISO $EVIDENCE_AFF $SEALING_KEY $SEALING_PEM
fi

echo $0 completed successfully.

exit 0

