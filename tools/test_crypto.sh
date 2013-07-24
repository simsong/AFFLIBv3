#!/bin/sh
# 
# test to make sure that the encrypted aff that is distributed with
# the AFFLIB can be decrypted using a known passphrase.
#
# This file is a work of a US government employee and as such is in the Public domain.
# Simson L. Garfinkel, March 12, 2012

unset AFFLIB_PASSPHRASE
export PATH=$srcdir:../tools:../../tools:.:$PATH

BASE=`mktemp -t encryptedXXXXXX`
ENCRYPTED_AFF=$BASE.aff
ENCRYPTED_AFD=$BASE.afd
PLAINTEXT_ISO=$BASE.raw

echo Making encrypted AFF from stored value

openssl base64 -d > $ENCRYPTED_AFF <<EOF
QUZGMTANCgBBRkYAAAAABwAAAgAAAAAAYmFkZmxhZ0JBRCBTRUNUT1IAQwRKkA4whVoweN599xo5
vqbYfLdYMdk2LnCdr+RCsR2fpKER5NHqWK0HjZ2aWm1pLSrV+FVyjO6iZRmD/oQ2EeME+gfZChM6
6HYobG44YeW5aExzF53XWQ8CcLMfCl2C70sefisTUJXm+ldEyaUp2anrFMYb1TMDe6SpZKE4fG0J
qrUVRk3TpvsfX5x1bExUGPbxmeRC66ueFP3e0N1v6hL61HWnYJ02EbhvGtuISNA3xMTWVLfjKrE2
9NdpKKBqdL6V9PTR+g6lIN/XKeV+dKixP3DFULiCLoLIF9spIn0FVQvWTHaAbCVVWzEVBlLK/5u6
wh3qevx03yYeKGJnGWHTLAJYrzXBe1rcjK0KWphN9vF37/+o8bNFyUm7/o5iqif+bLGU4sFdrRcx
R/7uGFkx6fa5ZqjUWgNyom0w8UnuXBUtKJAd/EPPcN+/+/cAkOR+ci46bOswwI1kL7yMn6sJnZA0
nBGgLnmRVCYhbwHCoY5XzJp6DUmfEQP++dXdKfSXcKMsi9sqa43rH/bXz4lCUh+l+BqiR8hps3i1
37Ir0wpI9Emye4sqIq6hLdzXreWMeO0d1ag+RwU9L9byjEPfBGiH5lFkqBzD+AUvtOeUWPmducwe
CThvm7jU1NYKgQ7lplX1XhOb/qCVx8/our86b+LsQVRUAAAAAh9BRkYAAAAACgAAAAgAAAACYmFk
c2VjdG9ycwAAAAAAAAAAQVRUAAAAACpBRkYAAAAADgAAAAkAAAAAYWZmbGliX3ZlcnNpb24iMy4w
LjBhNiJBVFQAAAAAL0FGRgAAAAANAAAAAwAAAABhZmZfZmlsZV90eXBlQUZGQVRUAAAAAChBRkYA
AAAADQAAADgAAAAAYWZma2V5X2FlczI1NgAAAAEoymitfh6PClmv5NuhF2G9CogbB4AlMBwMIK92
u2zaLlLpWPiaWURRi/h3ptg0u6AAAAAAQVRUAAAAAF1BRkYAAAAADwAAAAABAAAAcGFnZXNpemUv
YWVzMjU2QVRUAAAAACdBRkYAAAAADAAAACAAAAAAcGFnZTAvYWVzMjU2JY1RIwMyLqCQDSS3t1gC
uydwNotCzenReTJdzn7fdMlBVFQAAAAARA==
EOF

echo Making encrypted AFD
mkdir $ENCRYPTED_AFD
cp $ENCRYPTED_AFF $ENCRYPTED_AFD/file_000.aff

echo Making plaintext ISO
openssl base64 -d > $PLAINTEXT_ISO <<EOF
QUZGIGRlY3J5cHRpb24gYXBwZWFycyB0byB3b3JrLgo=
EOF

echo TESTING WITH PASSPHRASE IN ENVIRONMENT VARIABLE
export AFFLIB_PASSPHRASE=password
if ! affcompare $ENCRYPTED_AFF $PLAINTEXT_ISO  ; 
then 
    echo $ENCRYPTED_AFF does not decrypt properly.
    exit 1 
fi

if ! affcompare $ENCRYPTED_AFD $PLAINTEXT_ISO  ; 
then 
    echo $ENCRYPTED_AFD does not decrypt properly.
    exit 1 
fi

echo TESTING DECRYPTION WITH URL
unset AFFLIB_PASSPHRASE

if ! affcompare file://:password@/$ENCRYPTED_AFF $PLAINTEXT_ISO  ; 
then 
    echo $ENCRYPTED_AFF does not decrypt properly.
    exit 1 
fi

if ! affcompare file://:password@/$ENCRYPTED_AFD $PLAINTEXT_ISO  ; 
then 
    echo $ENCRYPTED_AFF does not decrypt properly.
    exit 1 
fi


# file://:password@/$ENCRYPTED_AFF 

# /bin/rm -f $PLAINTEXT_ISO $ENCRYPTED_AFF
exit 0
