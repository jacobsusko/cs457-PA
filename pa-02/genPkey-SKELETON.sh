#!/bin/bash

# "Script to Generate RSA Public/Private key Pair"

# "Written By:  1- MUST WRITE YOUR NAME(s) HERE ( OR LOSE SOME POINTS )

echo
echo

# Generate  2048-bit public/private key-pair for Amal
cd amal
rm -f *.pem 
openssl genpkey      .... missing stuff goes here
openssl rsa     -in  .... missing stuff goes here

echo "====================================="
echo "Here is Amal's RSA Key Information"
echo "====================================="
openssl  .... missing stuff goes here
echo
echo "====================================="

# Now, share Amal's public key with Basim using Linux Symbolic Links
cd ../basim
rm -f *.pem
ln -s  ../amal/amal_pub_key.pem  amal_pubKey.pem

#back to dispatcher's folder
cd ..
