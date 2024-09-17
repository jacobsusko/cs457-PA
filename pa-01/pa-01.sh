#-----------------------------------------------------
#Written By : Sydney Nguyen and Jacob Susko
#Submitted on:
#-----------------------------------------------------

#!/bin/bash
echo "Script to run Programming Assignment #1"
echo "By Jacob Susko and Sydney Nguyen"

# remove old executables + key/IV and symbolic link to the ../bunny.mp4 files 
rm -f bunny.mp4
rm -f genkey amal/amal basim/basim dispatcher
rm -f key.bin iv.bin
rm -f amal/key.bin basim/key.bin amal/iv.bin basim/iv.bin

# create symbolic link to ../bunny.mp4 file 
ln -s ../bunny.mp4 bunny.mp4

# build all executables (genKey, amal/amal, basim/basim, dispatcher) 
# the myCrypto.c file mus tbe linekd with each of the Amal and Basim executables
# wrappers.c file must be linked with dispacther.c executable program
echo "======================================"
echo "Compiling all source code"

gcc -o genkey genkey.c -lcrypto
gcc amal/amal.c myCrypto.c   -o amal/amal -lcrypto
gcc basim/basim.c myCrypto.c -o basim/basim -lcrypto
gcc  dispatcher.c wrappers.c -o dispatcher -lcrypto
echo
# runs genKey executable + hexdump the key and the IV that were just generated
./genkey
echo "This is the symmetric Key material:"
hexdump -C key.bin
echo
echo "This is the IV material:"
hexdump -C iv.bin
echo

# create synbolic links inside both the pa-01/amal + pa-01/basim folders to 
# point to the actual key.bin and iv.bin  located in the parent pa-01 folder
echo "Sharing the key and IV with Amal and Basim using symboic links"
ln -s ../key.bin amal/key.bin
ln -s ../iv.bin amal/iv.bin
ln -s ../key.bin basim/key.bin
ln -s ../iv.bin basim/iv.bin

# start dispatcher process, which will then fork the amal and basim processes
# This means that when Amal and Basim executables are running, their current 
# directory is the pa-01 folder
echo "Starting the dispatcher"
echo "=============================="
./dispatcher
echo
echo "=============================="
echo "The Dispatcher process has terminated"

# Display the log files of each process
echo "========== Alam's Log ============"
cat amal/logAmal.txt

echo "========== Basim's Log============"
cat basim/logBasim.txt

echo
echo "=================================="
echo "Verifying File Encryption / Decryption"

# finally uses the diff -s command to compare the original bunny.mp4 vs bunny.decr files 
diff -s bunny.mp4 bunny.decr