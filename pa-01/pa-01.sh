#-----------------------------------------------------
#Written By : Sydney Nguyen 
#Submitted on:
#-----------------------------------------------------

#!/bin/bash

# remove old executables + key/IV and symbolic link to the ../bunny.mp4 files 
rm -f bunny.mp4
rm -f genKey amal/amal basim/basim dispatcher
rm -f key.bin iv.bin
rm -f amal/key.bin basim/key.bin amal/ iv.bin basim/ iv.bin

# create symbolic link to ../bunny.mp4 file 
ln -s ../bunny.mp4 bunny.mp4

# build all executables (genKey, amal/amal, basim/basim, dispatcher) 
# the myCrypto.c file mus tbe linekd with each of the Amal and Basim executables
# wrappers.c file must be linked with dispacther.c executable program 
gcc -o genKey genKey.c
gcc -o amal/amal amal/amal.c myCrypto.c
gcc -o basim/basim basim/basim.c myCrypto.c
gcc -o dispatcher dispatcher.c wrappers.c

# runs genKey executable + hexdump the key and the IV that were just generated
./genKey
hexdump -C key.bin
hexdump -C iv.bin

# create synbolic links inside both the pa-01/amal + pa-01/basim folders to 
# point to the actual key.bin and iv.bin  located in the parent pa-01 folder
ln -s ../key.bin amal/key.bin
ln -s ../iv.bin amal/iv.bin
ln -s ../key.bin basim/key.bin
ln -s ../iv.bin basim/iv.bin

# start dispatcher process, which will then fork the amal and basim processes
# This means that when Amal and Basim executables are running, their current 
# directory is the pa-01 folder
./dispatcher

# Display the log files of each process
echo " Displaying Amal log:"
cat amal/amal.log

echo "DIsplaying Basim log:"
cat basim/bism.log

echo "Displaying Dispatcher log:"
cat dispatcher.log

# finally uses the diff -s command to compare the original bunny.mp4 vs bunny.decr files 
diff -s bunny.mp4 bunny.decr