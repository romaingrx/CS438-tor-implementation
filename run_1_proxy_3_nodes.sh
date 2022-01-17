#!/bin/bash

cd ourgui

NUM_RELAYS=$1
NUM_PROXIES=$2
NUM_MESSAGES=$3
NUM_PARALLEL=$4

BEGIN_PORT=3000

# Create Directory file
TOTAL=$((NUM_RELAYS+NUM_PROXIES))
CURRENT_PORT=$BEGIN_PORT 
> directory.txt 

for (( r=1; r<=$TOTAL; r++ ))
do 
    echo 127.0.0.1:$CURRENT_PORT >> directory.txt 
    CURRENT_PORT=$((CURRENT_PORT+1))
done 

#Run Relays
CURRENT_PORT=$BEGIN_PORT #Reset Current port
for (( r=1; r<=$NUM_RELAYS; r++ ))
do 

go run mod.go start --nodeaddr 127.0.0.1:$CURRENT_PORT --directoryfilename directory.txt > ../logs/$CURRENT_PORT.log &
CURRENT_PORT=$((CURRENT_PORT+1))

done

#Run Proxies
for (( r=1; r<=$NUM_PROXIES; r++ ))
do

go run mod.go start --nodeaddr 127.0.0.1:$CURRENT_PORT --directoryfilename directory.txt --messages $NUM_MESSAGES --parallel $NUM_PARALLEL --proxy > ../logs/$CURRENT_PORT.log &
CURRENT_PORT=$((CURRENT_PORT+1))

done

sleep 60000


