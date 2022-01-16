#!/bin/bash

cd ourgui

go run mod.go start --nodeaddr 127.0.0.1:3000 --directoryfilename directory.txt --proxy > ../logs/3000.log &
go run mod.go start --nodeaddr 127.0.0.1:3001 --directoryfilename directory.txt > ../logs/3001.log &
go run mod.go start --nodeaddr 127.0.0.1:3002 --directoryfilename directory.txt > ../logs/3002.log &
go run mod.go start --nodeaddr 127.0.0.1:3003 --directoryfilename directory.txt > ../logs/3003.log &

sleep 20

for pid in $(netstat -tulpn | grep -Po '[0-9]*(?=\/mod)')
do
    kill -s 9 ${pid}
done
