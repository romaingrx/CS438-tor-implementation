#!/bin/bash


for pid in $(netstat -tulpn | grep -Po '[0-9]*(?=\/mod)')
do
    kill -s 9 ${pid}
done