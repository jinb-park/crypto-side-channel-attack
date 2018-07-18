#!/bin/bash

rm -f plain.txt
touch plain.txt
echo $1 >> plain.txt

for (( c=1; c<=$1; c++ ))
do
	openssl rand -hex 16 >> plain.txt
done
