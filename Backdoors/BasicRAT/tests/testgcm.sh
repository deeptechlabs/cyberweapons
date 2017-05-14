#!/usr/bin/env bash

# creates 100 10MB files
# sends them
# then compares hashes
# no response means all 100 succeeded

for i in `seq 1 5`;
do
  echo -n "$i "
	head -c 10239 /dev/urandom > sendme
	python testgcm.py

  sent=$(md5 sendme | cut -d"=" -f2)
  recvd=$(md5 recvme | cut -d"=" -f2)

  if [[ "$sent" != "$recvd" ]]
  then
	  echo "Fail! $sent != $recvd"
	else
		echo "Pass!"
	fi
done;
