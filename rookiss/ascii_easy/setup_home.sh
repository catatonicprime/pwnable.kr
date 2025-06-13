#!/usr/bin/bash

if [ ! -d /home/ascii_easy ]
then
  mkdir /home/ascii_easy
fi
if [ ! -f /home/ascii_easy/libc-2.15.so ]
then
  ln -s $(pwd)/libc-2.15.so /home/ascii_easy/
fi
