@echo off
bcc -ml -O2 -w dlock2.cpp crc.cpp diamond2.cpp
pklite dlock2.exe
del crc.obj
del diamond2.obj
del dlock2.obj
