rem Makefile for RIPEM for Win32 using Microsoft Visual C++
@echo off
rem Mark Riordan 20 Sept 1997
pushd rsaref\install
echo = Making RSAREF
nmake -f rsarefnt.mak
cd ..\..\main
echo = Making RIPEM library
nmake -f mainnt.mak
cd ..\cmdline
echo = Making RIPEM executable
nmake -f ripemnt.mak
echo = Making RCERTS executable
nmake -f rcertsnt.mak
copy Release\ripemnt.exe ripem.exe
copy rcertsnt\rcertsnt.exe rcerts.exe
echo = Performing tests
cd ..\test
call dotests

