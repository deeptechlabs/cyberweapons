rem Batch file to compile RIPEM vanilla DOS version w/ Turbo C++ 2.0
rem Run this from the RIPEM directory.
cd rsaref\test
make  -frsaref.tma  >makerr
c:\e3\e3 makerr rsaref.tma
cd ..\..\main
make -K -fripem.tma   >makerr
c:\e3\e3 makerr ripem.tma
cd \ripem
goto exit
cd ..\test
copy ..\main\ripem.exe
testd
:exit
