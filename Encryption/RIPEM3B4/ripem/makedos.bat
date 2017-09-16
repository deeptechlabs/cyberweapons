rem Batch file to compile RIPEM vanilla DOS version w/ MS C
rem Run this from the RIPEM directory.
cd rsaref\install
nmake -f rsaref.mak
if errorlevel 1 goto err
cd ..\..\main
nmake -f ripemmai.mak
if errorlevel 1 goto err
cd ..\cmdline
nmake -f ripem.mak
if errorlevel 1 goto err
call makerc
cd ..\test
call dostest
goto done
:err
cd ..
echo *** Unsuccessful build of RIPEM!
:done
