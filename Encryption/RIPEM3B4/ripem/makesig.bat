rem Batch file to compile RIPEM/SIG vanilla DOS version w/ MS C 7.0
rem Run this from the RIPEM directory.
cd rsaref\test
nmake -f rsaref.mak
if errorlevel 1 goto err
cd ..\..\main
nmake -f ripemsig.mak
if errorlevel 1 goto err
cd ..\test
call testsig
goto done
:err
echo *** Unsuccessful build of RIPEM!
:done
