@echo off
echo Testing RIPEM signing.
..\main\ripem -e -m mic-clear -p test1.pub -s test1.prv -k test1pw -u test -i signin.txt -o signout.txt -h pr -R c -C c
echo If fc reports differences below, you may have problems.
fc signout2.txt signout.txt
echo .
echo Testing RIPEM signature verification.
echo == Look for "Signature status: VALID." below.
..\main\ripem -d -p test1.pub -s test1.prv -k test1pw -u test -i signed.txt  

