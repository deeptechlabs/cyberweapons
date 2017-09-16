@echo off
echo Decryption tests--should be fairly fast.
call testd
call testdede
echo Encryption test--file comparison should yield no differences.
call teste
fc message2.enc teste.enc
echo Key generation test--can be rather slow.
call testg
echo Differences below probably mean problems.
fc test1.prv privkey
