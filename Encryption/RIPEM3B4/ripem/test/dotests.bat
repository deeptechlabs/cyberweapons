@echo off
rem Perform tests on RIPEM for correctness 
call testd
if exist pubkeys del pubkeys
call testgen
cl show.c
show <pubkeys >pubkeys.beg 1-3
echo = Comparing generated key to expected key.  If you see
echo = differences output by the FC command, there may be problems.
fc pubkeys.beg pubkeys.exp

