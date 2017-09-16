12345678901234567890123456789012345678901234567890123456789012345678901234567890

Description of TestApp Application
-----------------------------------

This directory contains code for TestApp, a very simple application that
demonstrates the minimum setup required to connect to the entropy pool once it
has been set up by FrontEnd.

Files in Directory
------------------

testapp.c

Source for the application.


Routines
--------

WinMain(...)

The main functions called by the OS.  This function just runs through each of
the prng routines in a somewhat random order and then returns.  This is mostly
designed as testing code and should be stepped through.


To Do:
------
- This code should have much better error checking.

--------

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall 
{schneier,kelsey,hall}@counterpane.com.  

Thank you.

Ari