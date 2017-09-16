12345678901234567890123456789012345678901234567890123456789012345678901234567890

Description of FrontEnd Application
-----------------------------------

This directory contains code for the FrontEnd (also called Entropy Collection)
application.  This program should be run at startup, and must be running before
any client calls to the prngcore DLL can be made.

This progam connects the hook DLL to the prng DLL, funnelling entropy data from
one to the other, and then into the entropy pool, which it controls. This program 
does not have a visible main window.  The only control the user has over it is via
the context menu attached to its notification area icon.


Files in Directory
------------------

frontend.h and frontend.c

Header and source for the application.


Routines
--------

WinMain(...)

The main functions called by the OS.  This (in order) sets up the PRNG, sets up
the system hooks, sets up the hook end of the MM file to pass entropy data, and
then sets up the local end of the MM file. It also creates the reseed thread.
It then starts the message pump. When close is selected from the context menu,
the reseed thread is terminated via an event. The program closes the hook end of
the MM file (which send a message to the local end to close as well), removes 
the system hooks, and destroys the PRNG.


Helper Routines
---------------

SetupLocalMMFile(LPVOID)

Sets up a thread to receive data from the memory-mapped file. The parameter is
a void pointer pointing to the location of the MM file, which will be passed to
the thread.

ListenToMMFile(LPVOID)

This is the thread set up above.  This thread waits on the dataReady event flag.
When the flag is signalled, it checks that the data sent to the MM file (pointed
to by the parameter) is not the break signal, then passes that data to another
worker thread (if available) to input the data into the pool. It then signals
the writeAllowed event flag and waits for more.  When it receives the break 
signal, it simply signals the writeAllowed flag (to indicate that it is exiting)
and terminates.

PassData(LPVOID)

This is the thread called by ListenToMMFile.  The parameter is a pointer to the
data that it will be passing to prngInputEntropy.  This thread exists mostly so
that the whole system will not block if prngInputEntropy is running slowly.  If
this thread is still running when another block of input data is sent to 
ListenToMMFile, that data will be discarded. 

ReseedThread(LPVOID)

This thread is created suspended by WinMain. It is controlled via the ReseedBox
dialog which is called from the context menu.  The user can set the interval
between reseeds (in minutes) and the length of the reseed (in ticks). This data is
stored in global variables.  The parameter is the handle to an event that is set
to indicate that the thread should return.  Suspension of the thread during a reseed
(which would be catastrophic) is prevented by a critical section.


To Do:
------
- This entire application is slated to become a kernel-level device driver in
the next version of this package.  The details of that are sketchy at this
moment.


The Icon
--------

The icon for this program is *not* the Counterpane Yarrow icon.  The official
icon has not yet been determined.  The icon is instead the muted trumpet from
the Crying of Lot 49 by Thomas Pynchon (ISBN 006091307X), an excellent novel 
with entropy as one of its central themes.

--------

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall 
{schneier,kelsey,hall}@counterpane.com.  

Thank you.

Ari