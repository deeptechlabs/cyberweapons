12345678901234567890123456789012345678901234567890123456789012345678901234567890

Description of Entropyhooks Library
-----------------------------------

This directory contains code for a DLL containing all the necesary functions to 
collect and store timing data from the mouse and the keyboard.  The data is 
written out via a memory-mapped file and controlled by a pair of event flags.

A major programming issue in the DLL is that it will be called by a variety of
different processes, which means that handles and memory locations cannot be
stored as such.  This DLL will make a duplicate of its handles for each process
that attaches (and close them when the process detaches).  Memory allocation
is handled via smf.dll, which takes care of mapping the pages into each process'
space.

Files in Directory
------------------

hooks.c,hooks.h and hookspriv.h

The source code, public and private header files for the entropy collection DLL.
Note that this library must be a DLL to achieve the proper functionality for the 
collection routines.

entropysources.h

Header file that contains the structure enumerating the entropy sources.  This 
file should be included in any code that will be calling prngInputEntropy.

DLL Routines
------------

All major routines return the success/error value for their operation.
See hooks.h for the enumeration.

SetHooks(void)

Sets up the keyboard and mouse tracking routines. Allocates memory and sets up a
mutex to protect the hook routines. Should be called only once by the 
application controlling the entropy pool.

SetupMMComm(pComm,pDataReady,pWriteAllowed)

Sets up a memory-mapped communication block for transfer of information. Sets up
two event flags to control the block and returns them in pDataReady and 
pWriteAllowed. Returns the memory location in pComm.  This routine can only be 
called by the process that called SetHooks.

CloseMMComm(void)

Gains control of the mutex protecting the hooks routines and destroys it. Sends 
a break message across the communication block. Cleans up. This routine can 
only be called by the process that called SetHooks.

RemoveHooks(void)

Removes the keyboard and mouse tracking routines from the system. Cleans up the
memory. This routine can only be called by the process that called SetHooks.

Helper Routines
---------------

KeyboardHook
MouseHook

Callback routines that are called each time a keyboard or mouse event takes 
place. They are run in the space of the process that received the event. These 
routines check the reason for the event and then store data about it if 
appropriate. Access to the data collection/storage code is controlled by a 
mutex. Also, a process running a hook routine sets a flag to indicate this, so 
it does not deadlock on itself (don't ask me, that's just what happens) if it 
gets another input while processing the previous one.

WriteMouseTime
WriteMouseMove
WriteKeyTime

Helper routines to write out data when the buffers are full. They all call 
WriteData which does the actual writing to the communication file.

WriteData

Writes data to the communication file. Waits for the WriteAllowed event to be 
signalled before writting and signals the DataReady event when it is done.

SetupCounter

Tests the system to determine what sort of counter it has and sets a few 
variables based on what it finds.

CompressData

A small helper routine that removes the predictable zeroes from the mousetime
and keytime arrays. i.e. if only one byte of data is being stored per entry
in said arrays (timemask = 0x000000FF) instead of a full word, this function
will throw out the high byte of each word to accomodate for that.


To Do:
------
- It may be worthwhile to optimize the hook routines for speed (assembly?).
- Bugs to check for: Do the hook routines always run (do applications seem
to be stealing the data before we can)? Are the mutexes and events secure?
Are deadlocks/thread conflicts occuring?

--------

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall 
{schneier,kelsey,hall}@counterpane.com.  

Thank you.

Ari