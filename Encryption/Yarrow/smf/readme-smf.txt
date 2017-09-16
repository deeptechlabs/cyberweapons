12345678901234567890123456789012345678901234567890123456789012345678901234567890

Description of Smf Library
-----------------------------------

This directory contains code for a DLL containing all the necesary functions for
secure memory allocation and deletion.  This library is new and will require
some serious testing. It is theoretically secure based on Gutmann 1996 paper on
the topic (see Usenix 1996).

The general idea is that one cannot stop Win32 from potentially storing your data
in RAM to disk, at which point you will never find it again from inside your
application but an attacker may be able to find it by combing the system paging
file.  This problem is alleviated by having the data mostly stored on disk (in
a known location) via a memory-mapped file.  A pointer is provided, which, for
all intents and purposes, can be treated as any another. However, since the data
will only be written to disk in a known location, we can simply overwrite that
location with the appropriate sequence of data to make recovery enormously
difficult.

To use the DLL routines, you need only include smf.h in the calling 
application and make sure that the DLL is in an 
accessible location (usually C:\windows\system).

This DLL was created to solve the problem that results from dynamic memory
allocation in a(nother) DLL that will be called by multiple processes. Since each
process in Win32 has its own 32 bit virtual memory space, normal pointers cannot 
be shared. This library provides a solution to that problem. Memory is allocated 
and freed as normal through a single process, but all other processes can also access
that memory by knowing its pseudo-pointer value and calling the DLL to get a valid
pointer to the same data. This will make a bit more sense after the routines 
described below are reviewed.

Files in Directory
------------------

smf.c, smf.h, smfpriv.h

The source code, public and private header files for the secure memory DLL.

Data Structures
---------------

Data needed by (and therefore accessible to) all processes is stored in a
structure with the following members:

OrgId

The Id of the process that created this entry.

hand

The handle of the memory-mapped file relative to that process.

count

The number of processes that have mapped this block into their space.

size

Number of bytes allocated to the file.


An array of these structures is the main data storage for the DLL.

Also, each process calling the DLL gets its own array of void pointers that is
the same length as the above array.


DLL Routines
------------

The return value MMPTR is a macro defined as BYTE.  It is simply the index to 
the relevant entry in the array of structures defined above.  This value is 
known as the pseudo-pointer.

Note that the mutex only protects the array of structures.  It is up to the user
to protect the allocated memory itself.


MMPTR mmMalloc(DWORD size)

Allocates and maps a memory-mapped block of size bytes and returns a 
pseudo-pointer to it if it suceeds and MM_NULL if it fails.

void mmFree(MMPTR ptr)

Unmaps and frees the block pointed to by ptr. This block is also securely
deleted. Use of an MMPTR after it has been freed by any process will cause
an access violation (just as with free(...)). Therefore, you must be very
careful when calling this function. Returns instantly if ptr is MM_NULL.

LPVOID mmGetPtr(MMPTR ptr)

Returns the actual memory location for this pseudo-pointer in the calling
process' space.  Will map the memory-mapped file previously opened by another
process into the caller's space if necessary. This function increases a
pseudo-pointer's usage count.

void mmReturnPtr(MMPTR ptr)

Unmaps the pseudo-pointer from the caller's space.  It can be remapped if
necessary.  The function is called for all pseudo-pointers whenever a process
detaches from the DLL (it obviously will not use them after that). This function
decreases a pseudo-pointer's usage count.  If the count is reduces to 0, mmFree
is called instead.  Therefore, you should not call this function unless absolutely
necessary.  It is called by the DLL itself whenever a process detaches.


Helper Routines
---------------

SecureDelete(...)

This function is called on a block of data by mmFree. It overwrites the disk
location corresponding to this memory-mapped with a sequence of values designed
to make recovery very difficult. The file mapping is flushed after each value
is written to ensure that the values are actually written to disk.


To Do:
------
- Try to make this module even more transparent, such that the pseudo-pointers
can be treated as real pointer by the process.
- Check if this DLL can instead be run at the kernel level. It might then be
able to assign memory out of the VxD block (for 95) or the OS block (for NT)
and avoid this whole pseudo-pointer thing.
- Rework the functions such that they assign memory out of one, really large,
memory-mapped block instead of making one for each request.  Because of the way
Win32 manages memory, each block is effectively given its own page (or more).
Therefore, the current setup could cause a lot of swapping.
- Bugs to check for: Is there a noticeable system slowdown from the extra layer?

--------

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall 
{schneier,kelsey,hall}@counterpane.com.  

Thank you.

Ari