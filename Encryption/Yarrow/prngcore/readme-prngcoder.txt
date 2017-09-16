12345678901234567890123456789012345678901234567890123456789012345678901234567890

Description of High-Level Routines in Prngcore
----------------------------------------------

This file describes the data structures used in prngcore, as well as the high
level routines for use by those who will be setting up and altering the prng
and initializing the connection between the prng and the entropy collection
routines.  Those interested in simply calling the prng for output are directed
to the file readme-prnguser in this folder.

Note that these routines make use of the zlib compression library, and Steve 
Reid's SHA1 routines.

A major programming issue in the DLL is that it will be called by a number of
different processes, which means that handles and memory locations cannot be
stored simply as is. This DLL will make a duplicate of its handles for each process
that attaches (and close them when the process detaches) and will also call the
smf rountine to get (and store) the appropriate memory pointer at that time.

Files in this directory
-----------------------

comp.c and comp.h

Front end for the zlib compression library.

prng.c, yarrow.h and prng.h

Code and public and private headers for the core prng routines. Include both
yarrow.h and prng.h in code that will be calling high-level routines.

prngpriv.h

Private header file for prng.c

prng.mut

The routines in prng.c, wrapped for use with the mutex.

userdefines.h

Header file with macros that can be redefined to specify the system that this
code is being compiled on, as well as other details of the prng operation.

usersources.h

Header file for the user to name their own entropy sources.

assertverify.h

Misc. header with assert/verify routines for Win32.

ntonly.c and ntonly.h

Code for NT specific routines. Contains code to run a slow poll, which 
collects performance registry data, as well as code that restricts external
access to the above data.

95only.c and 95only.h

Code for Win95 specific routines. Contains code to run a slow poll, which
collects data on the processes that are currently running via the ToolHelp32
library.

sha1mod.c and sha1mod.h

Steve Reid's SHA1 code (slightly modified).  



Description of Structures
-------------------------

The main PRNG structure is a static variable visible only within the DLL 
itself. Its members are discussed below:

outstate

An output context that contains an output buffer and a secret IV.

index

The next byte in the IV to output.

numout

Number of bytes outputted since the last anti-backtracking operation.

pool

An SHA1 context to store the entropy pool. Note that this means we can never 
have more than 160 bits of entropy.

poolSize

An array storing the size in bytes of the various entropy pools.

poolEstBits

An array storing the user-provided estimate, in bits, of the amount of entropy 
in each of the pools.

comp_state

An array storing the compression states for each of the entropy, to provide 
another source of entropy estimation.

ready

The ready flag is set by the initialization routine and will be reset
in the case of a fatal error.


PRNG Routines
-------------

All major routines return the success/error value for their operation.
Note that all routines that need to be protected from simultaneous access are
implemented as m_<function_name> and then wrapped for use with the mutex.

prngInitialize()

Allocated memory for the global PRNG state and sets up the internal variables.  
Allocates memory, sets flags and initializes the SHA1 and compression contexts.
Does an initial slow poll to collect information for the initial output state.

prngProcessSeedBuffer(buf,ticks)

Takes a 20 byte buffer, which is hashed into the entropy pool. 20 bytes of PRNG
output are then also hashed in (to prevent total user knowledge of the pool) and
a reseed of length ticks is forced. The first 20 bytes of PRNG output are copied
into buf for future use with this function. Data used with this function should
be stored as securely as possible.

prngOutput(outbuf,outbuflen)

Writes outbuflen worth of "random" data to outbuf.  Data is taken from the
output buffer of outstate. Whenever this buffer is exhausted, it is then 
concatenated with the IV (secret state) and their digest is calculated
to provide the next 20 bytes of output. Every BACKTRACKLIMIT bytes, the prng 
will output 20 bytes and use those to reinitialize the state before continuing 
to output data.  To be able to backtrack through this change over would require 
inverting SHA1.

prngStretch(inbuf,inbuflen,outbuf,outbuflen)

Takes inbuflen bytes of data from inbuf and turns it into outbuflen bytes of 
data stored in outbuf by repeatedly hashing inbuf and then placing the digest in 
outbuf.

prngInput(inbuf,inbuflen,poolnum,estbits)

Takes inbuflen bytes of user data from inbuf and places it in user pool poolnum.  
The user pool names can be found in usersources.h. Note that there are three
pools designated for user input, but this can be changed. The user claims
that this data contains estbits bits of entropy.  This data is also placed in a
compression context (there is one per pool) to be able to provide an independant 
entropy estimate if the user has set the COMPRESSION_ON flag.

prngInputEntropy(inbuf,inbuflen,poolnum)

Same as the above function, but for use with the internal entropy sources. Data
collected by the hooks routines (as well as by slow polls) is feed through this
input routine. This routine is equivalent to the one above, except that the data
is always placed in a compression context.

prngSlowPoll(pollsize)

Does a slow poll with a buffer size of pollsize bytes. A value of at least 32K is
suggested, but smaller values can be used for shorter polls.  The data is then
fed into the entropy pool via prngInputEntropy.

prngForceReseed(ticks)

Forces a reseed that lasts about ticks ticks (ugh) long.  The reseed is done as 
follows. First, the pools is churned for ticks ticks by outputting 64 bytes 
from the prng and immediately putting it hashing it into the entropy pool. This 
does not provide any more security but will increase the effort needed on the 
part of an attacker.  The amount of time used in the reseed can also be counted
as a (rather insecure) part of the secret state for the purposes of attack.  The
function then outputs the message digest (after all the churning), rehashes the 
state pool into itself, and then outputs another digest.  This digest is used to 
reinitialize the output generator. This is the only connection between the 
entropy pool and the output. The compression states are then reinitialized.

prngAllowReseed(ticks)

Will force a reseed if there is enough entropy.  The entropy in each user pool
is taken to be the minimum of the user estimate and half the estimate acquired 
through compression, if used.  The entropy in an internal pool (those collected by
the system itself) is always calculated by compression. A reseed will be done if
the total entropy, ignoring the K greatest sources, is greater than THRESHOLD. 
Currently, K = 0  (a bad idea) and THRESHOLD = 100 (likely to remain fixed). 

prngDestroy()

Reverses the operation of prngInitialize. Flushes and deletes the compression 
states. Deallocates dynamic memory.


Helper functions
----------------

These functions are should not be called by except by other functions:

prng_do_SHA1(ctx)

Takes an output context, reinitializes the SHA1 context within, concatenates
the previous output buffer and the IV and outputs their digest. This value is
the new output buffer.

prng_make_new_state(ctx,state)

Takes a 20 byte buffer and stores it as the new secret IV. Calculates the
digest of that IV as the first output buffer.

prng_slow_poll(buf)

Does a poll that returns 20 bytes of data in buf. Currently collects ToolHelp32
information on 95 and performance registry data on NT.

prng_slow_init(void)

Initializes the full secret state by doing a slow poll of length SPLEN (can be
set by programmer) and then creating a new state from its SHA1 digest. Initializes
assorted associated variables as well.

trashMemory(mem,len)

Overwrites the section of memory len bytes long pointed to by mem. Will provide
a semi-secure delete for data stored in RAM for a short period of time. See the 
smf documentation for more details. 

bubbleSort(data,len)

Performs an in-place modified bubblesort on the integer data in data. Bubblesort
was chosen as this routine is used solely on the array of entropy estimates, 
which is assumed to be rather small (<10).  If the array becomes any larger 
than that (which would be quite strange), this routine should be replaced with 
a quicksort or radix sort of the data.


To Do:
------
- The NT security routines are not tested as they will not compile on my 95 box.
Security is theoretically good, but so was the Edsel. Things that should be
checked for include: Can handles be duplicated correctly inside the code and not
at all outside? Is the registry data secure? Can these routines be called by the
user with any usefulness, or only by the admin account?
- The slow poll for Win95 needs to be refined and prng_slow_init() needs to be
rethought.  Randomness quality testing needs to be done on both slow polls.

--------

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall
{schneier,kelsey,hall}@counterpane.com.  

Thank you.

Ari