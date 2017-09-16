12345678901234567890123456789012345678901234567890123456789012345678901234567890

Yarrow - Beta Release Version 0.8.7
-----------------------------------

This is the beta beta release of Counterpane's Yarrow, an integrated 
pseudo-random number generator and entropy collection utility.  This is
the main readme file for the package. The package contains the following 
folders:

entropyhooks - Entropy collection routines.  Contains the entropy DLL,
               which provides hook routines to collect mouse and keyboard
               timing as well as communcations routines based on memory-
               mapped files and event flags.

prngcore - The main PRNG routines. Currently in DLL form, with some functions
           available to the end user, and others available only to the high
           level user.  See readme-prnguser for more details.

frontend - Entropy collection and prng setup program.  This application should
           be run at startup time on any system that wishes to use the prng
           routines.  Attempting to call the prng routines without first
           running frontend will lead to an error.

testapp - A trivial application to test the "client end" of the PRNG (the 
          "server end" is setup and controlled by frontend).  Run frontend and
          then this application to demonstrate the full Yarrow setup.

smf - Secure Malloc/Free. Contains the memory management DLL. Memory is
      assigned from the system paging file and mapped into the current
      process' address space.  Memory is securely deleted upon freeing.

zlib - Compiled versions of the zlib compressiong library. zlibr.lib is the 
       release version and zlibd.lib is the debug version.

More details can be found in the individual folders.  These are primarily 
intended for those wishing a more in-depth understanding of the code. For those
interested in testing applications with this beta version, just compile frontend
and place it in the Startup folder of the Start menu.  Then restart your 
computer and call the PRNG routines either with testapp or with your own code.
You will want to read the file readme-prnguser in the prngcore folder. 
For those wishing to examine/tinker with/comment on the source code, you will
want to read all the readme files.  For those interested, details of the 
cryptography can be found in readme-crypto in the prngcore folder.

Frontend will eventually be replaced by a kernel-level device driver so that it
does not need to be run manually at startup.  It currently runs as an application
without a window, and can be controlled by right-clicking its icon in the
notification area (far right end of the taskbar).

All code is in C and is designed to work on Win95 and WinNT systems, though the
security of the NT routines are currently untested. Currently, there are OS specific
versions of the code only in the prngcore library. Switch between 95 and NT by 
changing the flag in prngcore/userdefines.h.

This package was programmed in Visual C++ 5.0.  Project and workspace
files have been provided.  Makefiles outputted from VC++ can also be found in
each folder.  All links used should be relative, allowing this archive to be
unpacked anywhere.  On the off-chance that that fails, the archive should be
unpacked in: C:\work\prng\yarrow.

Any questions can be directed to the programmer (me), Ari Benbasat, at 
pigsfly@unixg.ubc.ca.  Comments would be greatly appreciated.  Please cc: all
e-mail to Bruce Schneier, John Kelsey and Chris Hall 
{schneier,kelsey,hall}@counterpane.com.  

Thank you.

Ari Benbasat
