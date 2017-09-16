FastCAST Version 0.1.1
**********************

Copyright 1996-7 by Peter Gutmann (pgut001@cs.auckland.ac.nz), 
                 Leonard Janke (janke@unixg.ubc.ca), and 
                 Vesa Karvonen (vkarvone@mail.student.oulu.fi).

Overview
********

FastCAST is a software library providing Pentium optimized assembly
implementations of the block encryption and decryption algorithms used in
the CAST-128 cipher described in "Constructing Symmetric Ciphers Using the
CAST Design Procedure" by Carlisle Adams.  Also included are C code for key
initialization, a test driver written in C, and assembly implementations of
CBC encryption and decryption.  

Most of the work on the core sequencing is due to Vesa, and the results are
impressive.  FastCAST, in CBC mode, encrypts at a rate of about 31 cycles
per byte on a Pentium [1], whereas a C implementation of the CBC encryption
function, optimized with Version 5.0 of Microsoft's Visual C++ compiler
[2], encrypts at about 63 cycles per byte. 

License Terms
*************

Nortel, under whose aegis the CAST-128 algorithm was developed, allows free
use of the algorithm for any purpose.  In addition, the authors of this
particular implementation allow it to be used freely either for commercial
or non-commercial purposes, providing that derivative works are clearly
identified as such, and users agree to absolve the library's authors of all
legal liability from any losses or damages that may result from its use.

Installation
************

Step 1: Generation or Copying of the Assembly File  
==================================================

Using Pre-Generated Files
-------------------------

Pregenerated assembly files are included for some environments. These
pregenerated files are included in the pregen/ directory.  Check in this
directory to see if there is one that seems appropriate for your local
environment, and, if so, copy or move it to the c/ directory.  Note that
WASM (Watcom's assembler) is supposed to accept a syntax which is a subset
of MASM's, so it is suspected that the assembly files in pregen/wasm/cdecl/
directory will work with MASM compatiable assemblers. Also note that the
file in the gnu/ directory needs to include the file c/asm.h.

Generating the Assembly File from Scratch Using Makefiles
---------------------------------------------------------

The directory asm/ contains some C++ files and makefiles used to generate
the assembly file from scratch. If you are in an environment that allows
use of a makefile, check the corresponding config.* file in the fcast011/
directory to ensure that the defaults choosen are appropriate for your
local environment.  This is most important for GNU environments, in which
config.gnu is configured for a Linux, ELF, gas system by default. The
default target "all" creates the assembly file, while the target "install"
creates it, if necesarry, and copies it to the c/ directory. 

Generating the Assembly File from Scratch Without Makefiles
-----------------------------------------------------------

If there is no custom makefile for your environment, compile and link all
the *.cpp files in asm/ together to create an executable called "gencast".
Next, run gencast to see a usage summary.  gencast can then be run with the
approriate options and its output redirected to create an approriate assembly
file. The newly created assembly file can then be copied to the c/
directory.


Step 2: Compiling of the FastCAST library
=========================================

Generating the Library Using Makefiles
--------------------------------------

The directory c/ should now contain pre-existing c files and the assembly
file copied or moved there from Step 1. The default make target will now
create the library. 

Generating the Library Without Makefiles
----------------------------------------

Assemble the assembly file in the c/ directory that was put there in
Step 1.  Next compile the pre-existing *.c files into object files. The
object files can then be archived into a library, which you may like to
name "fastcast" or "fcast".

Step 3: Testing the Library with the C test driver
==================================================
 
c/cast128c.c can now be compiled, linked with the library, and run to
ensure that everything is working properly.  If you are using the
makefiles, the test driver can be created by making the target
"cast128c.exe" for Microsoft operating systems, and "cast128c" for UNIX
operating systems.

Using the Library
*****************

The file c/cast128c.c provides an example of how to use the functions
provided. There are also important notes on using the CBC functions in
cast128.h. If things are not crystal clear after studying these, bug the
maintainer to write some proper documentation. :)

Keeping in Touch and Upcoming
*****************************

The stand-alone version of this library will be maintained by Leonard
Janke. Updates will be posted to the library's homepage at 

http://www.interchg.ubc.ca/janke/fastcast/ 

Please contact Leonard if you have any questions, comments, suggestions
for improvements, or if you are able to provide improvements yourself.

Peter Gutmann will be integrating the functions provided into his cryptlib
library.  cryptlib is a free encryption library which provides conventional
and public-key encryption, key management, and encrypted data management
functions.  More information about cryptlib is available at

http://www.cs.auckland.ac.nz/~pgut001/cryptlib.html. 

Notes
*****

[1] 14 cycles per round x 16 rounds +overhead. Future version may reduce
    the overhead a bit.
[2] Microsoft Visual C++ Version 5.0 is widely acknowledged to be the 
    compiler which, in general, produces the fastest machine code 
    for Pentiums in protected mode at the time of writing. (The correctness
    of the code is another question...)

Leonard Janke (janke@unixg.ubc.ca)
June 17, 1997
