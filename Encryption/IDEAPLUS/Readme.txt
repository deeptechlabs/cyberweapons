/*****************************************************************************/
/*                        IDEA Encryption Algorithm                          */
/*****************************************************************************/
/*                                                                           */
/*   IDEA (International Data Encryption Algorithm) is a block encryption    */
/*   algorithm whose development results from a co-operation between the     */
/*   Swiss Federal Institute of Technology Zurich (ETHZ) and Ascom Tech Ltd. */
/*   IDEA encrypts or decrypts 64-bit data blocks, using symmetric 128-bit   */
/*   keys. The 128-bit keys are furthermore expanded to 52 16-bit subkeys.   */
/*                                                                           */
/*   For detailed technical information on IDEA contact:                     */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*   Patent rights of Ascom Systec Ltd. granted in Europe, Japan and the US. */
/*   All other rights reserved.                                              */
/*                                                                           */
/*   For detailed patent information on IDEA contact:                        */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*   Author:    Alain Beuchat/Daniel Zimmermann                              */
/*   Release:   2.1                                                          */
/*                                                                           */
/*****************************************************************************/
/*
File Name:		README

The README file of the IDEA Software describes the file structure of the
Release 2.1 and the way to install it on your system.

The major difference between Release 1.0 and 2.0 is a change in the MUL()
macro in order to avoid jumps. If the multiplication is implemented with jumps
treating the special case when one of the factors is zero (or 2**16,
respectively), a so-called side channel attack may take advantage of the fact
that the multiplication by zero takes less time than multiplication of non-zero
factors.
For more information, see  http://www.counterpane.com/side_channel.html .

ideaplus.c and ideaplus.cpp have Version number 2.1. Thsi version corrects
a minor error in the mul (multiplication 2**16+1) routine.

Furthermore, a set of binary files for testing IDEA in different modes of
operation has been added. For details see file Test_Cases_IDEA.txt.


DESCRIPTION OF THE FILES
------------------------

README
------
This file.


c_ext_fc.h
-----------
Macro definitions for the function prototypes compliance to either ANSI C or
Kernighan & Ritchie C format.


c_fct.h
-------
Macro definitions for the function definitions compliance to either ANSI C or
Kernighan & Ritchie C format.


ideaplus.h
----------
Header file defining the IDEA software:

 - "atomic" types (which are compiler and platform dependent):
     uint16:			unsigned 16-bit int;
     uint32:			unsigned 32-bit int;
     int32:			signed 32-bit int.

 - "idea" types:
     idea_key_t:		128-bit key type;
     idea_subkeys_t:		subkeys type (set of 52 16-bit subkeys);
     idea_block_t:		data block type.

 - "idea" functions:
     idea_encrypt_subkeys:	computes the encryption subkeys from a 128-bit
				key;
     idea_decrypt_subkeys:	computes the decryption subkeys from the
				encryption subkeys;
     idea_cipher:		enciphers an input block and writes it into an
				output block using a subkeys set (encryption or
				decryption).

"c_ext_fc.h" is #included in "ideaplus.h".


ideaplus.c
----------
Source code of the three IDEA functions (see "ideaplus.h").
Either Kernighan & Ritchie C or ANSI C code can be produced, using the macros
defined in "c_fct.h".
The emphasis for the implementation was put on the portability rather than on
the efficiency of the software. Therefore some improvements depending on the
compiler and the platform used could be brought up.
The main improvements may be the elimination of useless 16-bit maskings (only
if calculations are carried out on 16-bit length variables!) and the 
elimination of 2**16 additions (x + 2**16 = x if the number are represented as
complement to two and if we consider only the 16 lower bits).

For more information about the algorithms, see the IDEA software
documentation.
"c_fct.h" and "ideaplus.h" are  #included in "ideaplus.c".


ideat.c
-------
Test file for the IDEA software.
The correctness of the algorithm can be tested by running the "ideat" test
program. Either Kernighan & Ritchie C or ANSI C code can be produced, using
the macros defined in "c_fct.h".
"ideat" produces three tables showing the input and output data blocks of the
repeated encryption and decryption of a data block. If the last block is equal
to the input block, the algorithm is assumed to be correctly running.
If TEST_SIZE is #defined, "ideat" prints out a short report concerning the
choice of the "atomic" types defined in "ideaplus.h".
"c_fct.h" and "ideaplus.h" are  #included in "ideaplus.c".


Installation and testing of the IDEA software
---------------------------------------------

To install the IDEA software:

 1 - Copy "c_ext_fc.h", "c_fct.h", "ideaplus.h", "ideaplus.c", "ideat.c" to a
     directory.

 2 - Adjust the "atomic" types in "ideaplus.h".

 3 - Compile "ideaplus.c" and "ideat.c" --> "ideaplus.o" and "ideat.o".

 4 - Link "ideaplus.o" and "ideat.o" --> "ideat".

 5 - Run "ideat" and observe the output:
     Is Input block equal to Last block?
     Have all "atomic" types an optimum size? --> "ideat" generates correct
     results.
     Are only suggestions and no warnings produced? --> "ideat" generates
     correct results.
     Are there warnings on the "atomic" size? --> "ideat" generates dummy
     results.

 6 - If necessary, begin again with statement 2.

Remark:
When using a C++ compiler, use files "ideaplus.cpp" and "ideat.cpp" instead of
files "ideaplus.c" and "ideat.c", respectively.


TEST CASES FOR ECB, CBC, CFB, AND OFB (in separate directory Testdata.zip)
--------------------------------------------------------------------------

Test_Cases_IDEA.txt
-------------------
This file describes the IDEA test cases for the different modes of operation
(ECB, CBC, CFB, OFB) and gives the data in hex format.


Test_data
---------
Test data as binary files. For details see file Test_Cases_IDEA.txt.
