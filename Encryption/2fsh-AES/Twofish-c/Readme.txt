README.TXT

Algorithm:	Twofish
Submitters:	Bruce Schneier, Counterpane Systems
		Doug Whiting,	Hi/fn
		John Kelsey,	Counterpane Systems
		Chris Hall,	Counterpane Systems
		David Wagner,	UC Berkeley
		Niels Ferguson, Counterpane Systems

Optimized ANSI C implementation
=============================================

This directory contains the following files:

  Makefile.bcc        makefile for use with the Borland compiler
  Makefile.gcc        makefile for use with GCC-based compilers
  Makefile.Visualc    makefile for use with the Visual C compiler

  aes.h               NIST API header file adapted for Twofish
  debug.h             macros for debugging purposes
  platform.h          platform specific definitions
  table.h             Tables, macros, constants for Twofish S-boxes and MDS matrix
  twofish2.c          C API calls for optimized TWOFISH AES submission
  tst2fish.c          command line test program

  Readme.txt          This file
