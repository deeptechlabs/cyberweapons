To build RSAREF, copy the makefile for your operating system from the
'install' subdirectory to a new subdirectory. Then run your operating
system's 'make' program from the new subdirectory. The makefile will
compile the RSAREF source code and build the demonstration program.
Makefiles are found in subdirectories of the 'install' subdirectory:

     dos       Personal Computer running DOS, Microsoft C v8.0
     mac       Macintosh running System 7, MPW 3.2
     unix      NeXTStation, DECStation 3100, SPARCStation 1

For example, suppose you are running DOS with Microsoft's NMAKE
utility. From the new directory you would run the commands:

     copy ..\install\dos\makefile
     nmake

Note that when you transfer RSAREF to another operating system, the
following files in the 'rdemo/scripts' subdirectory should be
transferred in binary mode:

    - signatures: *.sig
    - initialization vectors: *.iv
    - envelopes: *.env
    - encrypted keys: *.key (excluding RSA key pairs in 508.key,
        767.key, 1024.key)

All other RSAREF files should be transferred in text mode.
