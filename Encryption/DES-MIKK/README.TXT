BasDES version 1.

DES library for MS QuickBasic 4.5 and MS Basic 7.1.

Svend Olaf Mikkelsen,
svolaf@inet.uni-c.dk,
May 28, 1997.

Available as:  http://inet.uni-c.dk/svolaf/basdes01.zip
Next version
if updated:    http://inet.uni-c.dk/svolaf/basdes02.zip


Based on the libdes library by Eric Young:
Version 4.01 13-Jan-97   (Libdes-l.gz)

libdes is available at:
ftp://ftp.psy.uq.oz.au/pub/Crypto/DES

Files from the libdes library used:
des_enc.c       (with this line added:   #include "spr.h" )
set_key.c
      *.h

For the libdes copyright notice, see below.


To use the library, invoke Basic with:

QB /L basdes45
or
QBX /L basdes71


A 486 processor or higher is required, since I was not able to
compile the C files to the 286 processor.

Only DES ECB mode is implemented, but Basic functions could be made to
support CBC and EDE modes.

Checking for weak keys is not supported, since the C memcmp function
used is not available to the Basic library.

****************************

The libdes copyright notice:

Copyright (C) 1995-1997 Eric Young (eay@mincom.oz.au)
All rights reserved.

This package is an DES implementation written by Eric Young (eay@mincom.oz.au).
The implementation was written so as to conform with MIT's libdes.

This library is free for commercial and non-commercial use as long as
the following conditions are aheared to.  The following conditions
apply to all code found in this distribution.

Copyright remains Eric Young's, and as such any Copyright notices in
the code are not to be removed.
If this package is used in a product, Eric Young should be given attribution
as the author of that the SSL library.  This can be in the form of a textual
message at program startup or in documentation (online or textual) provided
with the package.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by Eric Young (eay@mincom.oz.au)

THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

The license and distribution terms for any publically available version or
derivative of this code cannot be changed.  i.e. this code cannot simply be
copied and put under another distrubution license
[including the GNU Public License.]

The reason behind this being stated in this direct manner is past
experience in code simply being copied and the attribution removed
from it and then being distributed as part of other packages. This
implementation was a non-trivial and unpaid effort.

