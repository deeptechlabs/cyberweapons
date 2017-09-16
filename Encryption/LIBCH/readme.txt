libch Version 0.25a

libch is a C/C++/Assembly library I wrote for doing fast
one-way hashing on the Pentium. It was insipred by
Bosselaers, Govaerts, and Vandewalle's paper Fast Hashing
on the Pentium [BGV] and the speed improvements claimed
[BOS] since then. My cycle counts are all faster than [BGV]
and are reasonably close to [BOS]: 

hash   | libch | [BOS] | libch/[BOS]
------------------------------------
md5    |   353 |   345 |        1.02
sha0   |   863 |   N/A |         N/A
sha1   |   895 |   837 |        1.07
rmd128 |   618 |   597 |        1.04
rmd160 |  1040 |  1016 |        1.02 

I have tried to make this library easy to port. Currently
makefiles are included for Microsoft's Visual C++, Watcom C/C++
(Version 11.0), and GCC. In addition, you should be able to
assemble the compression functions with any assembler
supporting minimal MASM syntax, or with NASM. This library has
been tested under GCC 2.7.2/Linux, GCC 2.7.2/NT, MSVC++ 5.0/NT,
and Watcom C/C++ Version 11.0/NT. The library is public domain
except for some very minor provisos. Here are the files, enjoy!: 

lch025.zip :  libch Version 0.25 Source Code and Documentation
lch025a.txt:  Patch to version 0.25 needed for MSVC++