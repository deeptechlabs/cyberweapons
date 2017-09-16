Note that Paulo found a mistake in the reference implementation:
the first padding byte should be x01 not 0x80. Also note that the
macro LITTLE_ENDIAN needs to be defined externally (on a little
endian machine). The code has not been tested on big-endian
machines. [ The HAVAL reference implementation contains a
copyright notice which (to me at any rate) makes it *not* public
domain, although Dr Yuliang has stated in private email that it
*is* public domain. HAVAL is not patented ]