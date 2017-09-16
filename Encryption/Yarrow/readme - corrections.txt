12345678901234567890123456789012345678901234567890123456789012345678901234567890

Corrections
-----------

- I managed to omit two necessary include files (Zlib\zlib.h and Zlib\zconf.h)
from the original version of the Yarrow 0.8.7 archive. My apologies.

- Also, if you are using the VC++ project files on NT, you will need to alter
the post-compile step such that it saves the DLLs in C:\WinNT\System32 instead
of C:\Windows\System.

- A point about the makefiles passed along by James Grant of Signal 9 Solutions:

Another thing I noticed in the makefiles was that my version of
Visual C++ didn't like the '::' on lines like:

.cpp{$(CPP_OBJS)}.obj::

I reduced it to one, and it compiled fine.



That's all for now. Hopefully this should take care of any problems with the
archive itself, leaving only the (hopefully few) problems with the code. As
usual, if you have any question/comments/complaints, please direct them to
Ari Benbasat <pigsfly@unixg.ubc.ca> and cc: them to Bruce Schneier, John Kelsey
and Chris Hall <{schneier,kelsey,hall}@counterpane.com>.

Thanks
ari