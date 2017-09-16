Elliptix Snapshot Readme 1999/03/31


Disclaimer
----------

This snapshot is pre-alpha quality software. It is only provided for 
the brave and stupid people that want to live on the bleeding edge. 
Don't expect this piece of software to work on your machine, don't 
expect it to do something useful if it works and -above all- DO 
expect it to destroy your harddisk, eat your cat and blow up your 
monitor.

Now that we have warned you, feel free to read on... :-)


Introduction
------------

This is Elliptix, the Cryptix elliptic curve cryptography project.
Elliptic Curve Cryptography (ECC) is the state-of-the-art technology 
for public key cryptosystems, providing the highest security-to-key
size ratio.

Elliptix is intended to be a complete, 100% pure Java implementation
of the IEEE P1363, ANSI X9.62 and ANSI X9.63 standards (currently in 
draft form, but going soon to ballot).


Features and technical information
----------------------------------

At this stage Elliptix supports arithmetic over both GF(p) (with
projective coordinates) and GF(2^m) (with affine coordinates over
polynomial basis), but not curve parameter generation (CM and point
counting are on schedule, but this will take a while to complete).
Scalar multiplication employs the sliding window add/subtract method.

Higher level operations (e.g. signing and verification) are still 
missing, though ECDSA and ECDH are due to be soon released.


Updates
-------

You can find the latest Elliptix snapshot on the Cryptix website:
  http://www.cryptix.org/
We will post updated versions as soon as they are available.


Release
-------

No release date has been set.


Feedback
--------

We need feedback in order to improve Elliptix. If you have any 
comments, suggestions or bug reports, don't hesitate and send 'em 
to Paulo Barreto <pbarreto@cryptix.org>.


--
readme.txt 1999/03/31 19:12:41 gelderen