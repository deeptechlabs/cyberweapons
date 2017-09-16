D. J. Bernstein <djb@koobera.math.uic.edu> wrote:

This is SURF, a function taking a 1024-bit index and a 384-bit input to
a 256-bit output. As far as I know, when the index is selected randomly,
SURF is Turing secure; i.e., no practical algorithm can tell the
difference between SURF and a uniformly chosen random function.

Speed: The code below, compiled with gcc, takes about 3900 Pentium
cycles. That's about 6 output megabits/sec on a Pentium-100. Handwritten
asm will be about twice as fast. Setup time is zero.

Motivation: I'm using cryptographically strong confirmation numbers in
my new mailing list manager, ezmlm. I've decided that Snefru takes too
much memory. The compiled SURF code uses 384 bytes.

Inspiration: I follow TEA's lead in doing lots of rounds of a very fast
function. (DES touches each bit 8 times; TEA 32 times; SURF 16 times.)
I also follow TEA's approach to scheduling. SURF's data flow is, I
think, the most obvious generalization of Feistel to a large block.
SURF's depth is about thirty times full avalanche.

Distribution: Feel free to pass this along. Since it's a MAC it should
be exportable; I plan to publish it as part of ezmlm.

---Dan