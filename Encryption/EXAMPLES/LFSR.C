/* should the first case be:
	ShiftRegister = ((ShiftRegister ^ mask) >> 1)) | 0x8000000;
   ?  I preserved what you had, just added parenthesis to make
   clear how C interprets it.  I'm not remembering my LFSR theory
   right now, so I'm not sure which is right.
		--Ken Pizzini
		ken@halcyon.com
*/
/*
Instead of using the bits in the tap sequence to generate the new
leftmost bit, each bit in the tap sequence is XORed with the
output of the generator and replaced, and then the output of the
generator becomes the new leftmost bit (see Figure 15.4).
*/

#define mask 0x80000057

static unsigned long ShiftRegister=1;

void
seed_LFSR(unsigned long seed)
{
	if (seed == 0)	/* avoid calamity */
		seed = 1;
	ShiftRegister = seed;
}

int
modified_LFSR(void)
{
	if (ShiftRegister & 0x00000001) {
		ShiftRegister = (ShiftRegister ^ (mask >> 1)) | 0x8000000;
		return 1;
	} else {
		ShiftRegister >>= 1;
		return 0;
	}
}
