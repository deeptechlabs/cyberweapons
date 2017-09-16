//package UK.co.demon.windsong.tines.pegwit;
/**
	GF_M	dimension of the large finite field (GF_M = GF_L*GF_K)
	GF_L	dimension of the small finite field
	GF_K	degree of the large field reduction trinomial
	GF_T	intermediate power of the reduction trinomial
	GF_RP	reduction polynomial for the small field (truncated)
	GF_NZT	element of the large field with nonzero trace
	GF_TM0	size of trace mask
	GF_TM1	1st nonzero element of trace mask
	GF_TM2	2nd nonzero element of trace mask
	EC_B	scalar term of elliptic curve equation (y^2 + xy = x^3 + EC_B)
   @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
*/

public final class Ecparam
{
	public static final int GF_M=255;

	public static final int GF_L =	     15;
	public static final int GF_K =	     17;
	public static final int GF_T =	      3;
	public static final int GF_RP	=        3;
	public static final int GF_TM0 =       1;
	public static final int GF_TM1 =       1;
	public static final int EC_B =      0xa1;
}

