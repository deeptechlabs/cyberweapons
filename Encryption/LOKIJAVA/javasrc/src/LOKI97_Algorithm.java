// $Id: $
//
// $Log: $
// Revision 1.0  1998/04/06  raif
// + start of history.
//
// $Endlog$
//
package LOKI97;

import java.io.PrintWriter;
import java.security.InvalidKeyException;

/**
 * Implements the LOKI97 block cipher.<p>
 *
 * LOKI97 is a 128-bit symmetric block cipher with a 256-bit key schedule,
 * which may be initialised from 128, 192, or 256-bit keys. It uses 16 rounds
 * of data computation using a balanced feistel network with a complex
 * function f which incorporates two S-P layers. The 256-bit key schedule
 * uses 33 rounds of an unbalanced feistel network using the same complex
 * function f to generate the subkeys.<p>
 *
 * LOKI97 was written by Lawrie Brown (ADFA), Josef Pieprzyk, and Jennifer
 * Seberry (UOW) in 1997.<p>
 *
 * <b>Copyright</b> &copy; 1997, 1998 jointly by <a href="mailto:Lawrie.Brown@adfa.oz.au">
 * Lawrie Brown</a> & ITRACE, and
 * <a href="http://www.systemics.com/">Systemics Ltd</a> on behalf of the
 * <a href="http://www.systemics.com/docs/cryptix/">Cryptix Development Team</a>.
 * <br>All rights reserved.<p>
 *
 * <b>$Revision: $</b>
 * @author  Lawrie Brown
 * @author  Raif S. Naffah
 */
public final class LOKI97_Algorithm // implicit no-argument constructor
{
// Debugging methods and fields
//...........................................................................

    static final String NAME = "LOKI97_Algorithm";
    static final String FULL_NAME = LOKI97_Properties.FULL_NAME;
    static final boolean IN = true, OUT = false;

    static final boolean DEBUG = LOKI97_Properties.GLOBAL_DEBUG;
    
    /**
     * Debug diagnostics. Value of property key "Debug.Level.LOKI97_Algorithm"
     * in the LOKI97.properties file located in the CLASSPATH. <p>
     *
     * Values are:<dl compact>
     * <dt> 1 <dd> engine calls,
     * <dt> 2 <dd> enc/dec round values,
     * <dt> 3 <dd> subkeys,
     * <dt> 4 <dd> func f calls,
     * <dt> 5 <dd> func f internals,
     * <dt> 6 <dd> static init. </dl>
     */
    static final int debuglevel = DEBUG ? LOKI97_Properties.getLevel(NAME) : 0;
    static final PrintWriter err = DEBUG ? LOKI97_Properties.getOutput() : null;

    static final boolean TRACE = LOKI97_Properties.isTraceable(NAME);

    static void debug (String s) { err.println(">>> "+FULL_NAME+": "+s); }
    static void trace (boolean in, String s) {
        if (TRACE) err.println((in?"==> ":"<== ")+NAME+"."+s);
    }
    static void trace (String s) { if (TRACE) err.println("<=> "+NAME+"."+s); }


// LOKI97 algorithm specific constants and tables
//...........................................................................

    /** Number of bytes in a data-block. */
    static final int BLOCK_SIZE = 16;

    /** Number of rounds for the algorithm. */
    static final int ROUNDS = 16;

    /** Number of subkeys used by the algorithm. */
    static final int NUM_SUBKEYS = 3 * ROUNDS;

    /** Constant value for Delta which is used in the key schedule */
    private static final long DELTA = 0x9E3779B97F4A7C15L;

    /** Generator polynomial for S-box S1, in GF(2<sup>13</sup>). */
    private static final int S1_GEN = 0x2911;

    /** Size of S-box S1, for 13-bit inputs. */
    static final int S1_SIZE = 0x2000;

    /** Table of pre-computed S-box S1 values. */
    static final byte[] S1 = new byte[S1_SIZE];

    /** Generator polynomial for S-box S2, in GF(2<sup>11</sup>). */
    private static final int S2_GEN = 0xAA7;

    /** Size of S-box S2, for 11-bit inputs. */
    static final int S2_SIZE = 0x800;

    /** Table of pre-computed S-box S2 values. */
    static final byte[] S2 = new byte[S2_SIZE];

    /**
     * Table specifying the pre-computed permutation P. Note:<ul>
     * <li> precompute permutations for lowest 8 bits only, since the
     *      remainder of the permutation is related to it by successive
     *      right shifts for each successive input byte.
     * <li> value of P is a 64-bit wide (long) mask of the permuted input
     *      value.</ul>
     */
    static final long[] P = new long[0x100];

    private static final char[] HEX_DIGITS = {
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };


// Static code - to intialise the S-box and permutation tables
//...........................................................................

    static {
	long time = System.currentTimeMillis();

        if (DEBUG && debuglevel > 6) {
            System.out.println("Algorithm Name: "+LOKI97_Properties.FULL_NAME);
            System.out.println("Electronic Codebook (ECB) Mode");
            System.out.println();
        }
        //
        // precompute S-box tables for S1 and S2
        //
        if (DEBUG && debuglevel > 5) debug("Static init of precomputing tables");
        final int S1_MASK = S1_SIZE - 1; // mask to select S1 input bits
        final int S2_MASK = S2_SIZE - 1; // mask to select S2 input bits

        int i = 0; // index into S-box
        int b; // S-box fn input

        for (i = 0; i < S1_SIZE; i++) { // for all S1 inputs
            b = i ^ S1_MASK; // compute input value
            S1[i] = exp3(b, S1_GEN, S1_SIZE); // compute fn value
            if (DEBUG && debuglevel > 5) debug(" S1["+shortToString(i) + "] = "+byteToString(S1[i]));
        }
        for (i = 0; i < S2_SIZE; i++) { // for all S2 inputs
            b = i ^ S2_MASK; // compute input value
            S2[i] = exp3(b, S2_GEN, S2_SIZE); // compute fn value
            if (DEBUG && debuglevel > 5) debug(" S2["+shortToString(i) + "] = "+byteToString(S2[i]));
        }
        //
        // initialising expanded permutation P table (for lowest byte only)
        //   Permutation P maps input bits [63..0] to outputs bits:
        //   [56, 48, 40, 32, 24, 16,  8, 0,
        //    57, 49, 41, 33, 25, 17,  9, 1,
        //    58, 50, 42, 34, 26, 18, 10, 2,
        //    59, 51, 43, 35, 27, 19, 11, 3,
        //    60, 52, 44, 36, 28, 20, 12, 4,
        //    61, 53, 45, 37, 29, 21, 13, 5,
        //    62, 54, 46, 38, 30, 22, 14, 6,
        //    63, 55, 47, 39, 31, 23, 15, 7]  <- this row only used for table
        //  However, since it is so regular, can construct it on the fly
        //
        long pval; // constructed permutation output value
        for (i = 0; i < 0x100; i++) { // loop over all 8-bit inputs
            pval = 0L;
            // for each input bit permute to specified output position
            for (int j = 0, k = 7; j < 8; j++, k += 8)
                pval |= (long)((i >>> j) & 0x1) << k;
            P[i] = pval;
            if (DEBUG && debuglevel > 5) debug(" P["+byteToString(i)+"] = "+longToString(P[i]));
        }

        time = System.currentTimeMillis() - time;

	// Dump the precomputed S1, S2 and P tables if desired
	if (DEBUG && debuglevel > 8) {
	    System.out.println("==========");
	    System.out.println();
	    System.out.println("Static Data");
	    System.out.println();
	    System.out.println("S1[]:");
	    for(i=0;i<S1_SIZE/16;i++) { System.out.print(shortToString(i)+": "); for(int j=0;j<16;j++) System.out.print(byteToString(S1[i*16+j])+" "); System.out.println();}
	    System.out.println();
	    System.out.println("S2[]:");
	    for(i=0;i<S2_SIZE/16;i++) { System.out.print(shortToString(i)+": "); for(int j=0;j<16;j++) System.out.print(byteToString(S2[i*16+j])+" "); System.out.println();}
	    System.out.println();
	    System.out.println("P[]:");
	    for(i=0;i<256;i++) System.out.println(byteToString(i)+": "+longToString(P[i]));
	    System.out.println();

	    System.out.println("Total initialization time: "+time+" ms.");
	    System.out.println();
	}
    }

    /**
     * Returns a byte residue of base b to power 3 mod g in GF(2^n).
     *
     * @param b  Base of exponentiation, the exponent being always 3.
     * @param g  Irreducible polynomial generating Galois Field (GF(2^n)).
     * @param n  Size of the galois field.
     * @return (b ** 3) mod g.
     */
    static final byte exp3 (int b, int g, int n) {
        if (b == 0)
            return 0;
        int r = b;            // r = b ** 1
        b = mult(r, b, g, n); // r = b ** 2
        r = mult(r, b, g, n); // r = b ** 3
        return (byte) r;
    }

    /**
     * Returns the product of two binary numbers a and b, using the
     * generator g as the modulus: p = (a * b) mod g. g Generates a
     * suitable Galois Field in GF(2^n).
     *
     * @param a  First multiplicand.
     * @param b  Second multiplicand.
     * @param g  Irreducible polynomial generating Galois Field.
     * @param n  Size of the galois field.
     * @return (a * b) mod g.
     */
    static final int mult (int a, int b, int g, int n) {
        int p = 0;
        while (b != 0) {
            if ((b & 0x01) != 0)
                p ^= a;
            a <<= 1;
            if (a >= n)
                a ^= g;
            b >>>= 1;
        }
        return p;
    }


// Basic NIST API methods for LOKI97
//...........................................................................

    /**
     * Expand a user-supplied key material into a LOKI97 session key.
     *
     * @param key  The 128/192/256-bit user-key to use.
     * @exception  InvalidKeyException if the key is invalid.
     */
    public static synchronized Object makeKey (byte[] k)
    throws InvalidKeyException {

        if (DEBUG) trace(IN, "makeKey("+k+")");

	// do some basic sanity checks on the key
        if (k == null)
            throw new InvalidKeyException("Empty key");
        if (!(k.length == 16 || k.length == 24 || k.length == 32))
             throw new InvalidKeyException("Incorrect key length");

	// display intermediate session key values if wanted
        if (DEBUG && debuglevel > 7) {
            System.out.println("Intermediate Session Key Values");
            System.out.println();
            System.out.println("Raw="+toString(k));
        }

        long[] SK = new long[NUM_SUBKEYS];	// array of subkeys

        long deltan = DELTA;			// multiples of delta

        int i = 0;				// index into key input
        long k4, k3, k2, k1;			// key schedule 128-bit entities
        long f_out;				// fn f output value for debug

        // pack key into 128-bit entities: k4, k3, k2, k1
        k4 = (k[i++] & 0xFFL) << 56 | (k[i++] & 0xFFL) << 48 |
             (k[i++] & 0xFFL) << 40 | (k[i++] & 0xFFL) << 32 |
             (k[i++] & 0xFFL) << 24 | (k[i++] & 0xFFL) << 16 |
             (k[i++] & 0xFFL) <<  8 | (k[i++] & 0xFFL);
        k3 = (k[i++] & 0xFFL) << 56 | (k[i++] & 0xFFL) << 48 |
             (k[i++] & 0xFFL) << 40 | (k[i++] & 0xFFL) << 32 |
             (k[i++] & 0xFFL) << 24 | (k[i++] & 0xFFL) << 16 |
             (k[i++] & 0xFFL) <<  8 | (k[i++] & 0xFFL);
        if (k.length == 16) {   // 128-bit key - call fn f twice to gen 256 bits
            k2 = f(k3, k4);
            k1 = f(k4, k3);
        } else {                // 192 or 256-bit key - pack k2 from key data
            k2 = (k[i++] & 0xFFL) << 56 | (k[i++] & 0xFFL) << 48 |
                 (k[i++] & 0xFFL) << 40 | (k[i++] & 0xFFL) << 32 |
                 (k[i++] & 0xFFL) << 24 | (k[i++] & 0xFFL) << 16 |
                 (k[i++] & 0xFFL) <<  8 | (k[i++] & 0xFFL);
            if (k.length == 24) // 192-bit key - call fn f once to gen 256 bits
                k1 = f(k4, k3);
            else                // 256-bit key - pack k1 from key data
                k1 = (k[i++] & 0xFFL) << 56 | (k[i++] & 0xFFL) << 48 |
                     (k[i++] & 0xFFL) << 40 | (k[i++] & 0xFFL) << 32 |
                     (k[i++] & 0xFFL) << 24 | (k[i++] & 0xFFL) << 16 |
                     (k[i++] & 0xFFL) <<  8 | (k[i++] & 0xFFL);
        }

        if (DEBUG && debuglevel > 0) debug("makeKey("+ longToString(k4)+","+longToString(k3)+","+longToString(k2)+","+longToString(k1)+")");

        // iterate over all LOKI97 rounds to generate the required subkeys
        for (i = 0; i < NUM_SUBKEYS; i++) {
            f_out = f(k1 + k3 + deltan, k2);
            SK[i] = k4 ^ f_out;		// compute next subkey value using fn f
            k4 = k3;			// exchange the other words around
            k3 = k2;
            k2 = k1;
            k1 = SK[i];
            deltan += DELTA;		// next multiple of delta
            if (DEBUG && debuglevel > 2) debug(" SK["+i+"]="+longToString(SK[i])+"; f="+longToString(f_out));
        }

        if (DEBUG && debuglevel > 7) {
            for (i=0;i<NUM_SUBKEYS;i++) System.out.println("SK"+i+"="+longToString(SK[i]));
            System.out.println();
        }

        if (DEBUG) trace(OUT, "makeKey()");

        return SK;
    }


    //.......................................................................
    /**
     * Encrypt exactly one block of plaintext.
     *
     * @param in          The plaintext.
     * @param inOffset    Index of in from which to start considering data.
     * @param sessionKey  The session key to use for encryption.
     * @return The ciphertext generated from a plaintext using the session key.
     */
    public static byte[]
    blockEncrypt (byte[] in, int inOffset, Object sessionKey) {

        if (DEBUG) trace(IN, "blockEncrypt("+in+", "+inOffset+", "+sessionKey+")");
        long[] SK = (long[]) sessionKey;	// local ref to session key

        // pack input block into 2 longs: L and R
        long L = (in[inOffset++] & 0xFFL) << 56 |
                 (in[inOffset++] & 0xFFL) << 48 |
                 (in[inOffset++] & 0xFFL) << 40 |
                 (in[inOffset++] & 0xFFL) << 32 |
                 (in[inOffset++] & 0xFFL) << 24 |
                 (in[inOffset++] & 0xFFL) << 16 |
                 (in[inOffset++] & 0xFFL) <<  8 |
                 (in[inOffset++] & 0xFFL);
        long R = (in[inOffset++] & 0xFFL) << 56 |
                 (in[inOffset++] & 0xFFL) << 48 |
                 (in[inOffset++] & 0xFFL) << 40 |
                 (in[inOffset++] & 0xFFL) << 32 |
                 (in[inOffset++] & 0xFFL) << 24 |
                 (in[inOffset++] & 0xFFL) << 16 |
                 (in[inOffset++] & 0xFFL) <<  8 |
                 (in[inOffset++] & 0xFFL);

        if (DEBUG && debuglevel > 0) debug("blockEncrypt("+longToString(L)+longToString(R)+")");
        if (DEBUG && debuglevel > 6) System.out.println("PT="+longToString(L)+" "+longToString(R));

        // compute all rounds for this 1 block
        long nR, f_out;
        int k = 0;
        for (int i = 0; i < ROUNDS; i++) {
            nR = R + SK[k++];
            f_out = f(nR, SK[k++]);
            nR += SK[k++];
            R = L ^ f_out;
            L = nR;
            if (DEBUG && debuglevel > 1) debug(" L["+(i+1)+"]="+longToString(L) +
                "; R["+(i+1)+"]="+longToString(R)+"; f(SK("+(k-2)+"))="+longToString(f_out));
            if (DEBUG && debuglevel > 6) System.out.println("CT"+(i+1)+"="+longToString(L)+" "+longToString(R));
        }

        if (DEBUG && debuglevel > 0) debug("  = "+longToString(R)+longToString(L));

        // unpack resulting L & R into out buffer
        byte[] result = {
            (byte)(R >>> 56), (byte)(R >>> 48),
            (byte)(R >>> 40), (byte)(R >>> 32),
            (byte)(R >>> 24), (byte)(R >>> 16),
            (byte)(R >>>  8), (byte) R,
            (byte)(L >>> 56), (byte)(L >>> 48),
            (byte)(L >>> 40), (byte)(L >>> 32),
            (byte)(L >>> 24), (byte)(L >>> 16),
            (byte)(L >>>  8), (byte) L
        };

        if (DEBUG && debuglevel > 6) {
            System.out.println("CT="+toString(result));
            System.out.println();
        }
        if (DEBUG) trace(OUT, "blockEncrypt()");

        return result;
    }


    //.......................................................................
    /**
     * Decrypt exactly one block of ciphertext.
     *
     * @param in          The ciphertext.
     * @param inOffset    Index of in from which to start considering data.
     * @param sessionKey  The session key to use for decryption.
     * @return The plaintext generated from a ciphertext using the session key.
     */
    public static byte[]
    blockDecrypt (byte[] in, int inOffset, Object sessionKey) {

        if (DEBUG) trace(IN, "blockDecrypt("+in+", "+inOffset+", "+sessionKey+")");

        long[] SK = (long[]) sessionKey;	// local ref to session key

        // pack input block into 2 longs: L and R
        long L = (in[inOffset++] & 0xFFL) << 56 |
                 (in[inOffset++] & 0xFFL) << 48 |
                 (in[inOffset++] & 0xFFL) << 40 |
                 (in[inOffset++] & 0xFFL) << 32 |
                 (in[inOffset++] & 0xFFL) << 24 |
                 (in[inOffset++] & 0xFFL) << 16 |
                 (in[inOffset++] & 0xFFL) <<  8 |
                 (in[inOffset++] & 0xFFL);
        long R = (in[inOffset++] & 0xFFL) << 56 |
                 (in[inOffset++] & 0xFFL) << 48 |
                 (in[inOffset++] & 0xFFL) << 40 |
                 (in[inOffset++] & 0xFFL) << 32 |
                 (in[inOffset++] & 0xFFL) << 24 |
                 (in[inOffset++] & 0xFFL) << 16 |
                 (in[inOffset++] & 0xFFL) <<  8 |
                 (in[inOffset++] & 0xFFL);

        if (DEBUG && debuglevel > 0) debug("blockDecrypt("+longToString(L)+longToString(R)+")");
        if (DEBUG && debuglevel > 6) System.out.println("CT="+longToString(L)+" "+longToString(R));

        // compute all rounds for this 1 block
        long nR, f_out;
        int k = NUM_SUBKEYS - 1;
        for (int i = 0; i < ROUNDS; i++) {
            nR = R - SK[k--];
            f_out = f(nR, SK[k--]);
            nR -= SK[k--];
            R = L ^ f_out;
            L = nR;
            if (DEBUG && debuglevel > 1) debug(" L["+(i+1)+"]="+longToString(L) +
                "; R["+(i+1)+"]="+longToString(R)+"; f(SK("+(k+2)+"))="+longToString(f_out));
            if (DEBUG && debuglevel > 6) System.out.println("PT"+(i+1)+"="+longToString(L)+" "+longToString(R));
        }

        if (DEBUG && debuglevel > 0) debug("  = "+longToString(R)+longToString(L));

        // unpack resulting L & R into out buffer
        byte[] result = {
            (byte)(R >>> 56), (byte)(R >>> 48),
            (byte)(R >>> 40), (byte)(R >>> 32),
            (byte)(R >>> 24), (byte)(R >>> 16),
            (byte)(R >>>  8), (byte) R,
            (byte)(L >>> 56), (byte)(L >>> 48),
            (byte)(L >>> 40), (byte)(L >>> 32),
            (byte)(L >>> 24), (byte)(L >>> 16),
            (byte)(L >>>  8), (byte) L
        };

        if (DEBUG && debuglevel > 6) {
            System.out.println("PT="+toString(result));
            System.out.println();
        }
        if (DEBUG) trace(OUT, "blockDecrypt()");

        return result;
    }


    //.......................................................................
    /**
     * Basic symmetric encryption/decryption and a single KAT set tests.
     *
     * @return True iff all tests pass.
     */
    public static boolean self_test() {

        if (DEBUG) trace(IN, "self_test()");

        boolean ok = false;
        try {
            byte[] kb = new byte[] { // Standard LOKI97 Single Triple
                 0,  1,  2,  3,  4,  5,  6,  7,
                 8,  9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] pt = new byte[BLOCK_SIZE];
            int i;

            for (i = 0; i < BLOCK_SIZE; i++)
                pt[i] = (byte) i;

            Object key = makeKey(kb);

            byte[] ct = fromString("75080E359F10FE640144B35C57128DAD");
            byte[] tmp = blockEncrypt(pt, 0, key);
            ok = areEqual(ct, tmp);
            if (!ok) {
                if (DEBUG && debuglevel > 0) {
                    debug("KAT single triple");
                    debug("       key: " + toString(kb));
                    debug(" plaintext: " + toString(pt));
                    debug("ciphertext: " + toString(ct));
                    debug("  computed: " + toString(tmp));
                }
                throw new RuntimeException("Encryption failed");
            }

            tmp = blockDecrypt(ct, 0, key);
            ok = areEqual(pt, tmp);
            if (!ok) {
                if (DEBUG && debuglevel > 0) {
                    debug("KAT single triple");
                    debug("       key: " + toString(kb));
                    debug("ciphertext: " + toString(ct));
                    debug(" plaintext: " + toString(pt));
                    debug("  computed: " + toString(tmp));
                }
                throw new RuntimeException("Decryption failed");
            }

            if (DEBUG && debuglevel > 0) debug("KAT (single triple) OK? " + ok);

            ok = self_test(BLOCK_SIZE);

        } catch (Exception x) {
            if (DEBUG && debuglevel > 0) {
                debug("Exception encountered during self-test: " + x.getMessage());
                x.printStackTrace();
            }
        }

        if (DEBUG && debuglevel > 0) debug("Self-test OK? " + ok);
        if (DEBUG) trace(OUT, "self_test()");

        return ok;
    }


// private LOKI97 methods
//...........................................................................
    
    /** @return The length in bytes of LOKI97 input block. */
    public static int blockSize() { return BLOCK_SIZE; }

    /**
     * Complex highly non-linear round function
     * f(A,B) = Sb(P(Sa(E(KP(A,hi(B))))),lo(B))
     *
     * @param A  64-bit input A
     * @param B  64-bit input B
     * @return The resulting 64-bit function value
     */
    private static long f (long A, long B) {

        // Intermediate values in the computation are:
        //   d = KP(A,B)
        //   e = P(Sa(d))
        //   f = Sb(e,B)

        // Compute d = KP(A,B), where KP is a keyed permutation used to 
        //    exchange corresponding bits in 32-bit words [Al,Ar] 
        //    based on the lower half of B (called Br) (swap if B bit is 1)
        //    KP(A,B) = ((Al & ~Br)|(Ar & Br)) | ((Ar & ~Br)|(Al & Br))

        int Al = (int)(A >>> 32);
        int Ar = (int) A;
        int Br = (int) B;
        long d = ((long)((Al & ~Br) | (Ar & Br)) << 32) |
                 ((long)((Ar & ~Br) | (Al & Br)) & 0xFFFFFFFFL);

        // Compute e = P(Sa(d))
        //    mask out each group of 12 bits for E
        //    then compute first S-box column [S1,S2,S1,S2,S2,S1,S2,S1]
        //    permuting output through P (with extra shift to build full P)

        long e = P[S1[(int)((d >>> 56 | d << 8) & 0x1FFF)] & 0xFF] >>> 7 |
                 P[S2[(int)((d >>> 48)          &  0x7FF)] & 0xFF] >>> 6 |
                 P[S1[(int)((d >>> 40)          & 0x1FFF)] & 0xFF] >>> 5 |
                 P[S2[(int)((d >>> 32)          &  0x7FF)] & 0xFF] >>> 4 |
                 P[S2[(int)((d >>> 24)          &  0x7FF)] & 0xFF] >>> 3 |
                 P[S1[(int)((d >>> 16)          & 0x1FFF)] & 0xFF] >>> 2 |
                 P[S2[(int)((d >>>  8)          &  0x7FF)] & 0xFF] >>> 1 |
                 P[S1[(int)( d                  & 0x1FFF)] & 0xFF];

        // Compute f = Sb(e,B)
        //    where the second S-box column is [S2,S2,S1,S1,S2,S2,S1,S1]
        //    for each S, lower bits come from e, upper from upper half of B

        long f =
            (S2[(int)(((e>>>56) & 0xFF) | ((B>>>53) &  0x700))] & 0xFFL) << 56 |
            (S2[(int)(((e>>>48) & 0xFF) | ((B>>>50) &  0x700))] & 0xFFL) << 48 |
            (S1[(int)(((e>>>40) & 0xFF) | ((B>>>45) & 0x1F00))] & 0xFFL) << 40 |
            (S1[(int)(((e>>>32) & 0xFF) | ((B>>>40) & 0x1F00))] & 0xFFL) << 32 |
            (S2[(int)(((e>>>24) & 0xFF) | ((B>>>37) &  0x700))] & 0xFFL) << 24 |
            (S2[(int)(((e>>>16) & 0xFF) | ((B>>>34) &  0x700))] & 0xFFL) << 16 |
            (S1[(int)(((e>>> 8) & 0xFF) | ((B>>>29) & 0x1F00))] & 0xFFL) <<  8 |
            (S1[(int)(( e       & 0xFF) | ((B>>>24) & 0x1F00))] & 0xFFL);

        if (DEBUG && debuglevel > 3) debug("  f("+longToString(A)+","+longToString(B)+") = "+longToString(f));
        if (DEBUG && debuglevel > 4) debug("   d="+longToString(d)+"; e="+longToString(e));

        return f;
    }


    //.......................................................................
    /** A basic symmetric encryption/decryption test for a given key size. */
    private static boolean self_test (int keysize) {

        if (DEBUG) trace(IN, "self_test("+keysize+")");

        boolean ok = false;
        try {
            byte[] kb = new byte[keysize];
            byte[] pt = new byte[BLOCK_SIZE];
            int i;

            for (i = 0; i < keysize; i++)
                kb[i] = (byte) i;
            for (i = 0; i < BLOCK_SIZE; i++)
                pt[i] = (byte) i;

            if (DEBUG && debuglevel > 6) {
                System.out.println("==========");
                System.out.println();
                System.out.println("KEYSIZE="+(8*keysize));
                System.out.println("KEY="+toString(kb));
                System.out.println();
            }
            Object key = makeKey(kb);

            if (DEBUG && debuglevel > 6) {
                System.out.println("Intermediate Ciphertext Values (Encryption)");
                System.out.println();
            }
            byte[] ct =  blockEncrypt(pt, 0, key);

            if (DEBUG && debuglevel > 6) {
                System.out.println("Intermediate Plaintext Values (Decryption)");
                System.out.println();
            }
            byte[] cpt = blockDecrypt(ct, 0, key);

            ok = areEqual(pt, cpt);
            if (!ok)
                throw new RuntimeException("Symmetric operation failed");
        } catch (Exception x) {
            if (DEBUG && debuglevel > 0) {
                debug("Exception encountered during self-test: " + x.getMessage());
                x.printStackTrace();
            }
        }

        if (DEBUG && debuglevel > 0) debug("Self-test OK? " + ok);
        if (DEBUG) trace(OUT, "self_test()");

        return ok;
    }


//...........................................................................
    /** Encryption/decryption test using the standard single triple.
     *
     *  @return  true if test successful
     */
    public static boolean triple_test() {
	if (TRACE) trace(IN, "triple_test()");
	boolean result = false;
	boolean enok = true, deok = true;
	byte[] keyx = {				// Standard LOKI97 Single Triple
	      0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	     16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	byte[] plain = {
	     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	byte[] cipher = fromString("75080E359F10FE640144B35C57128DAD");
	byte[] temp;

	try {
	    if (DEBUG) debug("SelfTest");
	    // Display and verify single triple test value
	    if (DEBUG) debug("   key: " + toString(keyx));
	    if (DEBUG) debug(" plain: " + toString(plain));
	    if (DEBUG) debug("cipher: " + toString(cipher));

	    Object key = makeKey(keyx);
	    temp =  blockEncrypt(plain, 0, key);	// Test encrypt
	    if (! areEqual(temp, cipher)) enok = false;
	    if (DEBUG) debug("Test encrypt: " + toString(temp)+
		(enok ? "    GOOD" : "    FAILED"));

	    temp = blockDecrypt(cipher, 0, key);	// Test decrypt
	    if (! areEqual(temp, plain)) deok = false;
	    if (DEBUG) debug("Test decrypt: " + toString(temp)+
		(deok ? "    GOOD" : "    FAILED"));
	    result = enok && deok;
	} 
	catch (Exception ex) {
	    if (DEBUG) {
		debug("Exception in triple-test: " + ex.getMessage());
		ex.printStackTrace();
	    }
	}
	if (DEBUG) debug("triple-test OK? " + result);
	if (TRACE) trace(OUT, "triple_test()");
	return result;
    }


// utility static methods
// (copied from cryptix.util.core ArrayUtil and Hex classes)
//...........................................................................
    
    /**
     * Compares two byte arrays for equality.
     *
     * @return true if the arrays have identical contents
     */
    private static boolean areEqual (byte[] a, byte[] b) {
        int aLength = a.length;
        if (aLength != b.length)
            return false;
        for (int i = 0; i < aLength; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    /** Returns a byte array from a string of hexadecimal digits. */
    private static byte[] fromString (String hex) {
        int len = hex.length();
        byte[] buf = new byte[((len + 1) / 2)];
        int i = 0, j = 0;
        if ((len % 2) == 1)
            buf[j++] = (byte) fromDigit(hex.charAt(i++));
        while (i < len) {
            buf[j++] = (byte)(
                (fromDigit(hex.charAt(i++)) << 4) |
                 fromDigit(hex.charAt(i++))
            );
        }
        return buf;
    }

    /**
     * Returns a number from 0 to 15 corresponding to the hex
     * digit <i>ch</i>.
     */
    public static int fromDigit (char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        throw new IllegalArgumentException("Invalid hex digit '"+ch+"'");
    }

    /**
     * Returns a string of 2 hexadecimal digits (most significant
     * digit first) corresponding to the lowest 8 bits of <i>n</i>.
     */
    private static String byteToString (int n) {
        char[] buf = {
            HEX_DIGITS[(n >>> 4) & 0x0F],
            HEX_DIGITS[ n        & 0x0F]
        };
        return new String(buf);
    }

    /**
     * Returns a string of 4 hexadecimal digits (most significant
     * digit first) corresponding to the lowest 16 bits of <i>n</i>.
     */
    private static String shortToString (int n) {
        char[] buf = {
            HEX_DIGITS[(n >>> 12) & 0x0F],
            HEX_DIGITS[(n >>>  8) & 0x0F],
            HEX_DIGITS[(n >>>  4) & 0x0F],
            HEX_DIGITS[ n         & 0x0F]
        };
        return new String(buf);
    }

    /**
     * Returns a string of 16 hexadecimal digits (most significant
     * digit first) corresponding to the long <i>n</i>, which is
     * treated as unsigned.
     */
    private static String longToString(long n) {
        char[] buf = new char[16];
        for (int i = 15; i >= 0; i--) {
            buf[i] = HEX_DIGITS[(int) n & 0x0F];
            n >>>= 4;
        }
        return new String(buf);
    }

    /**
     * Returns a string of hexadecimal digits from a byte array. Each
     * byte is converted to 2 hex symbols.
     */
    private static String toString (byte[] ba) {
        int length = ba.length;
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }


// main(): use to generate the Intermediate Values KAT
//...........................................................................

    public static void main (String[] args) {
        self_test(16);
        self_test(24);
        self_test(32);
	triple_test();
    }
}
