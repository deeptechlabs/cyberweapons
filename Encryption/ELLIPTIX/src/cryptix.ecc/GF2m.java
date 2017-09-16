/* $Id: GF2m.java,v 1.2 1999/03/20 13:36:09 gelderen Exp $
 *
 * Copyright (C) 1995-1999 Systemics Ltd.
 * on behalf of the Cryptix Development Team. All rights reserved.
 * 
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have 
 * received a copy of the Cryptix General License along with this library; 
 * if not, you can download a copy from http://www.cryptix.org/ .
 */
package cryptix.ecc;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Arithmetic operations on elements of the finite field GF(2<SUP>m</SUP>)<BR>
 * <BR>
 * References:<BR>
 * <BR>
 * R. Schroeppel, H. Orman, S. O'Malley:<BR>
 *        "Fast Key Exchange with Elliptic Curve Systems",<BR>
 *        technical report TR95-03 (University of Arizona).<BR>
 * <BR>
 * E. De Win, S. Mister, B. Preneel, M. Wiener,<BR>
 *        "On the performance of signature schemes based on elliptic curves",<BR>
 *        Algorithmic Number Theory Symposium III, LNCS 1423, J.P. Buhler (Ed.),<BR>
 *        Springer-Verlag, 1998, pp. 252-266.<BR>
 * <BR>
 * E. De Win, A. Bosselaers, S. Vandenberghe, P. De Gersem, J. Vandewalle,<BR>
 *        "A fast software implementation for arithmetic operations in GF(2<SUP>n</SUP>)",<BR>
 *        Advances in Cryptology, Proceedings Asiacrypt'96, LNCS 1163,<BR>
 *        Springer-Verlag, 1996, pp. 65-76.<BR>
 * 
 * @author    Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 */
public class GF2m extends GF {

    /*
     * CAVEAT: setting DEBUG = true is useful for debugging, but
     * absolutely kills the CPU for excess of checkings.
     */
    protected static final boolean DEBUG = false;

    /**
     * Dimension pf the finite field GF(2<SUP>m</SUP>) over GF(2)
     */
    protected int m;
    /**
     * Square root mapping table
     */
    protected static final short sqTab[] = {
        0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
        0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
        0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
        0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
        0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
        0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
        0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
        0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
        0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
        0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
        0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
        0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
        0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
        0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
        0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
        0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
        0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
        0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
        0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
        0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
        0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
        0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
        0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
        0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
        0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
        0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
        0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
        0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
        0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
        0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
        0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
        0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555,
    };

    /**     * Trailing zero count (trailingZeroCnt[i] is the number of     * trailing zero bits in the binary representation of i.
     */
    protected static final byte trailingZeroCnt[] = {
        4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    };

    /**     * Leading zero count (leadingZeroCnt[i] is the number of     * leading zero bits in the binary representation of i.
     */
    protected static final byte leadingZeroCnt[] = {
        4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    
    /**
     * Create an instance of the zero element of GF(2<SUP>m</SUP>)
     * 
     * @param   m   dimension of the binary finite field GF(2<SUP>m</SUP>)
     * 
     * @exception   ArithmeticException     if m <= 0 (DEBUG mode only)
     */
    GF2m(int m) throws ArithmeticException {
        if (DEBUG && m <= 0) {
            throw new ArithmeticException("Invalid dimension for GF(2^m) (m must be positive)");
        }
        this.m = m;
        this.q = ZERO.setBit(m);
        this.v = ZERO;
    }

    /**
     * Create an instance of a specified element of GF(2<SUP>m</SUP>)
     * 
     * @param   m   dimension of the binary finite field GF(2<SUP>m</SUP>)
     * @param   x   value of the element of GF(2<SUP>m</SUP>)
     * 
     * @exception   ArithmeticException     if x is not in range 0 to 2<SUP>m</SUP> - 1 (DEBUG mode only)
     */
    GF2m(int m, BigInteger x) throws ArithmeticException {
        this(m);
        if (DEBUG && (x.signum() < 0 || x.compareTo(q) >= 0)) {
            throw new ArithmeticException("Finite field element is out of range");
        }
        this.v = x;
    }

    /**
     * Create an instance of a specified element of GF(2<SUP>m</SUP>)
     * 
     * @param   m   dimension of the binary finite field GF(2<SUP>m</SUP>)
     * @param   x   value of the element of GF(2<SUP>m</SUP>) represented as a little-endian int[]
     * 
     * @exception   ArithmeticException     if x is not in range 0 to 2<SUP>m</SUP> - 1 (DEBUG mode only)
     */
    GF2m(int m, int[] x) throws ArithmeticException {
        this(m, mapIntArrayToBigInteger(x));
    }

    // TODO: implement Octet String to Field Element primitive for GF(2^m)

    /**
     * Create an instance of the element of GF(2<SUP>m</SUP>)
     * described by the string val in base radix
     * 
     * @param   m       dimension of the binary finite field GF(2<SUP>m</SUP>)
     * @param   val     description of an element of GF(2<SUP>m</SUP>)
     * @param   radix   numerical base in which val is written
     * 
     * @exception   NumberFormatException   if val is not in appropriate format
     */
    GF2m(int m, String val, int radix) throws NumberFormatException {
        this(m, new BigInteger(val, radix));
    }

    /**
     * Create an instance of the element of GF(2<SUP>m</SUP>)
     * described by the string val in hexadecimal
     * 
     * @param   m       dimension of the binary finite field GF(2<SUP>m</SUP>)
     * @param   val description of an element of GF(2<SUP>m</SUP>)
     * 
     * @exception   NumberFormatException   if val is not in appropriate format
     */
    GF2m(int m, String val) throws NumberFormatException {
        this(m, val, 16);
    }

    /**
     * Create a random element from field GF(2<SUP>m</SUP>)
     * 
     * @param   m       dimension of the binary finite field GF(2<SUP>m</SUP>)
     * @param   rand    cryptographically strong PRNG
     */
    GF2m(int m, SecureRandom rand) {
        this(m, new BigInteger(m, rand));
    }

    /**
     * Create a copy of a given finite field element
     * 
     * @param   x   the element to be cloned
     */
    GF2m(GF2m x) {
        this.m = x.m;
        this.q = new BigInteger(x.q.toByteArray());
        this.v = new BigInteger(x.v.toByteArray());
    }

    /**
     * Create a random element of the same field as a given one
     * 
     * @param   x       the element defining the base finite field
     * @param   rand    cryptographically strong PRNG
     */
    GF2m(GF2m x, SecureRandom rand) {
        this.m = x.m;
        this.q = new BigInteger(x.q.toByteArray());
        this.v = new BigInteger(this.m, rand);
    }

    protected static int[] mapBigIntegerToIntArray(BigInteger b) {
        byte[] val = b.toByteArray();
        int[] p = new int[(val.length + 3)/4]; // words needed to store val
        int t = 0, i;
        for (i = val.length; i >= 4; i -= 4) {
            p[t++] = (val[i - 1] & 0xff) ^
                    ((val[i - 2] & 0xff) <<  8) ^
                    ((val[i - 3] & 0xff) << 16) ^
                    ((val[i - 4] & 0xff) << 24);
        }
        // invariant: 0 <= i < 4
        switch (i) {
        case 3:
            p[t++] = (val[2] & 0xff) ^
                    ((val[1] & 0xff) <<  8) ^
                    ((val[0] & 0xff) << 16);
            break;
        case 2:
            p[t++] = (val[1] & 0xff) ^
                    ((val[0] & 0xff) <<  8);
            break;
        case 1:
            p[t++] = (val[0] & 0xff);
            break;
        case 0:
            break;
        }
        return p;
    }

    protected static BigInteger mapIntArrayToBigInteger(int[] p) {
        byte[] w = new byte[1 + 4*p.length];
        w[0] = 0;
        int t = 1;
        for (int i = p.length - 1; i >= 0; i--) {
            int z = p[i];
            w[t++] = (byte)(z >>> 24);
            w[t++] = (byte)(z >>> 16);
            w[t++] = (byte)(z >>>  8);
            w[t++] = (byte)(z);
        }
        return new BigInteger(w);
    }

    /**
     * Create a clone of this element.<BR>
     * <BR>
     * This factory method is intended for use with the "Prototype" design
     * pattern as described by E. Gamma, R. Helm, R. Johnson and J. Vlissides
     * in "Design Patterns - Elements of Reusable Object-Oriented Software",
     * Addison-Wesley (1995).<BR>
     * 
     * @return  a clone of this finite field element
     */
    public Object clone() {
        return new GF2m(this);
    }

    /**
     * Compute a random element in the same field as this.<BR>
     * <BR>
     * This factory method is intended for use with the "Prototype" design
     * pattern as described by E. Gamma, R. Helm, R. Johnson and J. Vlissides
     * in "Design Patterns - Elements of Reusable Object-Oriented Software",
     * Addison-Wesley (1995).
     * 
     * @param   rand    cryptographically strong PRNG
     * 
     * @return  a random element from the same finite field as this
     */
    public GF randomize(SecureRandom rand) {
        return new GF2m(m, rand);
    }

    /**
     * Compute the field element in the same field as this,
     * described by the string val in base radix.<BR>
     * <BR>
     * This factory method is intended for use with the "Prototype" design
     * pattern as described by E. Gamma, R. Helm, R. Johnson and J. Vlissides
     * in "Design Patterns - Elements of Reusable Object-Oriented Software",
     * Addison-Wesley (1995).
     * 
     * @param   val     readable description of a finite field element
     * @param   radix   base in which the val description is given
     * 
     * @return  the field element described by val in base radix     * 
     * @exception   NumberFormatException   if val is not in appropriate format
     */
    public GF translate(String val, int radix) throws NumberFormatException {
        return new GF2m(m, val, radix);
    }

    /**
     * Compute the sum of this finite field element and another one
     * 
     * @param   x   the other finite field element, to be added to this
     * 
     * @return  the sum of this element and x
     * 
     * @exception   DifferentFieldsException    if this element and x
     *              do not belong to the same finite field
     */
    public GF add(GF x) throws DifferentFieldsException {
        if (!x.inSameField(this)) {
            throw new DifferentFieldsException();
        }
        return new GF2m(m, v.xor(x.v));
    }

    /**
     * Compute the difference of this element and another one
     * 
     * @param   x   the other finite field element, to be subtracted from this
     * 
     * @return  the difference of this element and x
     * 
     * @exception   DifferentFieldsException    if this element and x
     *              do not belong to the same finite field
     */
    public GF subtract(GF x) throws DifferentFieldsException {
        return this.add(x);
    }

    /**
     * Compute the opposite of this element (i.e. -this)
     * 
     * @return  the opposite of this element (i.e. -this)
     */
    public GF negate() {
        return this;
    }

    /**
     * Compute the product of this element and another one
     * 
     * @param   x   the other finite field element, to be multiplied with this
     * 
     * @return  the product of this element and x
     * 
     * @exception   DifferentFieldsException    if this element and x
     *              do not belong to the same finite field
     */
    public GF multiply(GF x) throws DifferentFieldsException {
        if (!x.inSameField(this)) {
            throw new DifferentFieldsException();
        }
        if (this.isZero()) {
            return this;
        }
        if (x.isZero()) {
            return x;
        }
        int[] p0 = ((GF2m)x).toIntArray();
        int len0 = p0.length;
        /*
         * to decrease bit fiddling overhead, precompute a table containing
         * the value of x shifted by 0 to 31 bits, then shift only wordwise:
         */
        int[][] p = new int[32][];
        p[0] = p0;
        for (int i = 1; i < 32; i++) {
            int[] pp = new int[len0 + 1];
            pp[0] = p0[0] << i;
            for (int j = 1; j < len0; j++) {
                pp[j] = (p0[j] << i) ^ (p0[j - 1] >>> -i);
            }
            pp[len0] = p0[len0 - 1] >>> -i;
            p[i] = pp;
        }
        int[] a = this.toIntArray();
        int[] t = new int[p[0].length + a.length];
        for (int i = 0; i < t.length; i++) {
            t[i] = 0;
        }
        /*
         * execute polynomial multiplication loop:
         */
        for (int i = 0; i < a.length; i++) {
            int w = a[i];
            /*
             * multiply a word at a time:
             */
            for (int k = 0; k < 32; k++) {
                if (((w >>> k) & 1) != 0) {
                    int[] pk = p[k];
                    for (int j = 0; j < pk.length; j++) {
                        t[i + j] ^= pk[j];
                    }
                }
            }
        }
        return new GF2m(m, reduce(t));
    }

    /**
     * Compute the square of this element
     * 
     * @return  the square of this element
     */
    public GF square() {
        int[] w = this.toIntArray(); // extract value in little-endian order
        int[] s = new int[2*w.length];
        for (int i = 0, j = 0; i < w.length; i++) {
            int u = w[i];
            s[j++] = ((sqTab[(u >>>  8) & 0xff]) << 16) ^ sqTab[ u         & 0xff];
            s[j++] = ((sqTab[ u >>> 24        ]) << 16) ^ sqTab[(u >>> 16) & 0xff];
        }
        return new GF2m(m, reduce(s));
    }

    /*
     * The extended Euclidean algorithm,
     * which maintains the following invariants:
     *     F = BA + XM
     *     G = CA + YM
     * where M is the chosen reduction polinomial for GF(2^m) (the values of X and Y are not stored);
     * hence B = A^(-1) (mod M) when F = 1     *      * This method is only kept here for reference
     */    /*
    public GF euclidInvert() throws ArithmeticException {
        if (this.isZero()) {
            throw new ArithmeticException("Cannot invert the null polynomial");
        }
        BigInteger B = ONE;
        BigInteger C = ZERO;
        BigInteger F = this.v;
        BigInteger G = GFUtil.getIrredPoly(m).toBigInteger();
        while (!F.equals(ONE)) {
            int degF = F.bitLength() - 1;
            int degG = G.bitLength() - 1;
            if (degF < degG) {
                BigInteger swap;
                swap = F; F = G; G = swap;
                swap = B; B = C; C = swap;
                int degX = degF; degF = degG; degG = degX;
            }
            int j = degF - degG;
            F = F.xor(G.shiftLeft(j));
            B = B.xor(C.shiftLeft(j));
        }
        return new GF2m(m, B);
    }    */

    /*
     * The original almost inverse algorithm, as described in 
     * R. Schroeppel, H. Orman, S. O'Malley, "Fast Key Exchange with Elliptic Curve Systems",
     * technical report TR95-03 (University of Arizona), section 4.4.
     * 
     * This algorithm maintains the following invariants:
     *     (x^k)F = BA + XM
     *     (x^k)G = CA + YM
     *     k < 2m
     * where M is the chosen reduction polinomial for GF(2^m) (the values of X and Y are not stored);
     * hence B = (x^k)A^(-1) (mod M) when F = 1, and finally A^(-1) = B >> k (mod M)
     * 
     * Unfortunately, due to the choice of reduction polynomials in P1363 and X9F1
     * (with very low-order middle terms), the original almost-inverse algorithm
     * is generally slower than the Euclidean algorithm.  It is kept here for reference only.
     */
    /*
    public GF almostInverse() throws ArithmeticException {
        if (this.isZero()) {
            throw new ArithmeticException("Cannot invert the null polynomial");
        }
        int k = 0;
        BigInteger B = ONE;
        BigInteger C = ZERO;
        BigInteger F = this.v;
        BigInteger G = GFUtil.makeIrred(m).toBigInteger();
        for (;;) {
            // if F = (x^t)*F' for some t, divide F by (x^t) (i.e. shift F right by t positions):
            int t = F.getLowestSetBit();
            if (t > 0) {
                F = F.shiftRight(t);
                C = C.shiftLeft(t);
                k += t;
            }
            int degF = F.bitLength() - 1;
            if (degF == 0) {
                break;
            }
            int degG = G.bitLength() - 1;
            if (degF < degG) {
                BigInteger swap;
                swap = F; F = G; G = swap;
                swap = B; B = C; C = swap;
                int degX = degF; degF = degG; degG = degX;
            }
            F = F.xor(G);
            B = B.xor(C);
        }
        // now B = (x^k)A^(-1) (mod M); compute A^(-1) = B*(x^(-k)) = B >> k (mod M)
        return new GF2m(m, B).shiftRight(k);
    }
    */

    /**
     * Compute the inverse of this element
     * 
     * @return  the inverse of this element if it is invertible (i.e. nonzero)
     * 
     * @exception   ArithmeticException     if this element is not invertible (i.e. zero)
     */
    public GF invert() throws ArithmeticException {
        /*
         * This method implements the modified almost-inverse algorithm, which
         * is more suitable than the original version for computing reciprocals
         * in GF(2^m) when minimal or near-minimal reduction polynomials are used,
         * as in P1363 and X9F1.
         * 
         * This algorithm maintains the following invariants:
         *     D = (x^h)A (mod M)
         *     (x^k)F = BD + XM
         *     (x^k)G = CD + YM
         *     k < 2m <= h
         * where h >= 2m is arbitrary and M is the chosen reduction polinomial for GF(2^m)
         * (the values of X and Y are not stored); hence B = (x^k)D^(-1) = (x^k)(x^(-h))A^(-1) =
         * (x^(k - h))A^(-1) (mod M) when F = 1, and finally A^(-1) = (x^(h - k))B =
         * B << (h - k) (mod M), since k < 2m <= h.
         * 
         * Thanks to Richard Schroeppel <rcs@cs.arizona.edu> for suggesting this variant.
         */
        if (this.isZero()) {
            throw new ArithmeticException("Cannot invert the null polynomial");
        }
        int k = 0;
        int n = (2*m + 31)/32;
        int h = 32*n; // h is the smaller multiple of 32 that is not smaller than 2m

        int[] B = new int[n]; B[0] = 1; int degB =  0; // B = 1
        int[] C = new int[n]; C[0] = 0; int degC = -1; // C = 0

        int[] G = GFUtil.getIrredPoly(m).toIntArray(); int degG =  m;

        int[] V = this.toIntArray();
        int[] F = new int[V.length + n];
        for (int i = 0; i < n; i++) {
            F[i] = 0;
        }
        System.arraycopy(V, 0, F, n, V.length);
        V = reduce(F);
        F = new int[G.length]; // F and G have the same length
        System.arraycopy(V, 0, F, 0, V.length);
        for (int i = V.length; i < F.length; i++) {
            F[i] = 0;
        }
        int degF = 32*V.length - 1;
        {
            int u = V[V.length - 1];
            if ((u & 0xffff0000) == 0) {
                u <<= 16;
                degF -= 16;
            }
            if ((u & 0xff000000) == 0) {
                u <<= 8;
                degF -= 8;
            }
            if ((u & 0xf0000000) == 0) {
                u <<= 4;
                degF -= 4;
            }
            degF -= leadingZeroCnt[u >>> 28];
        }
        for (;;) {
            // if F = (x^t)*F' for some t, divide F by (x^t) (i.e. shift F right by t positions):

            // compute number of trailing zero bits in F:
            int t;
            for (t = 0; F[t] == 0; t++); // skip over trailing zero words to find F[t] != 0 (the index never goes out of bounds, since F != 0
            int u = F[t], b = 0;
            if ((u & 0xffff) == 0) {
                u >>>= 16;
                b += 16;
            }
            if ((u & 0xff) == 0) {
                u >>>= 8;
                b += 8;
            }
            if ((u & 0xf) == 0) {
                u >>>= 4;
                b += 4;
            }
            b += trailingZeroCnt[u & 0xf];
            // the number of trailing zero bits is 32*t + b (t zero words F[0...t-1] plus b bits in word F[t])
            if (32*t + b > 0) {
                // F >>= 32*t + b:
                if (b != 0) {
                    for (int i = t; i < F.length - 1; i++) {
                        F[i - t] = (F[i] >>> b) ^ (F[i + 1] << -b);
                    }
                    F[F.length - t - 1] = F[F.length - 1] >>> b;
                } else {
                    System.arraycopy(F, t, F, 0, F.length - t);
                }
                for (int i = F.length - t; i < F.length; i++) {
                    F[i] = 0;
                }
                degF -= 32*t + b;
                // C <<= 32*t + b:
                if (b != 0) {
                    for (int i = C.length - 1 - t; i >= 1; i--) {
                        C[i + t] = (C[i] << b) ^ (C[i - 1] >>> -b);
                    }
                    C[t] = C[0] << b;
                } else {
                    System.arraycopy(C, 0, C, t, C.length - t);
                }
                for (int i = 0; i < t; i++) {
                    C[i] = 0;
                }
                degC += 32*t + b;
                // update k:
                k += 32*t + b;
            }
            if (degF == 0) {
                break;
            }
            if (degF < degG) {
                int[] swap;
                int deg;
                swap = F; F = G; G = swap;
                deg = degF; degF = degG; degG = deg;
                swap = B; B = C; C = swap;
                deg = degB; degB = degC; degC = deg;
            }
            for (int i = 0; i < F.length; i++) {
                F[i] ^= G[i];
            }
            for (int i = 0; i < B.length; i++) {
                B[i] ^= C[i];
            }
        }
        // now B = (x^(k - h))A^(-1) (mod M); compute A^(-1) = (x^(h - k))B = B << (h - k) (mod M)
        {
            C = new int[((32*B.length + h - k) + 31)/32]; // words necessary to hold B << (h - k)
            for (int i = 0; i < C.length; i++) {
                C[i] = 0;
            }
            int t = (h - k)/32;
            int b = (h - k)%32;
            // C = B << 32*t + b:
            if (b != 0) {
                for (int i = B.length - 1 - t; i >= 1; i--) {
                    C[i + t] = (B[i] << b) ^ (B[i - 1] >>> -b);
                }
                C[t] = B[0] << b;
            } else {
                System.arraycopy(B, 0, C, t, B.length);
            }
        }
        return new GF2m(m, reduce(C));
    }

    /**
     * Compute the quotient of this element divided by another one
     * 
     * @param   x   the other finite field element, by which this one is to be divided
     * 
     * @return  the quotient of this element divided by x if x is nonzero
     * 
     * @exception   DifferentFieldsException    if this element and x
     *              do not belong to the same finite field
     * @exception   ArithmeticException         if this element is not invertible (i.e. zero)
     */
    public GF divide(GF x) throws DifferentFieldsException, ArithmeticException {
        if (!x.inSameField(this)) {
            throw new DifferentFieldsException();
        }
        if (x.isZero()) {
            throw new ArithmeticException("Cannot divide by the null polynomial");
        }
        // TODO: use the extended Euclidean or almost inverse algorithm directly to divide polynomials
        return this.multiply(x.invert());
    }

    /**
     * Compute the left shift of this by n (if n < 0, a right shift is applied)
     * 
     * @param   n   shift amount
     * 
     * @return  this << n (mod p)
     */
    public GF shiftLeft(int n) {
        return (n <  0) ? shiftRight(-n)
            :  (n == 0) ? this
            : new GF2m(m, reduce(v.shiftLeft(n)));
    }

    /**
     * Compute the right shift of this by n (if n < 0, a left shift is applied)
     * 
     * @param   n   shift amount
     * 
     * @return  this >> n (mod p)
     */
    public GF shiftRight(int n) {
        if (n <  0) {
            return shiftLeft(-n);
        } else if (n == 0) {
            return this;
        } else {
            short[] red = GFUtil.getIrredArray(m);
            BigInteger B = this.v;
            if (red.length == 1) {
                int k = red[0]; // reduction polynomial is x^m + x^k + 1
                BigInteger mask = ZERO.setBit(k).subtract(ONE);
                while (n > 0) {
                    int t;
                    if (!B.testBit(0) && (t = B.getLowestSetBit()) >= k) {
                        if (t > n) {
                            t = n;
                        }
                    } else {
                        t = k;
                        if (t > n) {
                            t = n;
                            mask = ZERO.setBit(n).subtract(ONE);
                        }
                        /*
                         * shift in chunks of t bits by adding to B(x) its t low-order bits
                         * multiplied by the reduction polynomial M(x) = (x^m + x^k + 1), i.e.
                         * B(x) = B[t-1..0](x) * M(x) (mod M(x))
                         */
                        BigInteger low = B.and(mask);
                        B = B.xor(low.shiftLeft(k)).xor(low.shiftLeft(m));
                    }
                    B = B.shiftRight(t); // division by (x^t) is exact
                    n -= t;
                }
            } else {
                int k3 = red[2], k2 = red[1], k1 = red[0]; // reduction polynomial is x^m + x^k3 + x^k2 + x^k1 + 1
                BigInteger mask = ZERO.setBit(k1).subtract(ONE);
                while (n > 0) {
                    int t;
                    if (!B.testBit(0) && (t = B.getLowestSetBit()) >= k1) {
                        if (t > n) {
                            t = n;
                        }
                    } else {
                        t = k1;
                        if (t > n) {
                            t = n;
                            mask = ZERO.setBit(n).subtract(ONE);
                        }
                        /*
                         * shift in chunks of t bits by adding to B(x) its t low-order bits
                         * multiplied by the reduction polynomial M(x) = (x^m + x^k3 + x^k2 + x^k1 + 1), i.e.
                         * B(x) = B[t-1..0](x) * M(x) (mod M(x))
                         */
                        BigInteger low = B.and(mask);
                        B = B.xor(low.shiftLeft(k1)).xor(low.shiftLeft(k2)).xor(low.shiftLeft(k3)).xor(low.shiftLeft(m));
                    }
                    B = B.shiftRight(t); // division by (x^t) is exact
                    n -= t;
                }
            }
            return new GF2m(m, B);
        }
    }

    /**
     * Compute the square root of this element
     * 
     * @return  the square root of this element     */
    public GF sqrt() {
        /*
        GF w = this;
        for (int i = 0; i < m - 1; i++) {
            w = w.square();
        }
        return w;
        */
        int[] w = this.toIntArray(); // extract value in little-endian order
        for (int c = 0; c < m - 1; c++) {
            int[] s = new int[2*w.length];
            for (int i = 0, j = 0; i < w.length; i++) {
                int u = w[i];
                s[j++] = ((sqTab[(u >>>  8) & 0xff]) << 16) ^ sqTab[ u         & 0xff];
                s[j++] = ((sqTab[ u >>> 24        ]) << 16) ^ sqTab[(u >>> 16) & 0xff];
            }
            w = reduce(s);
        }
        return new GF2m(m, w);
    }

    /**
     * Convert this field element to a little-endian int[]
     * 
     * @return  this field element converted to a little-endian int[]
     */
    protected int[] toIntArray() {
        byte[] val = v.toByteArray();
        int[] p = new int[(val.length + 3)/4]; // words needed to store val
        int t = 0, i;
        for (i = val.length; i >= 4; i -= 4) {
            p[t++] = (val[i - 1] & 0xff) ^
                    ((val[i - 2] & 0xff) <<  8) ^
                    ((val[i - 3] & 0xff) << 16) ^
                    ((val[i - 4] & 0xff) << 24);
        }
        // invariant: 0 <= i < 4
        switch (i) {
        case 3:
            p[t++] = (val[2] & 0xff) ^
                    ((val[1] & 0xff) <<  8) ^
                    ((val[0] & 0xff) << 16);
            break;
        case 2:
            p[t++] = (val[1] & 0xff) ^
                    ((val[0] & 0xff) <<  8);
            break;
        case 1:
            p[t++] = (val[0] & 0xff);
            break;
        case 0:
            break;
        }
        return p;
    }

    /**
     * Convert this field element to compact polynomial format
     * 
     * @return  a string containing this element in polynomial format
     */
    public String toPolyString() {
        String result = new String();
        String sep = "";
        for (int deg = v.bitLength() - 1; deg >= 0; deg--) {
            if (v.testBit(deg)) {
                if (deg > 1) {
                    result += sep + "x^" + deg;
                } else if (deg == 1) {
                    result += sep + "x";
                } else { // deg == 0
                    result += sep + "1";
                }
                sep = " + ";
            }
        }
        return (sep.length() == 0) ? "0" : result;
    }

    /**
     * Reduce val by the default reduction polynomial for GF(2<SUP>m</SUP>)
     * 
     * @param   val BigInteger representation of an element from GF(2<SUP>m</SUP>)
     * 
     * @return  the element represented by val reduced by the default GF(2<SUP>m</SUP>) reduction polynomial
     */
    protected int[] reduce(int[] pp) {
        /*
         * The modular reduction algorithm is described in 
         * R. Schroeppel, H. Orman, S. O'Malley, "Fast Key Exchange with Elliptic Curve Systems",
         * technical report TR95-03 (University of Arizona), section 4.3.
         */
        int[] p = new int[pp.length];
        System.arraycopy(pp, 0, p, 0, pp.length);
        short[] red = GFUtil.getIrredArray(m);
        if (red.length == 1) {
            int k = red[0], // reduction polynomial is x^m + x^k + 1
                offsetk = (m - k)/32, shiftk = (m - k)%32,
                offsetm = (m    )/32, shiftm = (m    )%32;
            for (int h = 32*p.length - 1; h >= m; h -= m - k) {
                /*
                 * within this loop, h is the highest possible degree
                 * of the running value of the polynomial being reduced,
                 * and is decreased by m - k at each step;
                 */
                int lowBit = h - (m - k) + 1; // index of the lowest bit cleared in this step
                if (lowBit < m) {
                    lowBit = m;
                }
                int lox = lowBit/32; // index of the word containing lowBit
                int w, i;
                // reduce in 32-bit chunks:
                for (int r = h/32; r > lox; r--) {
                    /*
                     * at this step, eliminate all bits in the word
                     * containing the r-th bit, i.e. r/32+31..r/32;
                     * this is safe because p[r] does contains only
                     * bits of order higher than that of lowBit:
                     */
                    w = p[r]; p[r] = 0;
                    i = r - offsetm;
                    if (shiftm > 0) {
                        p[i  ] ^= w >>> shiftm;
                        p[i-1] ^= w << -shiftm;
                    } else {
                        p[i  ] ^= w;
                    }
                    i = r - offsetk;
                    if (shiftk > 0) {
                        p[i  ] ^= w >>> shiftk;
                        p[i-1] ^= w << -shiftk;
                    } else {
                        p[i  ] ^= w;
                    }
                }
                // reduce last word fragment, if any:
                int mask = 0xffffffff << (lowBit%32);
                w = p[lox] & mask; p[lox] &= (0xffffffff ^ mask);
                i = lox - offsetm;
                if (shiftm > 0) {
                    p[i  ] ^= w >>> shiftm;
                    if (i > 0) {
                        p[i-1] ^= w << -shiftm;
                    }
                } else {
                    p[i  ] ^= w;
                }
                i = lox - offsetk;
                if (shiftk > 0) {
                    p[i  ] ^= w >>> shiftk;
                    if (i > 0) {
                        p[i-1] ^= w << -shiftk;
                    }
                } else {
                    p[i  ] ^= w;
                }
            }
        } else {
            int k3 = red[2], k2 = red[1], k1 = red[0], // reduction polynomial is x^m + x^k3 + x^k2 + x^k1 + 1
                offset3 = (m - k3)/32, shift3 = (m - k3)%32,
                offset2 = (m - k2)/32, shift2 = (m - k2)%32,
                offset1 = (m - k1)/32, shift1 = (m - k1)%32,
                offsetm = (m     )/32, shiftm = (m     )%32;
            for (int h = 32*p.length - 1; h >= m; h -= m - k3) {
                /*
                 * within this loop, h is the highest possible degree
                 * of the running value of the polynomial being reduced,
                 * and is decreased by m - k3 at each step;
                 */
                int lowBit = h - (m - k3) + 1; // index of the lowest bit cleared in this step
                if (lowBit < m) {
                    lowBit = m;
                }
                int lox = lowBit/32; // index of the word containing lowBit
                int w, i;
                // reduce in 32-bit chunks:
                for (int r = h/32; r > lox; r--) {
                    /*
                     * at this step, eliminate all bits in the word
                     * containing the r-th bit, i.e. r/32+31..r/32;
                     * this is safe because p[r] does contains only
                     * bits of order higher than that of lowBit:
                     */
                    w = p[r]; p[r] = 0;
                    i = r - offsetm;
                    if (shiftm > 0) {
                        p[i  ] ^= w >>> shiftm;
                        p[i-1] ^= w << -shiftm;
                    } else {
                        p[i  ] ^= w;
                    }
                    i = r - offset1;
                    if (shift1 > 0) {
                        p[i  ] ^= w >>> shift1;
                        p[i-1] ^= w << -shift1;
                    } else {
                        p[i  ] ^= w;
                    }
                    i = r - offset2;
                    if (shift2 > 0) {
                        p[i  ] ^= w >>> shift2;
                        p[i-1] ^= w << -shift2;
                    } else {
                        p[i  ] ^= w;
                    }
                    i = r - offset3;
                    if (shift3 > 0) {
                        p[i  ] ^= w >>> shift3;
                        p[i-1] ^= w << -shift3;
                    } else {
                        p[i  ] ^= w;
                    }
                }
                // reduce last word fragment, if any:
                int mask = 0xffffffff << (lowBit%32);
                w = p[lox] & mask; p[lox] &= (0xffffffff ^ mask);
                i = lox - offsetm;
                if (shiftm > 0) {
                    p[i  ] ^= w >>> shiftm;
                    if (i > 0) {
                        p[i-1] ^= w << -shiftm;
                    }
                } else {
                    p[i  ] ^= w;
                }
                i = lox - offset1;
                if (shift1 > 0) {
                    p[i  ] ^= w >>> shift1;
                    if (i > 0) {
                        p[i-1] ^= w << -shift1;
                    }
                } else {
                    p[i  ] ^= w;
                }
                i = lox - offset2;
                if (shift2 > 0) {
                    p[i  ] ^= w >>> shift2;
                    if (i > 0) {
                        p[i-1] ^= w << -shift2;
                    }
                } else {
                    p[i  ] ^= w;
                }
                i = lox - offset3;
                if (shift3 > 0) {
                    p[i  ] ^= w >>> shift3;
                    if (i > 0) {
                        p[i-1] ^= w << -shift3;
                    }
                } else {
                    p[i  ] ^= w;
                }
            }
        }
        // there are at most (m + 31)/32 valid words
        int len = (p.length <= (m + 31)/32) ? p.length : (m + 31)/32;
        // TODO: solve the sign problem when mapping int[] to BigInteger
        int[] result = new int[len];
        System.arraycopy(p, 0, result, 0, len);
        return result;
    }

    protected byte[] reduce(byte[] val) {
        // map byte[] val to int[] p:
        int[] p = new int[(val.length + 3)/4]; // words needed to store val
        int t = 0, i;
        for (i = val.length; i >= 4; i -= 4) {
            p[t++] = (val[i - 1] & 0xff) ^
                    ((val[i - 2] & 0xff) <<  8) ^
                    ((val[i - 3] & 0xff) << 16) ^
                    ((val[i - 4] & 0xff) << 24);
        }
        // invariant: 0 <= i < 4
        switch (i) {
        case 3:
            p[t++] = (val[2] & 0xff) ^
                    ((val[1] & 0xff) <<  8) ^
                    ((val[0] & 0xff) << 16);
            break;
        case 2:
            p[t++] = (val[1] & 0xff) ^
                    ((val[0] & 0xff) <<  8);
            break;
        case 1:
            p[t++] = (val[0] & 0xff);
            break;
        case 0:
            break;
        }
        p = reduce(p);
        // there are at most (m + 31)/32 valid words
        int len = (p.length <= (m + 31)/32) ? p.length : (m + 31)/32;
        byte[] result = new byte[1 + 4*len]; // put a leading zero byte to ensure that the number is nonnegative
        result[0] = 0;
        t = 1;
        for (i = len - 1; i >= 0; i--) {
            int w = p[i];
            result[t++] = (byte)(w >>> 24);
            result[t++] = (byte)(w >>> 16);
            result[t++] = (byte)(w >>>  8);
            result[t++] = (byte)(w);
        }
        return result;
    }

    protected BigInteger reduce(BigInteger val) {
        return new BigInteger(reduce(val.toByteArray()));
    }

    /**
     * Convert this element from another polynomial basis to the default GF(2<SUP>m</SUP>) basis
     * 
     * @param   fromPoly    irreducible polynomial used for current basis
     * 
     * @return  this element expressed in the new polynomial basis
     */
    public GF fromBasis(GF fromPoly) {
        // TODO: implement change of basis
        throw new RuntimeException("Change of basis not yet implemented");
    }

    /**
     * Convert this element from the default GF(2<SUP>m</SUP>) basis to another polynomial basis
     * 
     * @param   toPoly  irreducible polynomial used for changed basis
     * 
     * @return  this element expressed in the new polynomial basis
     */
    public GF toBasis(GF toPoly) {
        // TODO: implement change of basis
        throw new RuntimeException("Change of basis not yet implemented");
    }

    /**
     * Compute the trace of this element
     * 
     * @return  the trace of this element
     */
    public int trace() {
        // CAVEAT: this algorithm is very slow!
        short[] tab = GFUtil.getTraceTable(m);
        if (tab != null) {
            /*
             * The trace table lists the degrees d of all monomials such that Tr(x^d) = 1;
             * since this = SUM_i{this_i * x^i} and the trace function is linear,
             * we have Tr(this) = SUM_i{this_i * Tr(x^i)} = SUM_{i in tab}{this_i}
             */
            int tr = 0;
            for (int i = 0; i < tab.length; i++) {
                if (v.testBit(tab[i])) {
                    tr ^= 1;
                }
            }
            return tr;
        } else {
            // bad luck: must compute trace the slow way
            GF t = this;
            for (int i = 1; i < m; i++) {
                t = t.square().add(this);
            }
            if (DEBUG && !(t.isZero() || t.isOne())) {
                throw new RuntimeException("LOGIC ERROR IN TRACE");
            }
            return t.getBit(0);
        }
    }

    /**
     * Compute a solution of z<SUP>2</SUP> + z = this, if such solution exists.
     * Remark: if z is a solution, the other one (there are only two) is z + 1     *      * @return  a solution of z<SUP>2</SUP> + z = this, if such solution exists,     *          otherwise null
     */
    public GF quadSolve() {
        /*
         * The equation z^2 + z = this over GF(2^m) has a solution iff Tr(this) = 0.
         * If m is odd, then a solution z is given by the half-trace of this:
         *        Set z := this.
         *        For i from 1 to (m - 1)/2 do
         *            Set z := z^2.
         *            Set z := z^2 + this.
         *        Return z.
         * If m is even, the following algorithm computes a solution z efficiently:
         *        Set t := <random element of trace 1 (see below)>.
         *        Set z := 0, w := this.
         *        For i from 1 to m - 1 do
         *            Set z := z^2 + t*(w^2).
         *            Set w := w^2 + this.
         *        Return z.
         * A suitable element of trace 1 is computed by the following algorithm:
         *        For i from 0 to m - 1 do
         *            Set t := (x^i).
         *            If Tr(t) == 1 then stop.
         *        Return t.
         */
        // check if a solution exists:
        if (trace() != 0) {
            return null; // no solution
        }
        GF z;
        if ((m & 1) == 1) {
            // m is odd
            // TODO: implement this section with table lookup (like trace computation)
            z = this;
            for (int i = (m - 1)/2; i > 0; i--) {
                z = z.square().square().add(this);
            }
        } else {
            // m is even
            // TODO: drop this section if composite m is excluded from X9F1/P1363
            GF2m t = null;
            short[] tab = GFUtil.getTraceTable(m);
            if (tab != null) {
                // a suitable element of trace 1 is given by (x^tab[0])
                t = new GF2m(m, ZERO.setBit(tab[0]));
            } else {
                // bad luck: must compute the desired element the slow way
                for (int i = 0; i < m; i++) {
                    t = new GF2m(m, ZERO.setBit(i));
                    if (t.trace() == 1) {
                        break;
                    }
                }
            }
            z = new GF2m(m);
            GF w = this;
            for (int i = 1; i < m; i++) {
                w = w.square();
                z = z.square().add(t.multiply(w));
                w = w.add(this);
            }
        }
        // check validity:
        if (DEBUG && !z.square().add(z).add(this).isZero()) {
            throw new RuntimeException("LOGIC ERROR IN QUAD SOLVING");
        }
        return z;
    }

}
