/* $Id: GFp.java,v 1.2 1999/03/20 13:36:09 gelderen Exp $
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
import java.util.Random;

/**
 * Arithmetic operations on elements of the finite field GF(p)
 * 
 * @author    Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 */
public class GFp extends GF implements Cloneable {

    /*
     * CAVEAT: setting DEBUG = true is useful for debugging, but
     * absolutely kills the CPU for excess of checkings.
     */
    protected static final boolean DEBUG = false;

    /**
     * Rabin-Miller certainty used for primality testing
     */
    static final int PRIMALITY_CERTAINTY = 50; // after ANSI X9F1

    /**
     * Create an instance of the zero element of GF(p)
     * 
     * @param   p   size of the prime finite field GF(p)
     * 
     * @exception   ArithmeticException     if p is not a prime > 3 (DEBUG mode only)
     */
    GFp(BigInteger p) throws ArithmeticException {
        if (DEBUG && (!p.isProbablePrime(PRIMALITY_CERTAINTY) || p.compareTo(THREE) <= 0)) {
            throw new ArithmeticException("field size must be prime (larger than 3)");
        }
        q = p;
        v = ZERO;
    }

    /**
     * Create an instance of the element x of GF(p)
     * 
     * @param   p   size of the prime finite field GF(p)
     * @param   x   value of the element of GF(p)
     * 
     * @exception   ArithmeticException     if x is not in range 0 to p - 1 (DEBUG mode only)
     */
    GFp(BigInteger p, BigInteger x) throws ArithmeticException {
        this(p);
        if (DEBUG && (x.signum() < 0 || x.compareTo(q) >= 0)) {
            throw new ArithmeticException("Finite field element is out of range");
        }
        v = x;
    }

    // TODO: implement Octet String to Field Element primitive for GF(p)

    /**
     * Create an instance of the element of GF(p)
     * described by the string val in the given radix
     * 
     * @param   p       size of the prime finite field GF(p)
     * @param   val     description of an element of GF(p)
     * @param   radix   numerical base in which val is written
     * 
     * @exception   NumberFormatException   if val is not in appropriate format
     */
    GFp(BigInteger p, String val, int radix) throws NumberFormatException {
        this(p, new BigInteger(val, radix));
    }

    /**
     * Create an instance of the element of GF(p)
     * described by the string val in hexadecimal
     * 
     * @param   p       size of the prime finite field GF(p)
     * @param   val     description of an element of GF(p)
     * 
     * @exception   NumberFormatException   if val is not in appropriate format
     */
    GFp(BigInteger p, String val) throws NumberFormatException {
        this(p, val, 16);
    }

    /**
     * Create a random element from field GF(p)
     * 
     * @param   p       size of the prime finite field GF(p)
     * @param   rand    cryptographically strong PRNG
     */
    GFp(BigInteger p, SecureRandom rand) {
        // TODO: check if the distribution of values mod q is acceptably uniform
        this(p);
        v = new BigInteger(q.bitLength(), rand).mod(q);
    }

    /**
     * Create a copy of a given finite field element
     * 
     * @param   x   the element to be cloned
     */
    GFp(GFp x) {
        // this(x.q, new BigInteger(x.v.toByteArray()));
        this(x.q, x.v);
    }

    /**
     * Create a random element of the same field as a given one
     * 
     * @param   x       the element defining the base finite field
     * @param   rand    cryptographically strong PRNG
     */
    GFp(GFp x, SecureRandom rand) {
        this(x.q, rand);
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
        return new GFp(this);
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
        return new GFp(q, rand);
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
        return new GFp(q, val, radix);
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
        return new GFp(q, v.add(x.v).mod(q));
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
        if (!x.inSameField(this)) {
            throw new DifferentFieldsException();
        }
        return new GFp(q, v.subtract(x.v).mod(q));
    }

    /**
     * Compute the opposite of this element (i.e. -this)
     * 
     * @return  the opposite of this element (i.e. -this)
     */
    public GF negate() {
        return new GFp(q, v.negate().mod(q));
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
        return new GFp(q, v.multiply(x.v).mod(q));
    }

    /**
     * Compute the square of this element
     * 
     * @return  the square of this element
     */
    public GF square() {
        return new GFp(q, v.multiply(v).mod(q));
    }

    /**
     * Compute the inverse of this element
     * 
     * @return  the inverse of this element if it is invertible (i.e. nonzero)
     * 
     * @exception   ArithmeticException     if this element is not invertible (i.e. zero)
     */
    public GF invert() throws ArithmeticException {
        return new GFp(q, v.modInverse(q));
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
        return new GFp(q, v.multiply(x.v.modInverse(q)).mod(q));
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
            : new GFp(q, v.shiftLeft(n).mod(q));
    }

    /**
     * Compute the right shift of this by n (if n < 0, a left shift is applied)
     * 
     * @param   n   shift amount
     * 
     * @return  this >> n (mod p)
     */
    public GF shiftRight(int n) {
        // this implementation is rather slow; should try to make it faster
        return (n <  0) ? shiftLeft(-n)
            :  (n == 0) ? this
            // : new GFp(q, v.shiftRight(n).mod(q)); // CAVEAT: this is WRONG!
            : new GFp(q, v.multiply(ONE.shiftLeft(n).modInverse(q)).mod(q));
    }

    /**
     * Compute a square root of this element (null if none exists)
     * 
     * @return  a square root of this element, if one exists, or null otherwise
     */
    public GF sqrt() {
        /* Algorithm P1363 A.2.5 - Finding Square Roots Modulo a Prime */
        if (this.isZero()) {
            return this; // zero
        }
        // case I: q mod 4 == 3 (just test bit 1, since bit 0 is 1 because q is odd):
        if (q.testBit(1)) {
            GFp z = new GFp(q, v.modPow(q.shiftRight(2).add(ONE), q));
            // test solution:
            return z.square().equals(this) ? z : null;
        }
        // case II: q mod 8 == 5 (just test bit 2, since bit 1 is 0 as tested above):
        if (q.testBit(2)) {
            BigInteger twog     = v.shiftLeft(1).mod(q);
            BigInteger gamma    = twog.modPow(q.shiftRight(3), q);
            BigInteger i        = twog.multiply(gamma).multiply(gamma).mod(q);
            GFp z = new GFp(q, v.multiply(gamma).multiply(i.subtract(ONE)).mod(q));
            // test solution:
            return z.square().equals(this) ? z : null;
        }
        // case III: q mod 4 == q mod 8 == 1 (bad news: this takes very long to compute...)
        BigInteger k = q.add(ONE).shiftRight(1);
        for (BigInteger P = ONE; /*P.compareTo(q) < 0*/; P = P.add(ONE)) {            // compute the Lucas sequence elements V = V_{(q+1)/2} mod q and Q_0 = this^{(q-1)/4)} mod q:
            BigInteger[] VQ0 = lucas(P, v, k);            // check whether a solution was found:            BigInteger halfV = (VQ0[0].testBit(0) ? VQ0[0].add(q) : VQ0[0]).shiftRight(1);            GFp z = new GFp(q, halfV); // GFp(q, halfV.mod(q));
            if (z.square().equals(this)) {
                return z;
            }
            // check whether no square roots exist:
            if (VQ0[1].compareTo(ONE) > 0 && VQ0[1].compareTo(q.subtract(ONE)) < 0) {                return null; // no square roots exist
            }
        }
    }

    /**
     * Compute the number of square roots (0, 1, or 2) of this element
     * 
     * @return  the number of square roots (0, 1, or 2) of this element
     */
    public int sqrtCount() {
        BigInteger count = v.modPow(q.subtract(ONE).shiftRight(1), q).add(ONE).mod(q);
        /*
        if (count.signum() < 0 || count.compareTo(TWO) > 0) {
            throw new ArithmeticException("Invalid Jacobi symbol in square root count");
        }
        */
        return count.intValue();
    }

    /**
     * Compute the Lucas sequence element (V[k] mod q) and (Q^{Floor[k]/2} mod q)
     * 
     * @param   P   initial value of the U-sequence
     * @param   Q   initial value of the V-sequence
     * @param   k   index of the desired Lucas sequence element
     * 
     * @return  a pair of BigInteger values containing (V[k] mod q)     *          and (Q^{Floor[k]/2} mod q), respectively
     */    private BigInteger[] lucas(BigInteger P, BigInteger Q, BigInteger k) {
        // Algorithm P1363 A.2.4 - Generating Lucas Sequences
        /*
        if (P.signum() <= 0 || Q.signum() <= 0 || k.signum() <= 0) {
            throw new RuntimeException("Lucas sequence undefined for the given arguments");
        }
        */
        BigInteger v_0 = TWO;
        BigInteger v_1 = P;
        BigInteger q_0 = ONE;
        BigInteger q_1 = ONE;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            q_0 = q_0.multiply(q_1).mod(q);
            if (k.testBit(i)) {
                q_1 = q_0.multiply(Q).mod(q);
                v_0 = (v_0.multiply(v_1).subtract(P.multiply(q_0))).mod(q);
                v_1 = (v_1.multiply(v_1).subtract(q_1.shiftLeft(1))).mod(q);
            } else {
                q_1 = q_0;
                v_1 = (v_0.multiply(v_1).subtract(P.multiply(q_0))).mod(q);
                v_0 = (v_0.multiply(v_0).subtract(q_0.shiftLeft(1))).mod(q);
            }
        }        return new BigInteger[] {v_0, q_0};
    }

}
