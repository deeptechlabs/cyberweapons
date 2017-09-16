/* $Id: GF.java,v 1.2 1999/03/20 13:36:08 gelderen Exp $
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
 * The GF class is an abstraction for arithmetic operations on elements of a finite field GF(q)
 * 
 * @author    Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 */
public abstract class GF {

    /**
     * Size of the finite field GF(q)
     */
    protected BigInteger q;

    /**
     * Internal representation of this element
     */
    protected BigInteger v;

    /**
     * Convenient BigInteger constants
     */
    protected static final BigInteger
        ZERO    = BigInteger.valueOf(0L),
        ONE     = BigInteger.valueOf(1L),
        TWO     = BigInteger.valueOf(2L),
        THREE   = BigInteger.valueOf(3L);

    /**
     * Check if this point is equal to a given object     *      * @param   x   the field element to be compared to this     *      * @return  true if this element is equal to x, otherwise false
     */
    public boolean equals(Object x) {
        return x instanceof GF            && q.equals(((GF)x).q)            && v.equals(((GF)x).v)            ;
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
    public abstract Object clone();

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
    public abstract GF randomize(SecureRandom rand);

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
    public abstract GF translate(String val, int radix) throws NumberFormatException ;

    /**
     * Return the size q of the underlying finite field GF(q)     * 
     * @return  the size q of the underlying finite field GF(q)
     */
    public BigInteger fieldSize() {
        return q;
    }

    /**
     * Check if this element is the addition neutral element ("zero") of GF(q)     *      * @return  true if this element is zero, otherwise false
     */
    public boolean isZero() {
        return v.signum() == 0;
    }

    /**
     * Check if this element is the multiplication neutral element ("one") of GF(q)     *      * @return  true if this element is one, otherwise false
     */
    public boolean isOne() {
        return v.compareTo(ONE) == 0;
    }

    /**
     * Check if this element is in the same field as another one     * 
     * @param   x   the other field element
     *      * @return  true if this element and x are in the same field, otherwise false
     */
    public boolean inSameField(GF x) {
        return x.fieldSize().equals(q); // this is a consequence of Kronecker's theorem
    }

    /**
     * Return the k-th bit of this point     * 
     * @return  the k-th bit of this point     */
    public int getBit(int k) {
        return v.testBit(k) ? 1 : 0;
    }

    /**
     * Compute a field element which differs from this element at most
     * at the k-th bit, which is set to the least significant bit of b
     */
    public GF setBit(int k, int b) {
        GF result = (GF)clone();
        result.v = ((b & 1) == 1) ? v.setBit(k) : v.clearBit(k);
        return result;
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
    public abstract GF add(GF x) throws DifferentFieldsException;

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
    public abstract GF subtract(GF x) throws DifferentFieldsException;

    /**
     * Compute the opposite of this element (i.e. -this)
     * 
     * @return  the opposite of this element (i.e. -this)
     */
    public abstract GF negate();

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
    public abstract GF multiply(GF x) throws DifferentFieldsException;

    /**
     * Compute the square of this element
     * 
     * @return  the square of this element
     */
    public abstract GF square();

    /**
     * Compute the inverse of this element
     * 
     * @return  the inverse of this element if it is invertible (i.e. nonzero)
     * 
     * @exception   ArithmeticException     if this element is not invertible (i.e. zero)
     */
    public abstract GF invert() throws ArithmeticException;

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
    public abstract GF divide(GF x) throws DifferentFieldsException, ArithmeticException;

    /**
     * Compute the left shift of this by n (if n < 0, a right shift is applied)
     * 
     * @param   n   shift amount
     * 
     * @return  this << n (mod p)
     */
    public abstract GF shiftLeft(int n);
    // TODO: check if shiftLeft is really necessary (comment out if not)

    /**
     * Compute the right shift of this by n (if n < 0, a left shift is applied)
     * 
     * @param   n   shift amount
     * 
     * @return  this >> n (mod p)
     */
    public abstract GF shiftRight(int n);
    // TODO: check if shiftRight is really necessary (comment out if not)

    /**
     * Compute a square root of this element (null if none exists)
     * 
     * @return  a square root of this element, if one exists, or null otherwise
     */
    public abstract GF sqrt();

    /**
     * Convert this element to a BigInteger, according to the X9F1/P1363 conversion rules
     * 
     * @return  this element converted to a BigInteger
     */
    public BigInteger toBigInteger() {
        return v; // new BigInteger(v.toByteArray());
    }

    /**
     * Convert this element to an octet string, according to the X9F1/P1363 conversion rules
     * 
     * @return  this element converted to an octet string
     */
    public byte[] toByteArray() {
        return v.toByteArray();
    }

    /**
     * Convert this element to human-readable (hexadecimal) string format
     * 
     * @return  this element converted to human-readable (hexadecimal) string format
     */
    public String toString() {
        return v.toString(16);
    }

    /**
     * Convert this element to human-readable format in the given radix
     * 
     * @return  this element converted to human-readable format in the given radix
     */
    public String toString(int radix) {
        return v.toString(radix);
    }

}
