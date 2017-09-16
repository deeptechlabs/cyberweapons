/* $Id: EPoint.java,v 1.2 1999/03/20 13:36:08 gelderen Exp $
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
 * The EPoint class is an abstraction for the arithmetic group of points
 * on an elliptic curve.<BR>
 * <BR>
 * A point of an elliptic curve is only meaningful when suitably attached
 * to some curve.  Hence, there must be no public means to create a point
 * by itself (i.e. concrete subclasses of EPoint shall have no public
 * constructor); the proper way to do this is to invoke the factory method
 * pointFactory() of the desired EC subclass.<BR>
 * <BR>
 * This is a direct application of the "Factory Method" design pattern
 * as described by E. Gamma, R. Helm, R. Johnson and J. Vlissides in
 * "Design Patterns - Elements of Reusable Object-Oriented Software",
 * Addison-Wesley (1995), pp. 107-116, especially Consequence #2
 * ("Connects parallel class hierarchies", pp. 109-110).<BR>
 * <BR>
 * This class must inherit from Cloneable to allow for the application of
 * the "Prototype" design pattern (see reference above) for uses of EPoint
 * where the actual nature of a curve point does not matter (e.g. in
 * general tests of implementation correctness).
 * 
 * @author    Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 */
public abstract class EPoint implements Cloneable {

    protected static final BigInteger THREE = BigInteger.valueOf(3L);

    /**
     * The underlying elliptic curve, given by its parameters
     */
    EC E;

    /**
     * Flag/mask for compressed point representation
     */
    public static final int COMPRESSED  = 2;

    /**
     * Flag/mask for expanded point representation
     */
    public static final int EXPANDED    = 4;
    /**
     * Flag/mask for hybrid point representation
     */
    public static final int HYBRID      = COMPRESSED | EXPANDED;

    /**
     * Create a clone of this point     *      * @return  a clone of this point
     */
    public abstract Object clone();

    /**
     * Check whether this point belongs to a given elliptic curve
     *
     * @param   curve   the elliptic curve to which pertinence is to be tested
     */
    public boolean isIn(EC curve) {
        return curve.contains(this);
    }

    /**
     * Check whether this is the point at infinity (i.e. the EC group zero element)     *      * @return  true if this is the point at infinity, otherwise false
     */
    public abstract boolean isZero();

    /**
     * Check whether Q lays on the same curve as this point
     *
     * @param   Q   an elliptic curve point
     */
    public boolean isOnSameCurve(EPoint Q) {
        return E.q.equals(Q.E.q)
            && E.a.equals(Q.E.a)
            && E.b.equals(Q.E.b)
            && E.k.equals(Q.E.k)
            && E.r.equals(Q.E.r)
            //  && E.G.equals(Q.E.G) // caveat: resist the temptation to uncomment this line! :-)            ;
    }

    /**
     * Compare this point to a given object
     *
     * @param   Q   the elliptic curve point to be compared to this     *      * @return  true if this point and Q are equal, otherwise false
     */
    public abstract boolean equals(Object Q);

    /**
     * Compute a random point on the same curve as this     *      * @return  a random point on the same curve as this
     */
    public abstract EPoint randomize(SecureRandom rand);

    /**
     * Normalize this point
     * 
     * @return  a normalized point equivalent to this
     */
    public abstract EPoint normalize();

    /**
     * Compute -this     *      * @return  -this
     */
    public abstract EPoint negate();

    /**
     * Compute this + Q
     *     * @return  this + Q     * 
     * @param   Q   an elliptic curve point     * 
     * @exception   DifferentCurvesException    if this and Q lay on different curves
     */
    public abstract EPoint add(EPoint Q) throws DifferentCurvesException;

    /**
     * Compute this - Q
     *     * @return  this - Q     * 
     * @param   Q   an elliptic curve point     * 
     * @exception   DifferentCurvesException    if this and Q lay on different curves
     */
    public abstract EPoint subtract(EPoint Q) throws DifferentCurvesException;

    /**
     * Compute 2*this     *      * @return  2*this
     */
    public abstract EPoint twice();

    /**
     * Compute k*this
     * 
     * @param   k   scalar by which this point is to be multiplied
     * 
     * @return  k*this
     */
    public EPoint multiply(BigInteger k) {
        /*
         * This method implements the the sliding window multiplication algorithm
         * with the scalar factor in non-adjacent form (NAF)
         * 
         * References:
         * 
         * E. De Win, S. Mister, B. Preneel, M. Wiener,
         *      "On the performance of signature schemes based on elliptic curves",
         *      Algorithmic Number Theory Symposium III, LNCS 1423, J.P. Buhler (Ed.),
         *      Springer-Verlag, 1998, pp. 252-266.
         *
         * Alfred J. Menezes, Paul C. van Oorschot, Scott A. Vanstone,
         *      "Handbook of Applied Cryptography", CRC Press (1997),
         *      section 14.6 (Exponentiation), especially algorithm 14.85
         */
        int signum = k.signum();
        if (signum == 0 || this.isZero()) {
            return E.infinity;
        }
        EPoint P = this;
        if (signum <  0) {
            P = P.negate();
            k = k.negate();
        }
        P = P.normalize(); // reduce the cost of projective addition
        /*
         * ideally, k should be reduced mod the order of P here for efficiency,
         * but since the order is generally not known the reduction is not done.
         */
        BigInteger h = k.multiply(THREE);
        EPoint Q = Q = (EPoint)P.clone();
        EPoint P2 = P .twice().normalize(); EPoint M  = P .negate();
        EPoint P3 = P .add(P2).normalize(); EPoint M3 = P3.negate();
        EPoint P5 = P3.add(P2).normalize(); EPoint M5 = P5.negate();
        EPoint P7 = P5.add(P2).normalize(); EPoint M7 = P7.negate();
        EPoint P9 = P7.add(P2).normalize(); EPoint M9 = P9.negate();
        int i = h.bitLength() - 2;
        while (i >= 4) {
            if (h.testBit(i) && !k.testBit(i)) { // 1 0 x x
                if (        h.testBit(i - 2) && !k.testBit(i - 2)) { //  1 0  1  0
                    Q = Q.twice().twice().twice().add(P5).twice();
                } else if (!h.testBit(i - 2) &&  k.testBit(i - 2)) { //  1 0 -1  0
                    Q = Q.twice().twice().twice().add(P3).twice();
                } else if ( h.testBit(i - 3) && !k.testBit(i - 3)) { //  1 0  0  1
                    Q = Q.twice().twice().twice().twice().add(P9);
                } else if (!h.testBit(i - 3) &&  k.testBit(i - 3)) { //  1 0  0 -1
                    Q = Q.twice().twice().twice().twice().add(P7);
                } else {                                             //  1 0  0  0
                    Q = Q.twice().add(P).twice().twice().twice();
                }
                i -= 4;
            } else if (!h.testBit(i) && k.testBit(i)) { // -1 0 x x
                if (       !h.testBit(i - 2) &&  k.testBit(i - 2)) { // -1 0 -1  0
                    Q = Q.twice().twice().twice().add(M5).twice();
                } else if ( h.testBit(i - 2) && !k.testBit(i - 2)) { // -1 0  1  0
                    Q = Q.twice().twice().twice().add(M3).twice();
                } else if (!h.testBit(i - 3) &&  k.testBit(i - 3)) { // -1 0  0 -1
                    Q = Q.twice().twice().twice().twice().add(M9);
                } else if ( h.testBit(i - 3) && !k.testBit(i - 3)) { // -1 0  0  1
                    Q = Q.twice().twice().twice().twice().add(M7);
                } else {                                             // -1 0  0  0
                    Q = Q.twice().add(M).twice().twice().twice();
                }
                i -= 4;
            } else { // 0 x x x
                Q = Q.twice();
                i--;
            }
        }
        while (i >= 1) {
            Q = Q.twice();
            if (        h.testBit(i) && !k.testBit(i)) {
                Q = Q.add(P);
            } else if (!h.testBit(i) &&  k.testBit(i)) {
                Q = Q.subtract(P);
            }
            i--;
        }
        return Q;
    }

    /*
    // Using a 5-bit window.  The tradeoff between code size
    // and speed gain is not favorable compared to a 4-bit window.
    public EPoint multiply(BigInteger k) {
        int signum = k.signum();
        if (signum == 0 || this.isZero()) {
            return E.infinity;
        }
        EPoint P = this;
        if (signum <  0) {
            P = P.negate();
            k = k.negate();
        }
        P = P.normalize();
        BigInteger h = k.multiply(THREE);
        EPoint Q = (EPoint)P.clone();
        EPoint P2  = P  .twice().normalize();
        EPoint P3  = P  .add(P2).normalize();
        EPoint P5  = P3 .add(P2).normalize();
        EPoint P7  = P5 .add(P2).normalize();
        EPoint P9  = P7 .add(P2).normalize();
        EPoint P11 = P9 .add(P2).normalize();
        EPoint P13 = P11.add(P2).normalize();
        EPoint P15 = P13.add(P2).normalize();
        EPoint P17 = P15.add(P2).normalize();
        EPoint P19 = P17.add(P2).normalize();
        EPoint P21 = P19.add(P2).normalize();
        int i = h.bitLength() - 2;
        while (i >= 5) {
            if (h.testBit(i) && !k.testBit(i)) { // 1 0 x x x
                if (        h.testBit(i - 2) && !k.testBit(i - 2)) { //  1 0  1  0 x
                    if (        h.testBit(i - 4) && !k.testBit(i - 4)) { // 1 0 1 0  1
                        Q = Q.twice().twice().twice().twice().twice().add(P21);
                    } else if (!h.testBit(i - 4) &&  k.testBit(i - 4)) { // 1 0 1 0 -1
                        Q = Q.twice().twice().twice().twice().twice().add(P19);
                    } else {                                             // 1 0 1 0  0
                        Q = Q.twice().twice().twice().add(P5).twice().twice();
                    }
                } else if (!h.testBit(i - 2) &&  k.testBit(i - 2)) { //  1 0 -1  0 x 
                    if (        h.testBit(i - 4) && !k.testBit(i - 4)) { // 1 0 -1 0  1
                        Q = Q.twice().twice().twice().twice().twice().add(P13);
                    } else if (!h.testBit(i - 4) &&  k.testBit(i - 4)) { // 1 0 -1 0 -1
                        Q = Q.twice().twice().twice().twice().twice().add(P11);
                    } else {                                             // 1 0 -1 0  0
                        Q = Q.twice().twice().twice().add(P3).twice().twice();
                    }
                } else if ( h.testBit(i - 3) && !k.testBit(i - 3)) { //  1 0  0  1 0
                    Q = Q.twice().twice().twice().twice().add(P9).twice();
                } else if (!h.testBit(i - 3) &&  k.testBit(i - 3)) { //  1 0  0 -1 0
                    Q = Q.twice().twice().twice().twice().add(P7).twice();
                } else {                                             //  1 0  0  0 x
                    if (        h.testBit(i - 4) && !k.testBit(i - 4)) { // 1 0 0 0  1
                        Q = Q.twice().twice().twice().twice().twice().add(P17);
                    } else if (!h.testBit(i - 4) &&  k.testBit(i - 4)) { // 1 0 0 0 -1
                        Q = Q.twice().twice().twice().twice().twice().add(P15);
                    } else {                                             // 1 0 0 0  0
                        Q = Q.twice().add(P).twice().twice().twice().twice();
                    }
                }
                i -= 5;
            } else if (!h.testBit(i) && k.testBit(i)) { // -1 0 x x x
                if (       !h.testBit(i - 2) &&  k.testBit(i - 2)) { // -1 0 -1  0 x
                    if (       !h.testBit(i - 4) &&  k.testBit(i - 4)) { // -1 0 -1 0 -1
                        Q = Q.twice().twice().twice().twice().twice().subtract(P21);
                    } else if ( h.testBit(i - 4) && !k.testBit(i - 4)) { // -1 0 -1 0  1
                        Q = Q.twice().twice().twice().twice().twice().subtract(P19);
                    } else {                                             // -1 0 -1 0  0
                        Q = Q.twice().twice().twice().subtract(P5).twice().twice();
                    }
                } else if ( h.testBit(i - 2) && !k.testBit(i - 2)) { // -1 0  1  0 x 
                    if (       !h.testBit(i - 4) &&  k.testBit(i - 4)) { // -1 0 1 0 -1
                        Q = Q.twice().twice().twice().twice().twice().subtract(P13);
                    } else if ( h.testBit(i - 4) && !k.testBit(i - 4)) { // -1 0 1 0  1
                        Q = Q.twice().twice().twice().twice().twice().subtract(P11);
                    } else {                                             // -1 0 1 0  0
                        Q = Q.twice().twice().twice().subtract(P3).twice().twice();
                    }
                } else if (!h.testBit(i - 3) &&  k.testBit(i - 3)) { // -1 0  0 -1 0
                    Q = Q.twice().twice().twice().twice().subtract(P9).twice();
                } else if ( h.testBit(i - 3) && !k.testBit(i - 3)) { // -1 0  0  1 0
                    Q = Q.twice().twice().twice().twice().subtract(P7).twice();
                } else {                                             // -1 0  0  0 x
                    if (       !h.testBit(i - 4) &&  k.testBit(i - 4)) { // -1 0 0 0 -1
                        Q = Q.twice().twice().twice().twice().twice().subtract(P17);
                    } else if ( h.testBit(i - 4) && !k.testBit(i - 4)) { // -1 0 0 0  1
                        Q = Q.twice().twice().twice().twice().twice().subtract(P15);
                    } else {                                             // -1 0 0 0  0
                        Q = Q.twice().subtract(P).twice().twice().twice().twice();
                    }
                }
                i -= 5;
            } else { // 0 x x x x
                Q = Q.twice();
                i--;
            }
        }
        while (i >= 1) {
            Q = Q.twice();
            if (        h.testBit(i) && !k.testBit(i)) {
                Q = Q.add(P);
            } else if (!h.testBit(i) &&  k.testBit(i)) {
                Q = Q.subtract(P);
            }
            i--;
        }
        return Q;
    }
    */

    /**
     * Compute the y-bit of the compressed form of this point     *      * @return  the y-bit of the compressed form of this point
     */
    public abstract int yBit();

    /**
     * Convert this curve point to a byte array.
     * This is the ANSI X9.62 Point-to-Octet-String Conversion primitive
     * 
     * @param   formFlags   the desired form of the octet string representation
     *                      (EPoint.COMPRESSED, EPoint.EXPANDED, EPoint.HYBRID)
     * 
     * @return  this point converted to a byte array using
     *          the algorithm defined in section 4.3.6 of ANSI X9.62
     */
    public abstract byte[] toByteArray(int formFlags);

    /**
     * Convert this point to human-readable (hexadecimal) string format
     * 
     * @return  this point converted to human-readable (hexadecimal) string format
     */
    public abstract String toString();

}
