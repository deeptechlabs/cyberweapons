/* $Id: EPointp.java,v 1.2 1999/03/20 13:36:08 gelderen Exp $
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
 * Arithmetic operations on points of elliptic curves over GF(p)
 * 
 * @author    Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 */
public class EPointp extends EPoint implements Cloneable {

    protected static final BigInteger ONE = BigInteger.valueOf(1L);

    protected static final boolean DEBUG = false;

    /**
     * The projective x-coordinate
     */
    GFp x;

    /**
     * The projective y-coordinate
     */
    GFp y;

    /**
     * The projective z-coordinate
     */
    GFp z;

    /**
     * Create an instance of the EC point at infinity on curve E
     */
    EPointp(ECp E) {
        this.E = E;
        /* the point at infinity is represented as (1, 1, 0) after P1363
         * since such a point does not satisfy any projective curve equation
         * of the form (y^2)z = x^3 + ax(z^2) + b(z^3) for 4a^3 + 27b^2 != 0
         */
        this.x = E.gfOne;
        this.y = E.gfOne;
        this.z = E.gfZero;
    }

    /**
     * Create a random nonzero point on curve E
     */
    EPointp(ECp E, SecureRandom rand) {
        this.E = E;
        GFp alpha;
        do {
            x = new GFp(E.q, rand);
            // alpha = x^3 + ax + b = (x^2 + a)x + b
            alpha = (GFp)x.square().add(E.a).multiply(x).add(E.b);
            if (alpha.isZero()) {
                y = E.gfZero;
                break;
            }
        } while (alpha.sqrtCount() == 0);
        y = (GFp)alpha.sqrt();
        z = E.gfOne; // the random point is normalized, i.e. always of form (x, y, 1)
    }

    /**
     * Create a normalized EC point from given affine coordinates and a curve
     *
     * @param    E    the underlying elliptic curve parameters
     * @param    x    the affine x-coordinate
     * @param    y    the affine y-coordinate
     */
    EPointp(ECp E, GFp x, GFp y)
        throws DifferentFieldsException, PointNotOnCurveException {
        if (!E.overFieldOf(x) || !E.overFieldOf(y)) {
            throw new DifferentFieldsException();
        }
        // note that x, y, and z belong now to the same field
        this.E = E;
        this.x = x;
        this.y = y;
        this.z = E.gfOne;
        if (!E.contains(this)) {
            throw new PointNotOnCurveException();
        }
    }

    /**
     * Create an EC point from a given affine x-coordinate, a y-bit and a curve
     */
    EPointp(ECp E, GFp x, int yBit)
        throws DifferentFieldsException, PointNotOnCurveException {
        if (!E.overFieldOf(x)) {
            throw new DifferentFieldsException();
        }
        this.E = E;
        this.x = x;
        if (x.isZero()) {
            this.y = (GFp)E.b.sqrt();
        } else {
            // alpha = x^3 + ax + b = (x^2 + a)x + b
            // beta  = sqrt(alpha)
            GFp alpha = (GFp)x.square().add(E.a).multiply(x).add(E.b);
            GFp beta  = (GFp)alpha.sqrt();
            if (beta == null) {
                throw new PointNotOnCurveException();
            }
            this.y = (beta.getBit(0) == (yBit & 1)) ? beta : (GFp)beta.negate();
        }
        this.z = E.gfOne; // the point is normalized
        // note that x, y, and z belong now to the same field
        // the following test is redundant: if alpha has a square root,
        // then (x, y, z) does belong to the curve:
        if (DEBUG && !E.contains(this)) {
            throw new PointNotOnCurveException();
        }
    }

    /**
     * Create an EC point from given projective coordinates and a curve
     */
    private EPointp(ECp E, GFp x, GFp y, GFp z)
        throws DifferentFieldsException, PointNotOnCurveException {
        if (DEBUG && (!E.overFieldOf(x) || !E.overFieldOf(y) || !E.overFieldOf(z))) {
            throw new DifferentFieldsException();
        }
        // note that x, y, and z belong now to the same field
        this.E = E;
        this.x = x;
        this.y = y;
        this.z = z;
        if (!E.contains(this)) {
            throw new PointNotOnCurveException();
        }
    }

    /**
     * Create a clone of a given EC point
     */
    private EPointp(EPointp P) {
        E = P.E;
        x = P.x;
        y = P.y;
        z = P.z;
    }

    /*     * performing arithmetic operations on elliptic curve points
     * generally implies knowing the nature of these points (more precisely,
     * the nature of the finite field to which their coordinates belong),
     * hence they are done by the underlying elliptic curve.
     */

    /**
     * Create a clone of this point     *      * @return  a clone of this point
     */
    public Object clone() {
        return new EPointp(this);
    }

    /**
     * Check whether this is the point at infinity (i.e. the EC group zero element)     *      * @return  true if this is the point at infinity, otherwise false
     */
    public boolean isZero() {
        return z.isZero();
    }

    /**
     * Compare this point to a given object
     *
     * @param   Q   the elliptic curve point to be compared to this     *      * @return  true if this point and Q are equal, otherwise false
     */
    public boolean equals(Object Q) {
        if (Q instanceof EPointp && this.isOnSameCurve((EPointp)Q)) {
            EPointp P = (EPointp)Q;
            if (z.isZero() || P.z.isZero()) {
                return z.equals(P.z);
            } else {
                GFp z2 = (GFp)z.square(), z3 = (GFp)z.multiply(z2),
                    pz2 = (GFp)P.z.square(), pz3 = (GFp)P.z.multiply(pz2);
                return
                    x.multiply(pz2).equals(P.x.multiply(z2)) &&
                    y.multiply(pz3).equals(P.y.multiply(z3));
            }
        } else {
            return false;
        }
    }

    /**
     * Compute a random point on the same curve as this     *      * @return  a random point on the same curve as this
     */
    public EPoint randomize(SecureRandom rand) {
        return new EPointp((ECp)this.E, rand);
    }

    /**
     * Normalize this point
     * 
     * @return  a normalized point equivalent to this
     */
    public EPoint normalize() {
        if (this.isZero()) {
            return E.infinity;
        } else if (this.z.isOne()) {
            return this; // already normalized
        } else {
            EPointp P = (EPointp)this.clone();
            GF z2 = z.square();
            GF z3 = z.multiply(z2);
            return new EPointp((ECp)E,
                (GFp)x.divide(z2),
                (GFp)y.divide(z3),
                ((ECp)E).gfOne);
            /*
            // pure BigInteger implementation (not sure if necessary for efficiency)
            BigInteger z1 = this.z.toBigInteger();
            BigInteger z2 = z1.multiply(z1);
            BigInteger z3 = z2.multiply(z1);
            return new EPointp((ECp)E,
                       new GFp(E.q, x.toBigInteger().multiply(z2.modInverse(E.q)).mod(E.q)),
                       new GFp(E.q, y.toBigInteger().multiply(z3.modInverse(E.q)).mod(E.q)),
                       ((ECp)E).gfOne);
            */
        }
    }

    /**
     * Compute -this     *      * @return  -this
     */
    public EPoint negate() {
        return new EPointp((ECp)E, x, (GFp)y.negate(), z);
    }

    /**
     * Compute this + Q
     *     * @return  this + Q     * 
     * @param   Q   an elliptic curve point     * 
     * @exception   DifferentCurvesException    if this and Q lay on different curves
     */
    public EPoint add(EPoint Q) throws DifferentCurvesException {
        if (DEBUG && !this.isOnSameCurve(Q)) {
            throw new DifferentCurvesException();
        }
        if (this.isZero()) {
            return Q;
        }
        if (Q.isZero()) {
            return this;
        }
        EPointp R = (EPointp)Q; // a shorthand to make the expressions more readable
        /*
         * BigInteger implementation, perhaps not as elegant as
         * a pure GF(p) implementation, but very efficient due to
         * the small number of modular reductions.
         * 
         * Reference: P1363 section A.10.5
         */
        BigInteger t1, t2, t3, t4, t5, t6, t7, t8;
        t1 = x.toBigInteger();
        t2 = y.toBigInteger();
        t3 = z.toBigInteger();
        t4 = R.x.toBigInteger();
        t5 = R.y.toBigInteger();
        t6 = R.z.toBigInteger();
        if (!t6.equals(ONE)) {
            t7 = t6.multiply(t6); // t7 = z1^2
            // u0 = x0.z1^2
            t1 = t1.multiply(t7).mod(E.q);
            // s0 = y0.z1^3 = y0.z1^2.z1
            t2 = t2.multiply(t7).multiply(t6).mod(E.q);
        }
        if (!t3.equals(ONE)) {
            t7 = t3.multiply(t3); // t7 = z0^2
            // u1 = x1.z0^2
            t4 = t4.multiply(t7).mod(E.q);
            // s1 = y1.z0^3 = y1.z0^2.z0
            t5 = t5.multiply(t7).multiply(t3).mod(E.q);
        }
        // W = u0 - u1
        t7 = t1.subtract(t4).mod(E.q);
        // R = s0 - s1
        t8 = t2.subtract(t5).mod(E.q);
        if (t7.signum() == 0) {
            return (t8.signum() == 0) ? R.twice() : E.infinity;
        }
        // T = u0 + u1
        t1 = t1.add(t4).mod(E.q);
        // M = s0 + s1
        t2 = t2.add(t5).mod(E.q);
        // z2 = z0.z1.W
        if (!t6.equals(ONE)) {
            t3 = t3.multiply(t6); // no need to reduce here
        }
        t3 = t3.multiply(t7).mod(E.q);
        // x2 = R^2 - T.W^2
        t5 = t7.multiply(t7).mod(E.q); // t5 = W^2
        t6 = t1.multiply(t5).mod(E.q); // t6 = T.W^2
        t1 = t8.multiply(t8).subtract(t6).mod(E.q);
        // 2.y2 = (T.W^2 - 2.x2).R - M.W^2.W
        t2 = t6.subtract(t1.shiftLeft(1)).multiply(t8).subtract(t2.multiply(t5).multiply(t7)).mod(E.q);
        t2 = (t2.testBit(0) ? t2.add(E.q) : t2).shiftRight(1).mod(E.q);
        return new EPointp((ECp)E,
            new GFp(E.q, t1),
            new GFp(E.q, t2),
            new GFp(E.q, t3));
        /*
        // a pure GF(p) implementation: about 80% slower due to excess of modular reductions
        GF t1, t2, t3, t4, t5, t6, t7;
        t1 = x;
        t2 = y;
        t3 = z;
        t4 = R.x;
        t5 = R.y;
        t6 = R.z;
        if (!R.z.isOne()) {
            t7 = t6.square();
            t1 = t1.multiply(t7);
            t7 = t7.multiply(t6);
            t2 = t2.multiply(t7);
        }
        t7 = t3.square();
        t4 = t4.multiply(t7);
        t7 = t7.multiply(t3);
        t5 = t5.multiply(t7);
        t4 = t1.subtract(t4);
        t5 = t2.subtract(t5);
        if (t4.isZero()) {
            return t5.isZero() ? R.twice() : E.infinity;
        }
        t1 = t1.shiftLeft(1).subtract(t4);
        t2 = t2.shiftLeft(1).subtract(t5);
        if (!R.z.isOne()) {
            t3 = t3.multiply(t6);
        }
        t3 = t3.multiply(t4);
        t7 = t4.square();
        t4 = t4.multiply(t7);
        t7 = t7.multiply(t1);
        t1 = t5.square();
        t1 = t1.subtract(t7);
        t7 = t7.subtract(t1.shiftLeft(1));
        t5 = t5.multiply(t7);
        t4 = t4.multiply(t2);
        t2 = t5.subtract(t4);
        t2 = t2.shiftRight(1);
        return new EPointp((ECp)E, (GFp)t1, (GFp)t2, (GFp)t3);
        */
    }

    /**
     * Compute this - Q
     *     * @return  this - Q     * 
     * @param   Q   an elliptic curve point     * 
     * @exception   DifferentCurvesException    if this and Q lay on different curves
     */
    public EPoint subtract(EPoint Q) throws DifferentCurvesException {
        return add(Q.negate());
    }

    /**
     * Compute 2*this     *      * @return  2*this
     */
    public EPoint twice() {
        /*
         * BigInteger implementation, perhaps not as elegant as
         * a pure GF(p) implementation, but very efficient due to
         * the small number of modular reductions.
         * 
         * Reference: P1363 section A.10.4
         */
        BigInteger t1, t2, t3, t4, t5;
        t1 = x.toBigInteger();
        t2 = y.toBigInteger();
        t3 = z.toBigInteger();
        if (t2.signum() == 0 || t3.signum() == 0) {
            return E.infinity;
        }
        t4 = t3.multiply(t3); // t4 = z^2 (no need to reduce: z is often 1)
        if (E.a.equals(((ECp)E).qMinus3)) {
            // M = 3(x^2 - z^4) = 3(x - z^2)(x + z^2)
            t4 = THREE.multiply(t1.subtract(t4).multiply(t1.add(t4))).mod(E.q);
        } else {
            // M = 3.x^2 + a.(z^2)^2
            t4 = THREE.multiply(t1.multiply(t1)).add(E.a.toBigInteger().multiply(t4).multiply(t4)).mod(E.q);
        }
        // z2 = 2.y.z
        t3 = t3.multiply(t2).shiftLeft(1).mod(E.q);
        // S = 4.x.y^2
        t2 = t2.multiply(t2).mod(E.q); // t2 = y^2
        t5 = t1.multiply(t2).shiftLeft(2).mod(E.q);
        // x2 = M^2 - 2.S
        t1 = t4.multiply(t4).subtract(t5.shiftLeft(1)).mod(E.q);
        // T = 8.(y^2)^2
        t2 = t2.multiply(t2).shiftLeft(3).mod(E.q);
        // y2 = M(S - x2) - T
        t2 = t4.multiply(t5.subtract(t1)).subtract(t2).mod(E.q);
        return new EPointp((ECp)E,
            new GFp(E.q, t1),
            new GFp(E.q, t2),
            new GFp(E.q, t3));
        /*
        // a pure GF(p) implementation: about 80% slower due to excess of modular reductions
        GF t1, t2, t3, t4, t5;
        GF three = new GFp(q, THREE);
        t1 = x;
        t2 = y;
        t3 = z;
        if (t2.isZero() || t3.isZero()) {
            return E.infinity;
        }
        if (E.a.equals(((ECp)E).qMinus3)) {
            t4 = t3.square();
            t5 = t1.subtract(t4);
            t4 = t4.add(t1);
            t5 = t5.multiply(t4);
            t4 = three.multiply(t5);
        } else {
            t4 = (GFp)E.a;
            t5 = t3.square();
            t5 = t5.square();
            t5 = t5.multiply(t4);
            t4 = t1.square();
            t4 = three.multiply(t4);
            t4 = t4.add(t5);
        }
        t3 = t3.multiply(t2);
        t3 = t3.shiftLeft(1);
        t2 = t2.square();
        t5 = t1.multiply(t2);
        t5 = t5.shiftLeft(2);
        t1 = t4.square();
        t1 = t1.subtract(t5.shiftLeft(1));
        t2 = t2.square();
        t2 = t2.shiftLeft(3);
        t5 = t5.subtract(t1);
        t5 = t5.multiply(t4);
        t2 = t5.subtract(t2);
        return new EPointp((ECp)E,
            (GFp)t1,
            (GFp)t2,
            (GFp)t3);
        */
    }

    /**
     * Compute the y-bit of the compressed form of this point     *      * @return  the y-bit of the compressed form of this point
     */
    public int yBit() {
        /*
         * since q is an odd prime, the y-bit is y mod 2,
         * where y is interpreted as a positive integer less than q
         * (i.e. the y-bit is the rightmost bit of y)
         */
        return y.getBit(0);
    }

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
    public byte[] toByteArray(int formFlags) {
        byte[] result;
        if (this.isZero()) {
            result = new byte[1];
            result[0] = (byte)0;
            return result;
        }
        EPointp thisNorm = (EPointp)this.normalize();
        byte[] osX = null, osY = null;
        osX = thisNorm.x.toByteArray();
        int pc = 0, resLen = 1 + osX.length;
        if ((formFlags & COMPRESSED) != 0) {
            pc |= COMPRESSED | yBit();
        }
        if ((formFlags & EXPANDED) != 0) {
            pc |= EXPANDED;
            osY = thisNorm.y.toByteArray();
            resLen += osY.length;
        }
        result = new byte[resLen];
        result[0] = (byte)pc;
        System.arraycopy(osX, 0, result, 1, osX.length);
        if (osY != null) {
            System.arraycopy(osY, 0, result, 1 + osX.length, osY.length);
        }
        return result;
    }

    /**
     * Convert this point to human-readable (hexadecimal) string format
     * 
     * @return  this point converted to human-readable (hexadecimal) string format
     */
    public String toString() {
        return "(" + x.toString(16) + ", " + y.toString(16) + ", " + z.toString(16) + ")";
    }
}
