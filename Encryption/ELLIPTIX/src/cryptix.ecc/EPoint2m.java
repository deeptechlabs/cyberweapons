/* $Id: EPoint2m.java,v 1.2 1999/03/20 13:36:08 gelderen Exp $
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
 * Arithmetic operations on points of elliptic curves over GF(2<SUP>m</SUP>)
 * 
 * @author    Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 */
public class EPoint2m extends EPoint implements Cloneable {

    protected static final boolean DEBUG = false;

    /**
     * the affine x-coordinate
     */
    GF2m x;

    /**
     * the affine y-coordinate
     */
    GF2m y;

    /**
     * Create an instance of the EC point at infinity on curve E
     */
    EPoint2m(EC2m E) {
        this.E = E;
        /* the point at infinity is represented as (0, 0) after P1363,
         * since such a point does not satisfy any affine curve equation
         * of the form y^2 + xy = x^3 + ax^2 + b for b != 0
         */
        this.x = E.gfZero;
        this.y = E.gfZero;
    }

    /**
     * create a random nonzero point on curve E
     */
    EPoint2m(EC2m E, SecureRandom rand) {
        this.E = E;
        do {
            x = new GF2m(E.q.bitLength() - 1, rand);
            if (x.isZero()) {
                y = (GF2m)E.b.sqrt();
            } else {
                GF2m beta = (GF2m)x.add(E.a).add(E.b.divide(x.square()));
                y = (GF2m)beta.quadSolve();
                if (y != null) {
                    if (!y.square().add(y).add(beta).isZero()) {
                        throw new RuntimeException("Inconsistent quad solving in randomize()");
                    }
                    y = (GF2m)y.multiply(x);
                }
            }
        } while (y == null);
        if (!E.contains(this)) {
            throw new RuntimeException("Inconsistent randomization");
        }
    }

    /**
     * create an EC point from given affine coordinates and a curve
     */
    EPoint2m(EC2m E, GF2m x, GF2m y)
        throws PointNotOnCurveException {
        this.E = E;
        this.x = x;
        this.y = y;
        if (!E.contains(this)) {
            throw new PointNotOnCurveException();
        }
    }

    /**
     * Create an EC point from a given x-coordinate, a y-bit and a curve
     */
    EPoint2m(EC2m E, GF2m x, int yBit)
        throws DifferentFieldsException, PointNotOnCurveException {
        if (!E.overFieldOf(x)) {
            throw new DifferentFieldsException();
        }
        this.E = E;
        this.x = x;
        if (x.isZero()) {
            this.y = (GF2m)E.b.sqrt();
        } else {
            // beta  = x + a + b/(x^2)
            GF2m beta  = (GF2m)x.add(E.a).add(E.b.divide(x.square()));
            GF2m z = (GF2m)beta.quadSolve(); // z^2 + z = beta
            if (z == null) {
                throw new PointNotOnCurveException();
            }
            this.y = (GF2m)x.multiply((z.getBit(0) == (yBit & 1)) ? z : z.add(E.gfOne));
        }
        // note that x and y belong now to the same field
        // the following test is redundant: if z has a square root,
        // then (x, y) does belong to the curve:
        if (DEBUG && !E.contains(this)) {
            throw new PointNotOnCurveException();
        }
    }

    /**
     * create a clone of a given EC point
     */
    EPoint2m(EPoint2m P) {
        E = P.E;
        x = P.x;
        y = P.y;
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
        return new EPoint2m(this);
    }

    /**
     * Check whether this is the point at infinity (i.e. the EC group zero element)     *      * @return  true if this is the point at infinity, otherwise false
     */
    public boolean isZero() {
        return x.isZero() && y.isZero();
    }

    /**
     * Compare this point to a given object
     *
     * @param   Q   the elliptic curve point to be compared to this     *      * @return  true if this point and Q are equal, otherwise false
     */
    public boolean equals(Object Q) {
        return Q instanceof EPoint2m            && this.isOnSameCurve((EPoint2m)Q)            && x.equals(((EPoint2m)Q).x)            && y.equals(((EPoint2m)Q).y)            ;
    }

    /**
     * Compute a random point on the same curve as this     *      * @return  a random point on the same curve as this
     */
    public EPoint randomize(SecureRandom rand) {
        return new EPoint2m((EC2m)this.E, rand);
    }

    /**
     * Normalize this point
     * 
     * @return  a normalized point equivalent to this
     */
    public EPoint normalize() {
        return this; // because affine coordinates are used
    }

    /**
     * Compute -this     *      * @return  -this
     */
    public EPoint negate() {
        return new EPoint2m((EC2m)E, x, (GF2m)x.add(y));
    }

    /**
     * Compute this + Q
     *     * @return  this + Q     * 
     * @param   Q   an elliptic curve point     * 
     * @exception   DifferentCurvesException    if this and Q lay on different curves
     */
    public EPoint add(EPoint Q) throws DifferentCurvesException {
        if (!isOnSameCurve(Q)) {
            throw new DifferentCurvesException();
        }
        if (this.isZero()) {
            return Q;
        }
        if (Q.isZero()) {
            return this;
        }
        EPoint2m R = (EPoint2m)Q; // a shorthand to make the expressions more readable
        if (x.equals(R.x)) {
            return y.equals(R.y) ? twice() : E.infinity;
        } else {
            GF lambda = y.add(R.y).divide(x.add(R.x));
            GF x3 = lambda.square().add(lambda).add(x).add(R.x).add(E.a);
            GF y3 = x.add(x3).multiply(lambda).add(x3).add(y);
            return new EPoint2m((EC2m)E, (GF2m)x3, (GF2m)y3);
        }
    }

    /**
     * Compute this - Q
     *     * @return  this - Q     * 
     * @param   Q   an elliptic curve point     * 
     * @exception   DifferentCurvesException    if this and Q lay on different curves
     */
    public EPoint subtract(EPoint Q) throws DifferentCurvesException {
        if (!isOnSameCurve(Q)) {
            throw new DifferentCurvesException();
        }
        return add(Q.negate());
    }

    /**
     * Compute 2*this     *      * @return  2*this
     */
    public EPoint twice() {
        if (x.isZero()) {
            return E.infinity;
        }
        GF lambda = x.add(y.divide(x));
        GF x2 = lambda.square().add(lambda).add(E.a);
        GF y2 = x.square().add(lambda.add(((EC2m)E).gfOne).multiply(x2));
        return new EPoint2m((EC2m)E, (GF2m)x2, (GF2m)y2);
    }

    /**
     * Compute the y-bit of the compressed form of this point     *      * @return  the y-bit of the compressed form of this point
     */
    public int yBit() {
        return x.isZero() ? 0 : y.divide(x).getBit(0);
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
        byte[] osX = null, osY = null;
        osX = x.toByteArray();
        int pc = 0, resLen = 1 + osX.length;
        if ((formFlags & COMPRESSED) != 0) {
            pc |= COMPRESSED | yBit();
        }
        if ((formFlags & EXPANDED) != 0) {
            pc |= EXPANDED;
            osY = y.toByteArray();
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
        return "(" + x.toString(16) + ", " + y.toString(16) + ")";
    }
}
