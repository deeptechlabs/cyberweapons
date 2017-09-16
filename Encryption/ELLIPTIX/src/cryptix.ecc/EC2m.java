/* $Id: EC2m.java,v 1.3 1999/03/20 19:27:57 gelderen Exp $
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
 * @author  Paulo S. L. M. Barreto <pbarreto@cryptix.org>
 */
public class EC2m extends EC {

    /**
     * Convenient GF2m constant
     */
    GF2m gfZero;

    /**
     * Convenient GF2m constant
     */
    GF2m gfOne;

    /**
     * Create a partial description of the elliptic curve over GF(2<SUP>m</SUP>) satisfying
     * the equation y^2 + xy = x^3 + ax^2 + b with near-prime group order u = k*r
     * with a specified base point of prime order r.  The base point is left undefined.
     *
     * @param   m   dimension of the field GF(2^m)
     * @param   a   curve equation coefficient
     * @param   b   curve equation coefficient
     * @param   k   cofactor of the curve group order
     * @param   r   prime order of the cryptographic subgroup
     */
    public EC2m(int m, GF2m a, GF2m b, BigInteger k, BigInteger r) {
        this.q = ZERO.setBit(m);
        this.a = a;
        this.b = b;
        this.k = k;
        this.r = r;
        this.G = null;
        gfZero = new GF2m(m, ZERO);
        gfOne  = new GF2m(m, ONE);
        // CAVEAT: the infinity attribute MUST be set AFTER gfZero and gfOne!
        infinity = new EPoint2m(this);
    }

    /**
     * Create a description of the elliptic curve over GF(2<SUP>m</SUP>) satisfying
     * the equation y^2 + xy = x^3 + ax^2 + b with near-prime group order u = k*r
     * with a specified base point of prime order r.
     *
     * @param   m   dimension of the field GF(2^m)
     * @param   a   curve equation coefficient
     * @param   b   curve equation coefficient
     * @param   k   cofactor of the curve group order
     * @param   r   prime order of the cryptographic subgroup
     * @param   G   description of base point of order r on the curve
     * 
     * @exception    InvalidECParamsException    if the selected parameters don't define a proper curve
     */
    public EC2m(int m, GF2m a, GF2m b, BigInteger k, BigInteger r, String G)
        throws InvalidECParamsException {
        this(m, a, b, k, r);

        int pc = Integer.parseInt(G.substring(0, 2), 16);
        int octetCount, coordLen, xPos, yPos, zPos;
        switch (pc) {
        case 0x02:
        case 0x03:
            // compressed form:
            try {
                String x = G.substring(2);
                this.G = new EPoint2m(this,
                    new GF2m(m, G.substring(2)), // x coordinate
                    pc & 1);
            } catch (PointNotOnCurveException e) {
                throw new InvalidECParamsException("Invalid base point description");
            }
            break;
        case 0x04:
            // expanded form:
            try {
                octetCount  = (G.length() >>> 1);
                coordLen    = octetCount - 1; // 2*((octetCount - 1)/2)
                xPos        = 2;
                yPos        = xPos + coordLen;
                zPos        = yPos + coordLen;
                this.G = new EPoint2m(this,
                    new GF2m(m, G.substring(xPos, yPos)),    // x-coordinate
                    new GF2m(m, G.substring(yPos, zPos)));    // y coordinate
            } catch (PointNotOnCurveException e) {
                throw new InvalidECParamsException("Invalid base point description");
            }
            break;
        case 0x06:
        case 0x07:
            // hybrid form:
            try {
                octetCount    = (G.length() >>> 1);
                coordLen    = octetCount - 1; // 2*((octetCount - 1)/2)
                xPos        = 2;
                yPos        = xPos + coordLen;
                zPos        = yPos + coordLen;
                this.G = new EPoint2m(this,
                    new GF2m(m, G.substring(xPos, yPos)),    // x-coordinate
                    new GF2m(m, G.substring(yPos, zPos)));    // y coordinate
                // TODO: compare compressed and expanded forms in hybrid representation
            } catch (PointNotOnCurveException e) {
                throw new InvalidECParamsException("Invalid base point description");
            }
            break;
        default:
            throw new InvalidECParamsException("Invalid base point description");
        }
        /*
        if (!this.G.multiply(r).isZero()) {
            throw new InvalidECParamsException("Wrong order");
        }
        */
    }

    /**
     * Check whether this curve contains a given point
     * (i.e. whether that point satisfies the curve equation)
     * 
     * @param   P   the point whose pertinence or not to this curve is to be determined
     * 
     * @return  true if this curve contains P, otherwise false
     */
    public boolean contains(EPoint P) {
        if (!(P instanceof EPoint2m)) {
            return false;
        }
        if (P.isZero()) {
            return true;
        }
        GF x = ((EPoint2m)P).x;
        GF y = ((EPoint2m)P).y;
        // check the affine equation (y + x).y = (x + a).x^2 + b:
        return y.add(x).multiply(y).equals(x.add(a).multiply(x.square()).add(b));
    }

}
