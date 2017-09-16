/* $Id: ECp.java,v 1.3 1999/03/20 19:27:57 gelderen Exp $
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

import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author  Paulo S. L. M. Barreto <pbarreto@cryptix.org>
 */
public class ECp extends EC {

    /**
     * Convenient GF(p) constant
     */
    GFp gfZero;

    /**
     * Convenient GF(p) constant
     */
    GFp gfOne;

    /**
     * Convenient GF(p) constant
     */
    GFp qMinus3;

    /**
     * Create a partial description of the elliptic curve over GF(p) satisfying
     * the equation y^2 = x^3 + ax + b with near-prime group order u = k*r
     * with a specified base point of prime order r.  The base point is left undefined.
     *
     * @param   p   an approximation for the size q of the underlying
     *              finite field GF(q) (q is taken to be the nearest odd prime
     *              not smaller than p or 3)
     * @param   a   curve equation coefficient
     * @param   b   curve equation coefficient
     * @param   k   cofactor of the curve group order
     * @param   r   prime order of the cryptographic subgroup
     * 
     * @exception    InvalidECParamsException    if the selected parameters don't define a proper curve
     */
    private ECp(BigInteger p, GFp a, GFp b, BigInteger k, BigInteger r)
        throws InvalidECParamsException {
        this.q = nextPrime(p);
        this.a = a;
        this.b = b;
        this.k = k;
        this.r = r;
        this.G = null;
        if (!r.isProbablePrime(GFp.PRIMALITY_CERTAINTY)) {
            throw new InvalidECParamsException("The order of the base point is not prime");
        }
        gfZero = new GFp(q, ZERO);
        gfOne  = new GFp(q, ONE);
        // CAVEAT: the infinity attribute MUST be set AFTER gfZero and gfOne!
        infinity = new EPointp(this);
        qMinus3  = new GFp(q, q.subtract(THREE));
    }

    /**
     * Create a description of the elliptic curve over GF(p) satisfying
     * the equation y^2 = x^3 + ax + b with near-prime group order u = k*r
     * with a specified base point of prime order r.
     *
     * @param   p   an approximation for the size q of the underlying
     *              finite field GF(q) (q is taken to be the nearest odd prime
     *              not smaller than p or 3)
     * @param   a   curve equation coefficient
     * @param   b   curve equation coefficient
     * @param   k   cofactor of the curve group order
     * @param   r   prime order of the cryptographic subgroup
     * @param   G   description of base point of order r on the curve
     * 
     * @exception    InvalidECParamsException    if the selected parameters don't define a proper curve
     */
    public ECp(BigInteger p, GFp a, GFp b, BigInteger k, BigInteger r, String G)
        throws InvalidECParamsException {
        this(p, a, b, k, r);

        int pc = Integer.parseInt(G.substring(0, 2), 16);
        int octetCount, coordLen, xPos, yPos, zPos;
        switch (pc) {
        case 0x02:
        case 0x03:
            // compressed form:
            try {
                String x = G.substring(2);
                this.G = new EPointp(this,
                    new GFp(q, G.substring(2)), // x coordinate
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
                this.G = new EPointp(this,
                    new GFp(q, G.substring(xPos, yPos)),    // x-coordinate
                    new GFp(q, G.substring(yPos, zPos)));    // y coordinate
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
                this.G = new EPointp(this,
                    new GFp(q, G.substring(xPos, yPos)),    // x-coordinate
                    new GFp(q, G.substring(yPos, zPos)));    // y coordinate
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
     * Create a description of the elliptic curve over GF(p) satisfying
     * the equation y^2 = x^3 + ax + b with near-prime group order u = k*r
     * with a random base point of prime order r.
     *
     * @param   p   an approximation for the size q of the underlying
     *              finite field GF(q) (q is taken to be the nearest odd prime
     *              not smaller than p or 3)
     * @param   a   curve equation coefficient
     * @param   b   curve equation coefficient
     * @param   k   cofactor of the curve group order
     * @param   r   prime order of the cryptographic subgroup
     * @param   rand    cryptographically strong PRNG
     * 
     * @exception    InvalidECParamsException    if the selected parameters don't define a proper curve
     */
    public ECp(BigInteger p, GFp a, GFp b, BigInteger k, BigInteger r, SecureRandom rand)
        throws InvalidECParamsException {
        this(p, a, b, k, r);
        // generate random base point of order r:
        do {
            EPointp P = new EPointp(this, rand);
            this.G = P.multiply(k);
        } while (this.G.isZero());
        if (!this.G.multiply(r).isZero()) {
            throw new InvalidECParamsException("Wrong order");
        }
    }

    /**
     * Create a description of random a elliptic curve over GF(p)
     *
     * @param   p   an approximation for the size q of the underlying
     *              finite field GF(q) (q is taken to be the nearest odd prime
     *              not smaller than p or 3)
     * @param   rand    cryptographically strong PRNG
     */
    public ECp(BigInteger p, SecureRandom rand) throws InvalidECParamsException {
        // TODO: implement Schoof-Elkies-Atkin-Lercier curve parameter generation method
        throw new InvalidECParamsException("Constructor not yet implemented");
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
        if (!(P instanceof EPointp)) {
            return false;
        }
        if (P.isZero()) {
            return true;
        }
        EPointp Q = (EPointp)P; // shorthand to make the expressions more readable
        // check the projective equation y^2 = x^3 + a.x.z^4 + b.z^6:
        GF z2 = Q.z.square();
        GF z4 = z2.square();
        GF z6 = z4.multiply(z2);
        // y^2 = x(x^2 + a.z4) + b.z6
        return Q.y.square().equals(Q.x.multiply(Q.x.square().add(a.multiply(z4))).add(b.multiply(z6)));
    }

    /**
     * Compute the nearest odd prime not smaller than a given BigInteger
     * 
     * @param   q   the lower bound for prime search
     * 
     * @return  the smallest odd prime not smaller than q
     */
    public static BigInteger nextPrime(BigInteger q) {
        BigInteger p = q;
        if (!p.testBit(0)) {
            p = p.add(ONE); // p must be an odd prime
        }
        while (p.equals(THREE)) {
            p = p.add(TWO); // p must be larger than 3
        }
        while (!p.isProbablePrime(GFp.PRIMALITY_CERTAINTY)) {
            p = p.add(TWO);
        }
        return p;
    }
}
