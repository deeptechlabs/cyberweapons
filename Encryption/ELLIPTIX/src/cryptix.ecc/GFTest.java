/* $Id: GFTest.java,v 1.3 1999/03/20 19:27:57 gelderen Exp $
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
 * @author  Paulo S. L. M. Barreto <pbarreto@cryptix.org>
 */
public class GFTest {

    /**
     * Generic prototype variable used in the GF tests.
     */
    GF prototype;

    /**
     * Create an instance of GFTest by providing a prototype for GF variables.
     *
     * This is a direct application of the "Prototype" design pattern
     * as described by E. Gamma, R. Helm, R. Johnson and J. Vlissides in
     * "Design Patterns - Elements of Reusable Object-Oriented Software",
     * Addison-Wesley (1995), pp. 117-126.
     *
     * @param   prototype   the prototype for ECPoint instantiation
     */
    public GFTest(GF prototype) {
        this.prototype = prototype;
    }

    private static boolean countTests = false;

    /**
     * Perform a complete test suite on the GF implementation
     *
     * @param   iterations  the desired number of iterations of the test suite
     * @param   random      the source of randomness for the various tests
     */
    public void doTest(int iterations, SecureRandom rand) throws GenericECException {
        GF x, y, z, u, v, w, zero, one, two;
        int fieldBitLength = prototype.fieldSize().bitLength();
        int k, d;
        zero = prototype.translate("0", 2);
        one  = prototype.translate("1", 2);
        two  = prototype.translate("10", 2);
        // check translation consistency:
        if (iterations == 1) {
            System.out.print("checking translation consistency...");
        }
        if (!zero.isZero()) {
            throw new GenericECException("Inconsistent translation of zero");
        }
        if (!one.isOne()) {
            throw new GenericECException("Inconsistent translation of one");
        }
        if (iterations == 1) {
            System.out.println(" done.");
        }
        long elapsed = -System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            if (countTests) {
                System.out.print("test #" + i + "... ");
            }
            // create random values from the prototype:
            x = prototype.randomize(rand);
            y = prototype.randomize(rand);
            z = prototype.randomize(rand);
            // check cloning and deep comparison:
            if (iterations == 1) {
                System.out.print("\nchecking cloning and deep comparison... ");
            }
            if (!x.equals(x)) {
                throw new GenericECException("Deep comparison failure");
            }
            u = (GF)x.clone();
            if (!u.equals(x)) {
                throw new GenericECException("Cloning and deep comparison do not match");
            }
            // check cloning and field pertinence:
            if (iterations == 1) {
                System.out.print("done.\nchecking cloning and field pertinence... ");
            }
            if (!u.inSameField(x)) {
                throw new GenericECException("Cloning and field pertinence do not match");
            }
            // check setBit/getBit consistency:
            if (iterations == 1) {
                System.out.print("done.\nchecking setBit/getBit consistency... ");
            }
            k = (rand.nextInt() & 0x7fffffff) % fieldBitLength;
            if (x.setBit(k, 0).getBit(k) != 0 || x.setBit(k, 1).getBit(k) != 1) {
                throw new GenericECException("Inconsistent setBit/getBit pairs");
            }
            // check addition properties:
            if (iterations == 1) {
                System.out.print("done.\nchecking addition properties... ");
            }
            if (!(x.add(y)).equals(y.add(x))) {
                throw new GenericECException("x + y != y + x");
            }
            if (!(x.add(y)).add(z).equals(x.add(y.add(z)))) {
                throw new GenericECException("(x + y) + z != x + (y + z)");
            }
            if (!x.add(zero).equals(x)) {
                throw new GenericECException("x + 0 != x");
            }
            if (!x.add(x.negate()).isZero()) {
                throw new GenericECException("x + (-x) != 0");
            }
            // check negation and subtraction properties:
            if (iterations == 1) {
                System.out.print("done.\nchecking negation and subtraction properties... ");
            }
            if (!x.negate().negate().equals(x)) {
                throw new GenericECException("-(-x) != x");
            }
            if (!(x.subtract(y)).equals(y.subtract(x).negate())) {
                throw new GenericECException("x - y != -(y - x)");
            }
            if (!(x.subtract(y)).subtract(z).equals(x.subtract(y.add(z)))) {
                throw new GenericECException("(x - y) - z != x - (y + z)");
            }
            if (!x.subtract(zero).equals(x)) {
                throw new GenericECException("x - 0 != x");
            }
            if (!zero.subtract(x).equals(x.negate())) {
                throw new GenericECException("0 - x != -x");
            }
            if (!x.subtract(x).isZero()) {
                throw new GenericECException("x - x != 0");
            }
            if (!x.add(y.negate()).equals(x.subtract(y))) {
                throw new GenericECException("x + (-y) != x - y");
            }
            if (!x.subtract(y.negate()).equals(x.add(y))) {
                throw new GenericECException("x - (-y) != x + y");
            }
            // check multiplication properties:
            if (iterations == 1) {
                System.out.print("done.\nchecking multiplication properties... ");
            }
            if (!x.multiply(one).equals(x)) {
                throw new GenericECException("x * 1 != x");
            }
            if (!(x.multiply(y)).equals(y.multiply(x))) {
                throw new GenericECException("x * y != y * x");
            }
            if (!x.multiply(y).multiply(z).equals(x.multiply(y.multiply(z)))) {
                throw new GenericECException("(x * y) * z != x * (y * z)");
            }
            // check inversion and division properties:
            if (iterations == 1) {
                System.out.print("done.\nchecking inversion and division properties... ");
            }
            if (!one.invert().equals(one)) {
                throw new GenericECException("1^(-1) != 1");
            }
            if (!x.isZero()) {
                if (!x.multiply(x.invert()).isOne()) {
                    throw new GenericECException("x * x^-1 != 1");
                }
                if (!x.invert().invert().equals(x)) {
                    throw new GenericECException("(x^-1)^-1 != x");
                }
                if (!y.isZero()) {
                    if (!(x.divide(y)).equals(y.divide(x).invert())) {
                        throw new GenericECException("x / y != (y / x)^-1");
                    }
                    if (!z.isZero()) {
                        if (!(x.divide(y)).divide(z).equals(x.divide(y.multiply(z)))) {
                            throw new GenericECException("(x / y) / z != x / (y * z)");
                        }
                    }
                    if (!x.multiply(y.invert()).equals(x.divide(y))) {
                        throw new GenericECException("x * y^-1 != x / y");
                    }
                    if (!x.divide(y.invert()).equals(x.multiply(y))) {
                        throw new GenericECException("x / y^-1 != x * y");
                    }
                }
                if (!one.divide(x).equals(x.invert())) {
                    throw new GenericECException("1 / x != x^-1");
                }
                if (!x.divide(x).isOne()) {
                    throw new GenericECException("x / x != 1");
                }
            }
            if (!x.divide(one).equals(x)) {
                throw new GenericECException("x / 1 != x");
            }
            // check squaring and square root extraction:
            if (iterations == 1) {
                System.out.print("done.\nchecking squaring and square root extraction... ");
            }
            if (!x.multiply(x).equals(x.square())) {
                throw new GenericECException("x * x != x^2");
            }
            if (!x.negate().square().equals(x.square())) {
                throw new GenericECException("(-x)^2 != x^2");
            }
            v = x.square().sqrt();
            if (v == null) {
                throw new GenericECException("no square root found for x^2");
            }
            if (!(v.equals(x) || v.equals(x.negate()))) {
                throw new GenericECException("sqrt(x^2) != (+/-)x");
            }
            v = x.sqrt();
            if (v != null && !v.square().equals(x)) {
                throw new GenericECException("(sqrt(x))^2 != x");
            }
            // check shifts:
            if (iterations == 1) {
                System.out.print("done.\nchecking shifts... ");
            }
            if (!x.shiftLeft(1).equals(x.multiply(two))) {
                throw new GenericECException("x << 1 != x * 2");
            }
            if (!x.shiftRight(1).equals(x.divide(two))) {
                throw new GenericECException("x >> 1 != x / 2");
            }
            k = rand.nextInt() % fieldBitLength;
            d = rand.nextInt() % fieldBitLength;
            if (!x.shiftLeft(k).shiftRight(k).equals(x)) {
                throw new GenericECException("(x << k) >> k != x");
            }
            if (!x.shiftRight(k).shiftLeft(k).equals(x)) {
                throw new GenericECException("(x >> k) << k != x");
            }
            if (!x.shiftLeft(-k).equals(x.shiftRight(k))) {
                throw new GenericECException("x << (-k) != x >> k");
            }
            if (!x.shiftRight(-k).equals(x.shiftLeft(k))) {
                throw new GenericECException("x >> (-k) != x << k");
            }
            /*
            The following test is redundant in face of the two previous tests:
            if (!x.shiftLeft(k).shiftRight(k).equals(x.shiftRight(k).shiftLeft(k))) {
                throw new GenericECException("(x << k) >> k != (x >> k) << k");
            }
            */
            if (!x.shiftLeft(k).shiftLeft(d).equals(x.shiftLeft(k + d))) {
                throw new GenericECException("(x << k) << d != x << (k + d)");
            }
            if (!x.shiftLeft(k).shiftRight(d).equals(x.shiftLeft(k - d))) {
                throw new GenericECException("(x << k) >> d != x << (k - d)");
            }
            if (!x.shiftRight(k).shiftRight(d).equals(x.shiftRight(k + d))) {
                throw new GenericECException("(x >> k) >> d != x >> (k + d)");
            }
            if (!x.shiftRight(k).shiftLeft(d).equals(x.shiftRight(k - d))) {
                throw new GenericECException("(x >> k) << d != x >> (k - d)");
            }
            if (countTests || iterations == 1) {
                System.out.println("done.");
            }
        }
        elapsed += System.currentTimeMillis();
        System.out.println("All " + iterations + " tests done in " + (float)elapsed/1000 + " s.");
    }

    public static void main(String[] args) {
        long elapsed;
        BigInteger ONE = BigInteger.valueOf(1L);

        System.out.print("Creating randomness source...");
        elapsed = -System.currentTimeMillis();
        byte[] randSeed = new byte[20];
        (new Random()).nextBytes(randSeed);
        SecureRandom rand = new SecureRandom(randSeed);
        elapsed += System.currentTimeMillis();
        System.out.println(" done, " + (float)elapsed/1000 + " s.");

        GFTest t;
        int iterations = (args.length > 0) ? Integer.parseInt(args[0]) : 100;

        for (int m = 2; m <= 2000; m++) {
            System.out.println("--------------------------------\n");

            if (m <= 1000) {
                GFUtil.set1363();
                System.out.println("Testing GF(2^" + m + "):");
                t = new GFTest(new GF2m(m));
                t.doTest(iterations, rand);
                System.out.println();
            }

            if (m >= 160) {
                GFUtil.setX9F1();
                System.out.println("Testing GF(2^" + m + "):");
                t = new GFTest(new GF2m(m));
                t.doTest(iterations, rand);
                System.out.println();
            }

            BigInteger p;

            // test p such that p mod 4 = 3:
            do {
                p = new BigInteger(m, 20, rand);
            } while ((p.intValue() & 3) != 3);
            System.out.println("Testing GF(0x" + p.toString(16) +"):");
            t = new GFTest(new GFp(p));
            t.doTest(iterations, rand);
            System.out.println();

            // test p such that p mod 8 = 5 (this can only happen for p >=  5, hence m >= 3):
            if (m >= 3) {
                do {
                    p = new BigInteger(m, 20, rand);
                } while ((p.intValue() & 7) != 5);
                System.out.println("Testing GF(0x" + p.toString(16) +"):");
                t = new GFTest(new GFp(p));
                t.doTest(iterations, rand);
                System.out.println();
            }

            // test p such that p mod 8 = 1 (this can only happen for p >= 17, hence m >= 5):
            if (m >= 5) {
                do {
                    p = new BigInteger(m, 20, rand);
                } while ((p.intValue() & 7) != 1);
                System.out.println("Testing GF(0x" + p.toString(16) +"):");
                t = new GFTest(new GFp(p));
                t.doTest(iterations, rand);
                System.out.println();
            }

        }


        System.out.println("Press <ENTER> to finish...");
        try {
            System.in.read();
            System.in.read();
        } catch (java.io.IOException e) {
        }
    }
}
