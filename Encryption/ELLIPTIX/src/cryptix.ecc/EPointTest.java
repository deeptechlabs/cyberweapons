/* $Id: EPointTest.java,v 1.3 1999/03/20 19:27:57 gelderen Exp $
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
public class EPointTest {

    /**
     * Generic prototype variable used in the EPoint tests.
     */
    EPoint prototype;

    /**
     * Create an instance of EPointTest by providing prototypes
     * for EPoint and GF variables.
     *
     * This is a direct application of the "Prototype" design pattern
     * as described by E. Gamma, R. Helm, R. Johnson and J. Vlissides in
     * "Design Patterns - Elements of Reusable Object-Oriented Software",
     * Addison-Wesley (1995), pp. 117-126.
     *
     * @param   prototype   the prototype for EPoint instantiation
     */
    public EPointTest(EPoint prototype) {
        this.prototype = prototype;
    }

    /**
     * Perform a complete test suite on the EC implementation
     *
     * @param   iterations  the desired number of iterations of the test suite
     * @param   random      the source of randomness for the various tests
     */
    public void doTest(int iterations, SecureRandom rand) throws GenericECException {
        EPoint u, v, w, x, y, z, ecZero;
        BigInteger m, n;
        int k, d, numBits = 256; // caveat: maybe using larger values is better
        long totalElapsed = -System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            System.out.print("test #" + i);
            long elapsed = -System.currentTimeMillis();
            // create random values from the prototype:
            x = prototype.randomize(rand);
            y = prototype.randomize(rand);
            z = prototype.randomize(rand);
            ecZero = prototype.E.infinity;
            m = new BigInteger(numBits, rand);
            n = new BigInteger(numBits, rand);

            // check cloning/comparison/pertinence:
            if (iterations == 1) {
                System.out.print("\nchecking cloning/comparison/pertinence");
            }
            if (!x.equals(x)) {
                throw new GenericECException("Comparison failure");
            }
            System.out.print(".");
            if (!x.isOnSameCurve(x)) {
                throw new GenericECException("Inconsistent pertinence self-comparison");
            }
            System.out.print(".");
            if (!x.E.contains(x)) {
                throw new RuntimeException("Inconsistent curve pertinence");
            }
            System.out.print(".");
            w = (EPoint)x.clone();
            if (!w.equals(x)) {
                throw new GenericECException("Cloning and deep comparison do not match");
            }
            System.out.print(".");
            if (!w.isOnSameCurve(x)) {
                throw new GenericECException("Cloning and curve pertinence do not match");
            }

            // check addition/subtraction/negation properties:
            if (iterations == 1) {
                System.out.print(" done.\nchecking addition/subtraction/negation properties");
            }
            if (!x.add(y).equals(y.add(x))) {
                throw new GenericECException("x + y != y + x");
            }
            System.out.print(".");
            if (!x.add(ecZero).equals(x)) {
                throw new GenericECException("x + 0 != x");
            }
            System.out.print(".");
            if (!x.add(x.negate()).isZero()) {
                throw new GenericECException("x + (-x) != 0");
            }
            System.out.print(".");
            if (!x.add(y).add(z).equals(x.add(y.add(z)))) {
                throw new GenericECException("(x + y) + z != x + (y + z)");
            }
            System.out.print(".");
            if (!x.negate().negate().equals(x)) {
                throw new GenericECException("-(-x) != x");
            }
            System.out.print(".");
            if (!(x.subtract(y)).equals(y.subtract(x).negate())) {
                throw new GenericECException("x - y != -(y - x)");
            }
            System.out.print(".");
            if (!(x.subtract(y)).subtract(z).equals(x.subtract(y.add(z)))) {
                throw new GenericECException("(x - y) - z != x - (y + z)");
            }
            System.out.print(".");
            if (!x.subtract(ecZero).equals(x)) {
                throw new GenericECException("x - 0 != x");
            }
            System.out.print(".");
            if (!ecZero.subtract(x).equals(x.negate())) {
                throw new GenericECException("0 - x != -x");
            }
            System.out.print(".");
            if (!x.subtract(x).isZero()) {
                throw new GenericECException("x - x != 0");
            }
            System.out.print(".");
            if (!x.add(y.negate()).equals(x.subtract(y))) {
                throw new GenericECException("x + (-y) != x - y");
            }
            System.out.print(".");
            if (!x.subtract(y.negate()).equals(x.add(y))) {
                throw new GenericECException("x - (-y) != x + y");
            }

            // check scalar multiplication properties:
            if (iterations == 1) {
                System.out.print(" done.\nchecking scalar multiplication properties");
            }
            if (!x.multiply(BigInteger.valueOf(0L)).equals(ecZero)) {
                throw new GenericECException("0*x != 0");
            }
            System.out.print(".");
            if (!x.multiply(BigInteger.valueOf(1L)).equals(x)) {
                throw new GenericECException("1*x != x");
            }
            System.out.print(".");
            if (!x.multiply(BigInteger.valueOf(2L)).equals(x.twice())) {
                throw new GenericECException("2*x != twice x");
            }
            System.out.print(".");
            if (!x.multiply(BigInteger.valueOf(2L)).equals(x.add(x))) {
                throw new GenericECException("2*x != x + x");
            }
            System.out.print(".");
            if (!x.multiply(BigInteger.valueOf(-1L)).equals(x.negate())) {
                throw new GenericECException("(-1)*x != -x");
            }
            System.out.print(".");
            if (!x.multiply(m.negate()).equals(x.negate().multiply(m))) {
                throw new GenericECException("(-m)*x != m*(-x)");
            }
            System.out.print(".");
            if (!x.multiply(m.negate()).equals(x.multiply(m).negate())) {
                throw new GenericECException("(-m)*x != -(m*x)");
            }
            System.out.print(".");
            if (!x.multiply(m.add(n)).equals(x.multiply(m).add(x.multiply(n)))) {
                throw new GenericECException("(m + n)*x != m*x + n*x");
            }
            System.out.print(".");
            if (!x.multiply(m.subtract(n)).equals(x.multiply(m).subtract(x.multiply(n)))) {
                throw new GenericECException("(m - n)*x != m*x - n*x");
            }
            System.out.print(".");
            w = x.multiply(n).multiply(m);
            if (!w.equals(x.multiply(m).multiply(n))) {
                throw new GenericECException("m*(n*x) != n*(m*x)");
            }
            System.out.print(".");
            if (!w.equals(x.multiply(m.multiply(n)))) {
                throw new GenericECException("m*(n*x) != (m*n)*x");
            }
            // TODO: test point compression/expansion/conversion
            elapsed += System.currentTimeMillis();
            System.out.println(" done; elapsed =  " + (float)elapsed/1000 + " s.");
        }
        totalElapsed += System.currentTimeMillis();
        System.out.println("All " + iterations + " tests done in " + (float)totalElapsed/1000 + " s.");
    }

    public static void main(String[] args) {
        int iterations = (args.length > 0) ? Integer.parseInt(args[0]) : 1;

        try {
            byte[] randSeed = new byte[20];
            (new Random()).nextBytes(randSeed);
            SecureRandom rand = new SecureRandom(randSeed);
            BigInteger q;
            EC param;
            EPointTest t;

            // load sample X9.62 curve parameters:
            GFUtil.setX9F1();

            /*
            System.out.print("Loading curve y^2 = x^3 + 10x + 5 over GF(13)...");
            q = BigInteger.valueOf(13L);
            param = new ECp(p,
                            new GFp(p, "A"),
                            new GFp(p, "5"),
                            BigInteger.valueOf(2L),
                            BigInteger.valueOf(5L),
                            "0201");
            t = new EPointTest((EPointp)param.infinity);
            System.out.println(" done.");
            t.doTest(iterations, rand);
            System.out.println();
            */

            System.out.println("Loading X9.62 J.2.1 (191-bit binary field)");
            param = new EC2m(191,
                            new GF2m(191, "2866537B676752636A68F56554E12640276B649EF7526267"),
                            new GF2m(191, "2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC"),
                            BigInteger.valueOf(2L),
                            new BigInteger("1569275433846670190958947355803350458831205595451630533029"),
                            "0436B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D765BE73433B3F95E332932E70EA245CA2418EA0EF98018FB");
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.2.2 (239-bit binary field)");
            param = new EC2m(239,
                            new GF2m(239, "32010857077C5431123A46B808906756F543423E8D27877578125778AC76"),
                            new GF2m(239, "790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16"),
                            BigInteger.valueOf(4L),
                            new BigInteger("220855883097298041197912187592864814557886993776713230936715041207411783"),
                            "0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305");
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.3.1 (192-bit prime field)");
            q = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
            param = new ECp(q,
                            new GFp(q, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"),
                            new GFp(q, "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"),
                            BigInteger.valueOf(1L),
                            new BigInteger("6277101735386680763835789423176059013767194773182842284081"),
                            "03188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012");
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.3.2 (239-bit prime field)");
            q = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
            param = new ECp(q,
                            new GFp(q, "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC"),
                            new GFp(q, "6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A"),
                            BigInteger.valueOf(1L),
                            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"),
                            "020FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF");
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.1.1 (163-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb163v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.1.2 (163-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb163v2);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.1.3 (163-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb163v3);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.2 (176-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb176w1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.3.1 (191-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb191v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.3.2 (191-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb191v2);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.3.3 (191-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb191v3);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.4 (208-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb208w1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.5.1 (239-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb239v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.5.2 (239-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb239v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.5.3 (239-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb239v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.6 (272-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb272w1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.7 (304-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb304w1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.8 (359-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb359v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.9 (368-bit binary field)");
            param = EC.getNamedCurve(EC.c2pnb368w1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.4.10 (431-bit binary field)");
            param = EC.getNamedCurve(EC.c2tnb431r1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.1.1 (192-bit prime field)");
            param = EC.getNamedCurve(EC.prime192v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.1.2 (192-bit prime field)");
            param = EC.getNamedCurve(EC.prime192v2);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.1.3 (192-bit prime field)");
            param = EC.getNamedCurve(EC.prime192v3);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.2.1 (239-bit prime field)");
            param = EC.getNamedCurve(EC.prime239v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.2.2 (239-bit prime field)");
            param = EC.getNamedCurve(EC.prime239v2);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.2.3 (239-bit prime field)");
            param = EC.getNamedCurve(EC.prime239v3);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

            System.out.println("Loading X9.62 J.5.3 (256-bit prime field)");
            param = EC.getNamedCurve(EC.prime256v1);
            t = new EPointTest(param.infinity);
            t.doTest(iterations, rand);
            System.out.println();

        } catch (Exception e) {
            System.out.println(e.toString());
        } catch (Error e) {
            System.out.println(e.toString());
        }
        System.out.println("Press <ENTER> to continue...");
        try {
            System.in.read();
        } catch (java.io.IOException e) {
        }
    }
}
