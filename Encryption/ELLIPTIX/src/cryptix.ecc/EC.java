/* $Id: EC.java,v 1.3 1999/03/20 19:27:57 gelderen Exp $
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
 * The EC class is an abstraction of elliptic curves considered as a whole,
 * i.e. sets of coordinate pairs satisfying the curve equation with certain parameters.
 *
 * @author  Paulo S. L. M. Barreto <pbarreto@cryptix.org>
 */
public abstract class EC {

    /**
     * Convenient BigInteger constants
     */
    protected static final BigInteger
        ZERO  = BigInteger.valueOf(0L),
        ONE   = BigInteger.valueOf(1L),
        TWO   = BigInteger.valueOf(2L),
        THREE = BigInteger.valueOf(3L);

    /**
     * Size of the underlying finite field GF(q)
     */
    BigInteger q;

    /**
     * Coefficient of the elliptic curve equation
     */
    protected GF a;

    /**
     * Coefficient of the elliptic curve equation
     */
    protected GF b;

    /**
     * Cofactor of the base point (curve order u = k*r)
     */
    BigInteger k;

    /**
     * Prime order of the base point (curve order u = k*r)
     */
    BigInteger r;

    /**
     * The base point of large prime order r
     */
    EPoint G;

    /**
     * The point at infinity
     */
    EPoint infinity;

    /**
     * Return the size q of the field GF(q) over which this curve is defined
     * 
     * @return  the size q of the field GF(q) over which this curve is defined
     */
    public BigInteger getFieldSize() {
        return q;
    }

    /**
     * Return the A coefficient of the equation defining this curve
     * 
     * @return  the A coefficient of the equation defining this curve
     */
    public GF getA() {
        return a;
    }

    /**
     * Return the B coefficient of the equation defining this curve
     * 
     * @return  the B coefficient of the equation defining this curve
     */
    public GF getB() {
        return b;
    }

    /**
     * Return the number of points in this curve (i.e. the curve order)
     * 
     * @return  number of points in this curve (i.e. the curve order)
     */
    public BigInteger getCurveOrder() {
        return k.multiply(r);
    }

    /**
     * Return the large prime factor r of the curve order u = k*r
     * 
     * @return  the large prime factor r of the curve order u = k*r
     */
    public BigInteger getBasePointOrder() {
        return r;
    }

    /**
     * Return the cofactor k of the curve order u = k*r
     * 
     * @return  the cofactor k of the curve order u = k*r
     */
    public BigInteger getCofactor() {
        return k;
    }

    /**
     * Return the base point of order r on this elliptic curve
     * 
     * @return  the base point of order r on this elliptic curve
     */
    public EPoint getBasePoint() {
        return G;
    }

    /**
     * Get a random nonzero point on this curve
     * 
     * @param   rand    a cryptographically strong PRNG
     * 
     * @return  a random nonzero point on this curve
     */
    public EPoint pointFactory(SecureRandom rand) {
         return G.randomize(rand); // using the Prototype design pattern
    }

    /**
     * Check is this curve is defined of the same field a given field element
     * 
     * @param   P   the field element whose source field is to be compared
     *              against the defining field of this curve
     * 
     * @return  true if this curve is defined on the same field as P, otherwise false
     */
    public boolean overFieldOf(GF P) {
        /*
         * Kronecker's theorem states that comparing the field sizes
         * is enough to determine if two fields are isomorphic;
         * this implies they are equal if the same representation is used.
         */
        return P.fieldSize().equals(q);
    }

    /**
     * Check whether this curve contains a given point
     * (i.e. whether that point satisfies the curve equation)
     * 
     * @param   P   the point whose pertinence or not to this curve is to be determined
     * 
     * @return  true if this curve contains P, otherwise false
     */
    public abstract boolean contains(EPoint P);

    private static final int c_TwoCurve = 0x0000;
    private static final int primeCurve = 0x0100;

    /**
     * X9F1 named curves
     */
    public static final int
        c2pnb163v1 = c_TwoCurve |  1, // J.4.1, example 1
        c2pnb163v2 = c_TwoCurve |  2, // J.4.1, example 2
        c2pnb163v3 = c_TwoCurve |  3, // J.4.1, example 3
        c2pnb176w1 = c_TwoCurve |  4, // J.4.2, example 1
        c2tnb191v1 = c_TwoCurve |  5, // J.4.3, example 1
        c2tnb191v2 = c_TwoCurve |  6, // J.4.3, example 2
        c2tnb191v3 = c_TwoCurve |  7, // J.4.3, example 3
    //  c2onb191v4 = c_TwoCurve |  8, // J.4.3, example 4 -- not supported (ONB)
    //  c2onb191v5 = c_TwoCurve |  9, // J.4.3, example 5 -- not supported (ONB)
        c2pnb208w1 = c_TwoCurve | 10, // J.4.4, example 1
        c2tnb239v1 = c_TwoCurve | 11, // J.4.5, example 1
        c2tnb239v2 = c_TwoCurve | 12, // J.4.5, example 2
        c2tnb239v3 = c_TwoCurve | 13, // J.4.5, example 3
    //  c2onb239v4 = c_TwoCurve | 14, // J.4.5, example 4 -- not supported (ONB)
    //  c2onb239v5 = c_TwoCurve | 15, // J.4.5, example 5 -- not supported (ONB)
        c2pnb272w1 = c_TwoCurve | 16, // J.4.6, example 1
        c2pnb304w1 = c_TwoCurve | 17, // J.4.7, example 1
        c2tnb359v1 = c_TwoCurve | 18, // J.4.8, example 1
        c2pnb368w1 = c_TwoCurve | 19, // J.4.9, example 1
        c2tnb431r1 = c_TwoCurve | 20, // J.4.10,example 1
        prime192v1 = primeCurve |  1, // J.5.1, example 1
        prime192v2 = primeCurve |  2, // J.5.1, example 2
        prime192v3 = primeCurve |  3, // J.5.1, example 3
        prime239v1 = primeCurve |  4, // J.5.2, example 1
        prime239v2 = primeCurve |  5, // J.5.2, example 2
        prime239v3 = primeCurve |  6, // J.5.2, example 3
        prime256v1 = primeCurve |  7; // J.5.3, example 1

    /**
     * Build an X9.62 named curve
     * 
     * @param   curveName   a constant representing the X9.62 curve
     * 
     * @return  the desired X9.62 curve, or null if the curve name is invalid or unsupported
     */
    public static EC getNamedCurve(int curveName) {
        BigInteger p;
        switch (curveName) {
        case c2pnb163v1:
            return new EC2m(163,
                            new GF2m(163, "072546B5435234A422E0789675F432C89435DE5242"),
                            new GF2m(163, "00C9517D06D5240D3CFF38C74B20B6CD4D6F9DD4D9"),
                            BigInteger.valueOf(2L),
                            new BigInteger("0400000000000000000001E60FC8821CC74DAEAFC1", 16),
                            "0307AF69989546103D79329FCC3D74880F33BBE803CB");
        case c2pnb163v2:
            return new EC2m(163,
                            new GF2m(163, "0108B39E77C4B108BED981ED0E890E117C511CF072"),
                            new GF2m(163, "0667ACEB38AF4E488C407433FFAE4F1C811638DF20"),
                            BigInteger.valueOf(2L),
                            new BigInteger("03FFFFFFFFFFFFFFFFFFFDF64DE1151ADBB78F10A7", 16),
                            "030024266E4EB5106D0A964D92C4860E2671DB9B6CC5");
        case c2pnb163v3:
            return new EC2m(163,
                            new GF2m(163, "07A526C63D3E25A256A007699F5447E32AE456B50E"),
                            new GF2m(163, "03F7061798EB99E238FD6F1BF95B48FEEB4854252B"),
                            BigInteger.valueOf(2L),
                            new BigInteger("03FFFFFFFFFFFFFFFFFFFE1AEE140F110AFF961309", 16),
                            "0202F9F87B7C574D0BDECF8A22E6524775F98CDEBDCB");
        case c2pnb176w1:
            return new EC2m(176,
                            new GF2m(176, "E4E6DB2995065C407D9D39B8D0967B96704BA8E9C90B"),
                            new GF2m(176, "5DDA470ABE6414DE8EC133AE28E9BBD7FCEC0AE0FFF2"),
                            BigInteger.valueOf(0xFF6EL),
                            new BigInteger("010092537397ECA4F6145799D62B0A19CE06FE26AD", 16),
                            "038D16C2866798B600F9F08BB4A8E860F3298CE04A5798");
        case c2tnb191v1:
            return new EC2m(191,
                            new GF2m(191, "2866537B676752636A68F56554E12640276B649EF7526267"),
                            new GF2m(191, "2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC"),
                            BigInteger.valueOf(2L),
                            new BigInteger("40000000000000000000000004A20E90C39067C893BBB9A5", 16),
                            "0236B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D");
        case c2tnb191v2:
            return new EC2m(191,
                            new GF2m(191, "401028774D7777C7B7666D1366EA432071274F89FF01E718"),
                            new GF2m(191, "0620048D28BCBD03B6249C99182B7C8CD19700C362C46A01"),
                            BigInteger.valueOf(4L),
                            new BigInteger("20000000000000000000000050508CB89F652824E06B8173", 16),
                            "023809B2B7CC1B28CC5A87926AAD83FD28789E81E2C9E3BF10");
        case c2tnb191v3:
            return new EC2m(191,
                            new GF2m(191, "6C01074756099122221056911C77D77E77A777E7E7E77FCB"),
                            new GF2m(191, "71FE1AF926CF847989EFEF8DB459F66394D90F32AD3F15E8"),
                            BigInteger.valueOf(6L),
                            new BigInteger("155555555555555555555555610C0B196812BFB6288A3EA3", 16),
                            "03375D4CE24FDE434489DE8746E71786015009E66E38A926DD");
        /*
        case c2onb191v4:
            return null; // ONB not yet supported
        case c2onb191v5:
            return null; // ONB not yet supported
        */
        case c2pnb208w1:
            return new EC2m(208,
                            new GF2m(208, "0000000000000000000000000000000000000000000000000000"),
                            new GF2m(208, "C8619ED45A62E6212E1160349E2BFA844439FAFC2A3FD1638F9E"),
                            BigInteger.valueOf(0xFE48L),
                            new BigInteger("0101BAF95C9723C57B6C21DA2EFF2D5ED588BDD5717E212F9D", 16),
                            "0289FDFBE4ABE193DF9559ECF07AC0CE78554E2784EB8C1ED1A57A");
        case c2tnb239v1:
            return new EC2m(239,
                            new GF2m(239, "32010857077C5431123A46B808906756F543423E8D27877578125778AC76"),
                            new GF2m(239, "790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16"),
                            BigInteger.valueOf(4L),
                            new BigInteger("2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447", 16),
                            "0257927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D");
        case c2tnb239v2:
            return new EC2m(239,
                            new GF2m(239, "4230017757A767FAE42398569B746325D45313AF0766266479B75654E65F"),
                            new GF2m(239, "5037EA654196CFF0CD82B2C14A2FCF2E3FF8775285B545722F03EACDB74B"),
                            BigInteger.valueOf(6L),
                            new BigInteger("1555555555555555555555555555553C6F2885259C31E3FCDF154624522D", 16),
                            "0228F9D04E900069C8DC47A08534FE76D2B900B7D7EF31F5709F200C4CA205");
        case c2tnb239v3:
            return new EC2m(239,
                            new GF2m(239, "01238774666A67766D6676F778E676B66999176666E687666D8766C66A9F"),
                            new GF2m(239, "6A941977BA9F6A435199ACFC51067ED587F519C5ECB541B8E44111DE1D40"),
                            BigInteger.valueOf(10L),
                            new BigInteger("0CCCCCCCCCCCCCCCCCCCCCCCCCCCCCAC4912D2D9DF903EF9888B8A0E4CFF", 16),
                            "0370F6E9D04D289C4E89913CE3530BFDE903977D42B146D539BF1BDE4E9C92");
        /*
        case c2onb239v4:
            return null; // ONB not yet supported
        case c2onb239v5:
            return null; // ONB not yet supported
        */
        case c2pnb272w1:
            return new EC2m(272,
                            new GF2m(272, "91A091F03B5FBA4AB2CCF49C4EDD220FB028712D42BE752B2C40094DBACDB586FB20"),
                            new GF2m(272, "7167EFC92BB2E3CE7C8AAAFF34E12A9C557003D7C73A6FAF003F99F6CC8482E540F7"),
                            BigInteger.valueOf(0xFF06L),
                            new BigInteger("0100FAF51354E0E39E4892DF6E319C72C8161603FA45AA7B998A167B8F1E629521", 16),
                            "026108BABB2CEEBCF787058A056CBE0CFE622D7723A289E08A07AE13EF0D10D171DD8D");
        case c2pnb304w1:
            return new EC2m(304,
                            new GF2m(304, "FD0D693149A118F651E6DCE6802085377E5F882D1B510B44160074C1288078365A0396C8E681"),
                            new GF2m(304, "BDDB97E555A50A908E43B01C798EA5DAA6788F1EA2794EFCF57166B8C14039601E55827340BE"),
                            BigInteger.valueOf(0xFE2EL),
                            new BigInteger("0101D556572AABAC800101D556572AABAC8001022D5C91DD173F8FB561DA6899164443051D", 16),
                            "02197B07845E9BE2D96ADB0F5F3C7F2CFFBD7A3EB8B6FEC35C7FD67F26DDF6285A644F740A2614");
        case c2tnb359v1:
            return new EC2m(359,
                            new GF2m(359, "5667676A654B20754F356EA92017D946567C46675556F19556A04616B567D223A5E05656FB549016A96656A557"),
                            new GF2m(359, "2472E2D0197C49363F1FE7F5B6DB075D52B6947D135D8CA445805D39BC345626089687742B6329E70680231988"),
                            BigInteger.valueOf(0x4CL),
                            new BigInteger("01AF286BCA1AF286BCA1AF286BCA1AF286BCA1AF286BC9FB8F6B85C556892C20A7EB964FE7719E74F490758D3B", 16),
                            "033C258EF3047767E7EDE0F1FDAA79DAEE3841366A132E163ACED4ED2401DF9C6BDCDE98E8E707C07A2239B1B097");
        case c2pnb368w1:
            return new EC2m(368,
                            new GF2m(368, "E0D2EE25095206F5E2A4F9ED229F1F256E79A0E2B455970D8D0D865BD94778C576D62F0AB7519CCD2A1A906AE30D"),
                            new GF2m(368, "FC1217D4320A90452C760A58EDCD30C8DD069B3C34453837A34ED50CB54917E1C2112D84D164F444F8F74786046A"),
                            BigInteger.valueOf(0xFF70L),
                            new BigInteger("010090512DA9AF72B08349D98A5DD4C7B0532ECA51CE03E2D10F3B7AC579BD87E909AE40A6F131E9CFCE5BD967", 16),
                            "021085E2755381DCCCE3C1557AFA10C2F0C0C2825646C5B34A394CBCFA8BC16B22E7E789E927BE216F02E1FB136A5F");
        case c2tnb431r1:
            return new EC2m(431,
                            new GF2m(431, "1A827EF00DD6FC0E234CAF046C6A5D8A85395B236CC4AD2CF32A0CADBDC9DDF620B0EB9906D0957F6C6FEACD615468DF104DE296CD8F"),
                            new GF2m(431, "10D9B4A3D9047D8B154359ABFB1B7F5485B04CEB868237DDC9DEDA982A679A5A919B626D4E50A8DD731B107A9962381FB5D807BF2618"),
                            BigInteger.valueOf(0x2760L),
                            new BigInteger("0340340340340340340340340340340340340340340340340340340323C313FAB50589703B5EC68D3587FEC60D161CC149C1AD4A91", 16),
                            "02120FC05D3C67A99DE161D2F4092622FECA701BE4F50F4758714E8A87BBF2A658EF8C21E7C5EFE965361F6C2999C0C247B0DBD70CE6B7");
        case prime192v1:
            p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
            return new ECp(p,
                            new GFp(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"),
                            new GFp(p, "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"),
                            BigInteger.valueOf(1L),
                            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16),
                            "03188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012");
        case prime192v2:
            p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
            return new ECp(p,
                            new GFp(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"),
                            new GFp(p, "CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953"),
                            BigInteger.valueOf(1L),
                            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31", 16),
                            "03EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A");
        case prime192v3:
            p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
            return new ECp(p,
                            new GFp(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"),
                            new GFp(p, "22123DC2395A05CAA7423DAECCC94760A7D462256BD56916"),
                            BigInteger.valueOf(1L),
                            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13", 16),
                            "027D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896");
        case prime239v1:
            p = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
            return new ECp(p,
                            new GFp(p, "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC"),
                            new GFp(p, "6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A"),
                            BigInteger.valueOf(1L),
                            new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B", 16),
                            "020FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF");
        case prime239v2:
            p = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
            return new ECp(p,
                            new GFp(p, "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC"),
                            new GFp(p, "617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C"),
                            BigInteger.valueOf(1L),
                            new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063", 16),
                            "0238AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7");
        case prime239v3:
            p = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
            return new ECp(p,
                            new GFp(p, "7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC"),
                            new GFp(p, "255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E"),
                            BigInteger.valueOf(1L),
                            new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551", 16),
                            "036768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A");
        case prime256v1:
            p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
            return new ECp(p,
                            new GFp(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
                            new GFp(p, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
                            BigInteger.valueOf(1L),
                            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
                            "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        default:
            return null;
        }
    }

}
