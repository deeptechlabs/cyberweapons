// $Id: $
//
// $Log: $
// Revision 1.0  1998/04/06  raif
// + original version based on cryptix.tools.MCT.
//
// $Endlog$
/*
 * Copyright (c) 1998 Systemics Ltd on behalf of
 * the Cryptix Development Team. All rights reserved.
 */
package NIST;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.StringTokenizer;

/**
 * For a designated candidate AES block cipher algorithm, this command
 * generates and exercises Monte Carlo Tests data for both Encryption
 * and Decryption in Electronic Codebook (ECB) and Cipher Block Chaining
 * (CBC) modes.<p>
 *
 * MCT's output file format is in conformance with the layout described in
 * Section 4 of NIST's document "Description of Known Answer Tests and Monte
 * Carlo Tests for Advanced Encryption Standard (AES) Candidate Algorithm
 * Submissions" dated January 7, 1998.<p>
 *
 * This code processes the user's request using NIST Basic API.<p>
 *
 * <b>Copyright</b> &copy; 1998
 * <a href="http://www.systemics.com/">Systemics Ltd</a> on behalf of the
 * <a href="http://www.systemics.com/docs/cryptix/">Cryptix Development Team</a>.
 * <br>All rights reserved.<p>
 *
 * <b>$Revision: $</b>
 * @author  Raif S. Naffah
 */
public final class MCT
{
// main method
//...........................................................................
    
    public static void main (String[] args) {
        System.out.println(
            "NIST Monte-Carlo Tests data generator/exerciser\n" +
            VERSION + "\n" +
            "Copyright (c) 1998 Systemics Ltd. on behalf of\n" +
            "the Cryptix Development Team.  All rights reserved.\n\n");
        MCT cmd = new MCT();
        cmd.processOptions(args);
        cmd.run();
    }


// Constants and variables
//...........................................................................

    static final String VERSION = "$Revision: 1.0$";
    static final String SUBMITTER = "<as stated on the submission cover sheet>";

    private static final char[] HEX_DIGITS = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };

    /** Current values of switches as set from the command line arguments. */
    boolean ecb = false ;        // -e  generate ECB Encrypt/Decrypt only
    boolean cbc = false ;        // -c  generate CBC Encrypt/Decrypt only
    boolean encrypting = false ; // -E  generate Encrypt data only
    boolean decrypting = false ; // -D  generate Decrypt data only
    String dirName = null;       // -d  destination directory if != user.dir
    String keylengths = null;    // -l  comma-separated key lengths

    String cipherName = null;    // cipher algorithm name == package
    File destination = null;     // destination directory File object
    int[] keys = new int[] {128, 192, 256}; // key-length values to test with

    final String eeFileName = "ecb_e_m.txt"; // ECB/Encrypt output filename
    final String edFileName = "ecb_d_m.txt"; // ECB/Decrypt output filename
    final String ceFileName = "cbc_e_m.txt"; // CBC/Encrypt output filename
    final String cdFileName = "cbc_d_m.txt"; // CBC/Decrypt output filename

    // will use zeroes for fields that require initial values.
    // could be replaced by random.nextBytes() using
    //
//    static final java.util.Random rand = new java.util.Random();
    //
    // or for cryptographically strong randoms use the following
    //
//    static final java.security.SecureRandom rand = new java.security.SecureRandom();
    //
    // bear in mind that initialising the latter PRNG is a lengthy process

    // statistics fields
    long encBlocks;     // total count of encrypted blocks
    long decBlocks;     // total count of decrypted blocks
    long keyCount;      // total count of key creation requests

    Method makeKey = null; // reference to makeKey([B)
    Method encrypt = null; // reference to blockEncrypt([B, int, int)
    Method decrypt = null; // reference to blockDecrypt([B, int, int)


// Own methods
//...........................................................................

    /** Process command line arguments. */
    void processOptions (String[] args) {
        int argc = args.length;
        if (argc == 0) printUsage();
        System.out.println(
            "(type \"java NIST.MCT\" with no arguments for help)\n\n");
        int i = -1;
        String cmd = "";
        boolean next = true;
        while (true) {
            if (next) {
                i++;
                if (i >= argc)
                    break;
                else
                    cmd = args[i];
            } else
                cmd = "-" + cmd.substring(2);
            
            if (cmd.startsWith("-e")) {              // ECB mode only
                ecb = true;
                cbc = false;
                next = (cmd.length() == 2);
            } else if (cmd.startsWith("-c")) {       // CBC mode only
                ecb = false;
                cbc = true;
                next = (cmd.length() == 2);
            } else if (cmd.startsWith("-E")) {       // Encrypt cases only
                encrypting = true;
                decrypting = false;
                next = (cmd.length() == 2);
            } else if (cmd.startsWith("-D")) {       // Decrypt cases only
                encrypting = false;
                decrypting = true;
                next = (cmd.length() == 2);
            } else if (cmd.startsWith("-l")) {       // key lengths
                keylengths = args[i + 1];
                i++;
                next = true;
            } else if (cmd.startsWith("-d")) {       // destination directory
                dirName = args[i + 1];
                i++;
                next = true;
            } else // it's the cipher
                cipherName = cmd;
        }
        // sanity checks
        if (cipherName == null)
            halt("Missing cipher algorithm name");
        if (cipherName.length() > 1 &&
                (cipherName.startsWith("\"") || cipherName.startsWith("'")))
            cipherName = cipherName.substring(2, cipherName.length() - 2);

        if (keylengths != null) {
            int count = 0;
            int k;
            int[] keystemp = new int[3]; // maximum allowed
            StringTokenizer st = new StringTokenizer(keylengths, ", \t\"");
            while (st.hasMoreTokens()) {
                k = Integer.parseInt(st.nextToken());
                if (k <= 0)
                    halt("Negative key length not allowed: "+k);
                if (count == 3)
                    halt("Only three key-length values are allowed.");
                keystemp[count++] = k;
            }
            if (count != 0) {
                keys = new int[count];
                System.arraycopy(keystemp, 0, keys, 0, count);
            }
        }
        if (!ecb && !cbc)
            ecb = cbc = true;

        if (!encrypting && !decrypting)
            encrypting = decrypting = true;

        if (dirName == null)
            dirName = System.getProperty("user.dir");
        destination = new File(dirName);
        if (! destination.isDirectory())
            halt("Destination <" + destination.getName() +
                "> is not a directory");

        String aes = cipherName + "." + cipherName + "_Algorithm";
        try {
            Class algorithm = Class.forName(aes);
            // inspect the Basic API class
            Method[] methods = algorithm.getDeclaredMethods();
            for (i = 0; i < methods.length; i++) {
                String name = methods[i].getName();
                int params = methods[i].getParameterTypes().length;
                if (name.equals("makeKey") && (params == 1))
                    makeKey = methods[i];
                else if (name.equals("blockEncrypt") && (params == 3))
                    encrypt = methods[i];
                else if (name.equals("blockDecrypt") && (params == 3))
                    decrypt = methods[i];
            }
            if (makeKey == null)
                throw new NoSuchMethodException("makeKey()");
            if (encrypt == null)
                throw new NoSuchMethodException("blockEncrypt()");
            if (decrypt == null)
                throw new NoSuchMethodException("blockDecrypt()");
        } catch (ClassNotFoundException x1) {
            halt("Unable to find "+aes+" class");
        } catch (NoSuchMethodException x2) {
            halt("Unable to find "+aes+"."+x2.getMessage()+" method");
        }
    }

    /**
     * Print an error message to System.err and halts execution returning
     * -1 to the JVM.
     *
     * @param s A message to output on System.err
     */
    static void halt (String s) {
        System.err.println("\n*** "+s+"...");
        System.exit(-1);
    }

    /**
     * Write a notification message to System.out.
     *
     * @param s  String to output to System.out.
     */
    static void notify (String s) { System.out.println("MCT: "+s+"..."); }
    
    /** write help text and quit. */
    void printUsage() {
        System.out.println(
        "NAME\n" +
        "  MCT: A Monte Carlo Tests data generator/exerciser for any AES\n" +
        "  candidate cipher algorithm.\n\n" +
        "SYNTAX\n" +
        "  java NIST.MCT\n" +
        "    [ -e | -c ]\n" +
        "    [ -E | -D ]\n" +
        "    [ -l <comma-separated-key-lengths>]\n" +
        "    [ -d <output-directory>]\n" +
        "    <cipher>\n\n" +
        "DESCRIPTION\n" +
        "  For a designated candidate AES block cipher algorithm, this command\n" +
        "  generates and exercises Monte Carlo Tests data for both Encryption\n" +
        "  and Decryption in Electronic Codebook (ECB) and Cipher Block Chaining\n" +
        "  (CBC) modes.\n" +
        "  MCT's output file format is in conformance with the layout described\n" +
        "  in Section 4 of NIST's document \"Description of Known Answer Tests\n" +
        "  and Monte Carlo Tests for Advanced Encryption Standard (AES) Candidate\n" +
        "  Algorithm Submissions\" dated January 7, 1998.\n\n" +
        "OPTIONS\n" +
        "  -e   Generate test data for the cipher in ECB mode only.  By default\n"+
        "       MCT generates both ECB and CBC test suites.\n\n" +
        "  -c   Generate test data for the cipher in CBC mode only.  By default\n"+
        "       MCT generates both ECB and CBC test suites.\n\n" +
        "  -E   Generate Encryption data only for the cipher in one or both of\n"+
        "       ECB and CBC modes depending on the first two switches.  By default\n"+
        "       MCT generates both Encryption and Decryption data.\n\n" +
        "  -D   Generate Decryption data only for the cipher in one or both of\n"+
        "       ECB and CBC modes depending on the first two switches.  By default\n"+
        "       MCT generates both Encryption and Decryption data.\n\n" +
        "  -l <comma-separated-key-lengths>\n" +
        "       Comma separated list (maximum of three) of key lengths to use\n" +
        "       for the tests.  If omitted, the following three values are\n" +
        "       assumed: 128, 192 and 256.\n\n" +
        "  -d <output-directory>\n" +
        "       Pathname of the directory where the output files: \"ecb_e_m.txt\",\n" +
        "       \"ecb_d_m.txt\", \"cbc_e_m.txt\" and \"cbc_d_m.txt\" will be generated.\n" +
        "       If this destination directory is not specified, those files will\n" +
        "       be placed in the current user directory.\n\n" +
        "  <cipher>\n" +
        "       Cipher algorithm name.\n\n" +
        "COPYRIGHT\n" +
        "  Copyright (c) 1998 Systemics Ltd. on behalf of\n" +
        "  the Cryptix Development Team.  All rights reserved.\n");
        System.exit(0);
    }

    /** main action. */
    void run() {
        long time = System.currentTimeMillis();

        if (ecb) {
            if (encrypting)
                ecbEncrypt(eeFileName);
            if (decrypting)
                ecbDecrypt(edFileName);
        }
        if (cbc) {
            if (encrypting)
                cbcEncrypt(ceFileName);
            if (decrypting)
                cbcDecrypt(cdFileName);
        }
        notify("Java interpreter used: Version "+System.getProperty("java.version"));
        notify("Java Just-In-Time (JIT) compiler: "+System.getProperty("java.compiler"));
        // print timing and stats info
        notify("Total execution time (ms): "+(System.currentTimeMillis() - time));
        notify("During this time, "+cipherName+":");
        notify("  Encrypted "+encBlocks+" blocks");
        notify("  Decrypted "+decBlocks+" blocks");
        notify("  Created "+keyCount+" session keys");
    }


// ECB MCT methods
//...........................................................................

    void ecbEncrypt (String encName) {
        PrintWriter enc = null;
        File f1 = new File(destination, encName);
        try {
            enc = new PrintWriter(new FileWriter(f1) , true);
        } catch (IOException x) {
            halt("Unable to initialize <" + encName + "> as a Writer:\n" +
                x.getMessage());
        }
        enc.println();
        enc.println("=========================");
        enc.println();
        enc.println("FILENAME:  \"" + encName+ "\"");
        enc.println();
        enc.println("Electronic Codebook (ECB) Mode - ENCRYPTION");
        enc.println("Monte Carlo Test");
        enc.println();
        enc.println("Algorithm Name: " + cipherName);
        enc.println("Principal Submitter: " + SUBMITTER);
        enc.println();

        try {
            for (int k = 0; k < keys.length; k++)
                ecbEncryptForKey(keys[k], enc);
        } catch (Exception x) {
            halt("Exception encountered in a " + cipherName +
                "_Algorithm method:\n" + x.getMessage());
        }
        enc.println("==========");
        enc.close();
    }

    void ecbDecrypt (String decName) {
        PrintWriter dec = null;
        File f2 = new File(destination, decName);
        try {
            dec = new PrintWriter(new FileWriter(f2) , true);
        } catch (IOException x) {
            halt("Unable to initialize <" + decName + "> as a Writer:\n" +
                x.getMessage());
        }
        dec.println();
        dec.println("=========================");
        dec.println();
        dec.println("FILENAME:  \"" + decName+ "\"");
        dec.println();
        dec.println("Electronic Codebook (ECB) Mode - DECRYPTION");
        dec.println("Monte Carlo Test");
        dec.println();
        dec.println("Algorithm Name: " + cipherName);
        dec.println("Principal Submitter: " + SUBMITTER);
        dec.println();

        try {
            for (int k = 0; k < keys.length; k++)
                ecbDecryptForKey(keys[k], dec);
        } catch (Exception x) {
            halt("Exception encountered in a " + cipherName +
                "_Algorithm method:\n" + x.getMessage());
        }
        dec.println("==========");
        dec.close();
    }

    void ecbEncryptForKey (int keysize, PrintWriter enc)
    throws IllegalAccessException, InvocationTargetException {
        notify("Processing MCT in ECB-Encrypt mode (long); key size: " + keysize);

        enc.println("==========");
        enc.println();
        enc.println("KEYSIZE=" + keysize);
        enc.println();

        Object[] args = {};            // actual arguments
        int keylen = keysize / 8;      // number of bytes in user key
        byte[] keyMaterial = new byte[keylen];
        int SIZE = 16;                 // default AES block size in bytes
        byte[] pt = new byte[SIZE];    // plaintext @i == ciphertext@i-1
        byte[] ct_1;                   // ciphertext @j-1
        int j, k, count;               // temp vars
        Object skeys;                  // algorithm secret key

        // step 1. we use all zeroes.
//        rand.nextBytes(keyMaterial);
//        rand.nextBytes(pt);

        for (int i = 0; i < 400; i++) {                      // step 2 (both)
            args = new Object[] { keyMaterial };
            skeys = makeKey.invoke(null, args);
            keyCount++;

            enc.println("I="   + i);                              // step 2.a
            enc.println("KEY=" + toString(keyMaterial));
            enc.println("PT="  + toString(pt));
            args = new Object[] {pt, new Integer(0), skeys};
            ct_1 = (byte[]) encrypt.invoke(null, args);           // step 2.b
            encBlocks++;
            for (j = 1; j < 9999; j++) {
                args[0] = ct_1;
                ct_1 = (byte[]) encrypt.invoke(null, args);
                encBlocks++;
            }
            args[0] = ct_1;
            pt = (byte[]) encrypt.invoke(null, args);             // step 2.e
            encBlocks++;
            enc.println("CT=" + toString(pt));                    // step 2.c
            enc.println();

            // may throw ArrayIndexOutOfBoundsException with
            // non-AES ciphers; ie. those for which:
            // keylen < size || keylen > 2*SIZE
            if (keylen > SIZE) {
                count = keylen - SIZE;
                j = SIZE;
//                k = SIZE - count;
                k = 0;
                while (j < keylen)
                    keyMaterial[j++] ^= ct_1[k++];
            }
            j = 0;                                                // step 2.d
            k = 0;
            while (j < SIZE)
                keyMaterial[j++] ^= pt[k++];
        }
    }

    void ecbDecryptForKey (int keysize, PrintWriter dec)
    throws IllegalAccessException, InvocationTargetException {
        notify("Processing MCT in ECB-Decrypt mode (long); key size: " + keysize);
        
        dec.println("==========");
        dec.println();
        dec.println("KEYSIZE=" + keysize);
        dec.println();

        Object[] args = {};            //actual arguments
        int keylen = keysize / 8;      // number of bytes in user key
        byte[] keyMaterial = new byte[keylen];
        int SIZE = 16;                 // default AES block size in bytes
        byte[] ct = new byte[SIZE];    // ciphertext @i == plaintext @i+1
        byte[] pt_1;                   // plaintext @j-1
        int j, k, count;               // temp vars
        Object skeys;                  // algorithm secret key

        // step 1. we use all zeroes.
//        rand.nextBytes(keyMaterial);
//        rand.nextBytes(ct);

        for (int i = 0; i < 400; i++) {                      // step 2 (both)
            args = new Object[] { keyMaterial };
            skeys = makeKey.invoke(null, args);
            keyCount++;

            dec.println("I="   + i);                              // step 2.a
            dec.println("KEY=" + toString(keyMaterial));
            dec.println("CT="  + toString(ct));
            args = new Object[] {ct, new Integer(0), skeys};
            pt_1 = (byte[]) decrypt.invoke(null, args);           // step 2.b
            decBlocks++;
            for (j = 1; j < 9999; j++) {
                args[0] = pt_1;
                pt_1 = (byte[]) decrypt.invoke(null, args);
                decBlocks++;
            }
            args[0] = pt_1;
            ct = (byte[]) decrypt.invoke(null, args);             // step 2.e
            decBlocks++;
            dec.println("PT=" + toString(ct));                    // step 2.c
            dec.println();

            // may throw ArrayIndexOutOfBoundsException with
            // non-AES ciphers; ie. those for which:
            // keylen < size || keylen > 2*SIZE
            if (keylen > SIZE) {
                count = keylen - SIZE;
                j = SIZE;
                k = 0;
                while (j < keylen)
                    keyMaterial[j++] ^= pt_1[k++];
            }
            j = 0;                                                // step 2.d
            k = 0;
            while (j < SIZE)
                keyMaterial[j++] ^= ct[k++];

        }
    }


// CBC MCT methods
//...........................................................................

    void cbcEncrypt (String encName) {
        PrintWriter pw = null;    // instantiate a PrintWriter for Encryption
        File f = new File(destination, encName);
        try {
            pw = new PrintWriter(new FileWriter(f) , true);
        } catch (IOException x) {
            halt("Unable to initialize <" + encName + "> as a Writer:\n" +
                x.getMessage());
        }
        pw.println();
        pw.println("=========================");
        pw.println();
        pw.println("FILENAME:  \"" + encName+ "\"");
        pw.println();
        pw.println("Cipher Block Chaining (CBC) Mode - ENCRYPTION");
        pw.println("Monte Carlo Test");
        pw.println();
        pw.println("Algorithm Name: " + cipherName);
        pw.println("Principal Submitter: " + SUBMITTER);
        pw.println();

        try {
            for (int k = 0; k < keys.length; k++)
                cbcEncryptForKey(keys[k], pw);
        } catch (Exception x) {
            halt("Exception encountered in a " + cipherName +
                "_Algorithm method:\n" + x.getMessage());
        }
        pw.println("==========");
        pw.close();
    }
    
    void cbcDecrypt (String decName) {
        PrintWriter pw = null;    // instantiate a PrintWriter for Encryption
        File f = new File(destination, decName);
        try {
            pw = new PrintWriter(new FileWriter(f) , true);
        } catch (IOException x) {
            halt("Unable to initialize <" + decName + "> as a Writer:\n" +
                x.getMessage());
        }
        pw.println();
        pw.println("=========================");
        pw.println();
        pw.println("FILENAME:  \"" + decName+ "\"");
        pw.println();
        pw.println("Cipher Block Chaining (CBC) Mode - DECRYPTION");
        pw.println("Monte Carlo Test");
        pw.println();
        pw.println("Algorithm Name: " + cipherName);
        pw.println("Principal Submitter: " + SUBMITTER);
        pw.println();

        try {
            for (int k = 128; k < 257; k += 64)
                cbcDecryptForKey(k, pw);
        } catch (Exception x) {
            halt("Exception encountered in a " + cipherName +
                "_Algorithm method:\n" + x.getMessage());
        }
        pw.println("==========");
        pw.close();
    }

    void cbcEncryptForKey (int keysize, PrintWriter pw)
    throws IllegalAccessException, InvocationTargetException {
        notify("Processing MCT in CBC-Encrypt mode (long); key size: "+keysize);

        pw.println("==========");
        pw.println();
        pw.println("KEYSIZE=" + keysize);
        pw.println();

        Object[] args = {};            //actual arguments
        int keylen = keysize / 8;      // number of bytes in user key material
        byte[] keyMaterial = new byte[keylen];
        int SIZE = 16;                 // default AES block size in bytes
        byte[] pt = new byte[SIZE];    // plaintext
        byte[] ct = new byte[SIZE];    // ciphertext
        byte[] iv = new byte[SIZE];    // initialization vector
        int j, k, count;               // temp vars
        Object skeys;                  // algorithm secret key

        // step 1. we use all zeroes.
//        rand.nextBytes(keyMaterial);
//        rand.nextBytes(iv);
//        rand.nextBytes(pt);

        // we do this cause we don't distinguish between j = 0 or other
        // in fact we don't need it at all if we start with zero values
        System.arraycopy(iv, 0, ct, 0, SIZE);

        for (int i = 0; i < 400; i++) {                             // step 2
                        // step 2.a is implicit since we're handling cv as iv
            pw.println("I="   + i);                               // step 2.b
            pw.println("KEY=" + toString(keyMaterial));
            pw.println("IV="  + toString(iv));
            pw.println("PT="  + toString(pt));

            args = new Object[] { keyMaterial };
            skeys = makeKey.invoke(null, args);  // the cipher's session keys
            keyCount++;

            args = new Object[3];
            args[1] = new Integer(0);
            args[2] = skeys;

            for (j = 0; j < 10000; j++) {                         // step 2.c
                for (k = 0; k < SIZE; k++)                      // step 2.c.i
                    iv[k] ^= pt[k];
                System.arraycopy(ct, 0, pt, 0, SIZE); // copy ct@(j-1) into pt
                args[0] = iv;
                ct = (byte[]) encrypt.invoke(null, args);      // step 2.c.ii
                encBlocks++;
                System.arraycopy(ct, 0, iv, 0, SIZE);        // set new iv/cv
            }
            pw.println("CT=" + toString(ct));                     // step 2.d
            pw.println();

            // may throw ArrayIndexOutOfBoundsException with
            // non-AES ciphers; ie. those for which:
            // keylen < size || keylen > 2*SIZE
            //
            // remember: we keep ct@(j-1) values in pt...
            if (keylen > SIZE) {
                count = keylen - SIZE;
                j = SIZE;
                k = 0;
                while (j < keylen)
                    keyMaterial[j++] ^= pt[k++];
            }
            j = 0;                                                // step 2.d
            k = 0;
            while (j < SIZE)
                keyMaterial[j++] ^= ct[k++];
        }
    }

    void cbcDecryptForKey (int keysize, PrintWriter pw)
    throws IllegalAccessException, InvocationTargetException {
        notify("Processing MCT in CBC-Decrypt mode (long); key size: "+keysize);
        
        pw.println("==========");
        pw.println();
        pw.println("KEYSIZE=" + keysize);
        pw.println();

        Object[] args = {};            //actual arguments
        int keylen = keysize / 8;      // number of bytes in user key material
        byte[] keyMaterial = new byte[keylen];
        int SIZE = 16;                 // default AES block size in bytes
        byte[] pt = new byte[SIZE];    // plaintext
        byte[] ct = new byte[SIZE];    // ciphertext
        byte[] iv = new byte[SIZE];    // initialization vector
        byte[] pt9998 = new byte[SIZE];// save this value
        int j, k, count;               // temp vars
        Object skeys;                  // algorithm secret key object

        // step 1. we use all zeroes.
//        rand.nextBytes(keyMaterial);
//        rand.nextBytes(iv);
//        rand.nextBytes(ct);

        for (int i = 0; i < 400; i++) {                             // step 2
                        // step 2.a is implicit since we're handling cv as iv
            pw.println("I="   + i);                               // step 2.b
            pw.println("KEY=" + toString(keyMaterial));
            pw.println("IV="  + toString(iv));
            pw.println("CT="  + toString(ct));

            args = new Object[] { keyMaterial };
            skeys = makeKey.invoke(null, args);  // the cipher's session keys
            keyCount++;

            args = new Object[3];
            args[1] = new Integer(0);
            args[2] = skeys;

            for (j = 0; j < 10000; j++) {                         // step 2.c
                args[0] = ct;
                pt = (byte[]) decrypt.invoke(null, args); // steps 2.c.i + ii
                decBlocks++;
                for (k = 0; k < SIZE; k++)                    // step 2.c.iii
                    pt[k] ^= iv[k];
                System.arraycopy(ct, 0, iv, 0, SIZE);          // step 2.c.iv
                System.arraycopy(pt, 0, ct, 0, SIZE);
                if ( j == 9998 )
                  System.arraycopy(pt, 0, pt9998, 0, SIZE );
            }
            pw.println("PT=" + toString(pt));                     // step 2.d
            pw.println();

            // may throw ArrayIndexOutOfBoundsException with
            // non-AES ciphers; ie. those for which:
            // keylen < size || keylen > 2*SIZE
            //
            // remember: iv contains values of pt@(j-1)

            if (keylen > SIZE) {
                count = keylen - SIZE; 
                k = 0;
                j = SIZE;
                while (j < keylen)
                    keyMaterial[j++] ^= pt9998[k++];
            }
            k = 0;
            j = 0;
            while (j < SIZE)
                keyMaterial[j++] ^= pt[k++];
        }
    }


// utility static methods (from cryptix.util.core ArrayUtil and Hex classes)
//...........................................................................

    /**
     * Returns a string of hexadecimal digits from a byte array. Each
     * byte is converted to 2 hex symbols.
     */
    private static String toString (byte[] ba) {
        int length = ba.length;
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[length-i-1];
            i++;
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }
}
