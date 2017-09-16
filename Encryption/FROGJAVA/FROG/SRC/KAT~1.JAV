// $Id: $
//
// $Log: $
// Revision 1.0  1998/04/06  raif
// + original version based on cryptix.tools.KAT.
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
 * generates and exercises Known Answer Tests data for both Variable Key
 * and Variable Text suites.<p>
 *
 * KAT's output file format is in conformance with the layout described in
 * Section 3 of NIST's document "Description of Known Answer Tests and Monte
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
public final class KAT
{
// main method
//...........................................................................
    
    public static void main (String[] args) {
        System.out.println(
            "NIST Known Answer Tests data generator/exerciser\n" +
            VERSION + "\n" +
            "Copyright (c) 1998 Systemics Ltd. on behalf of\n" +
            "the Cryptix Development Team.  All rights reserved.\n\n");
        KAT cmd = new KAT();
        cmd.processOptions(args);
        cmd.run();
    }


// Fields & constants
//...........................................................................

    static final String VERSION = "$Revision: 1.0$";
    static final String SUBMITTER = "<as stated on the submission cover sheet>";

    // current values of switches as set from the command line arguments
    boolean varKey = false ;  // -k  generate variable-key data
    boolean varText = false ; // -t  generate variable-text data
    String dirName = null;    // -d  output directory if != user.dir
    String keylengths = null; // -l  comma-separated key lengths

    String cipherName = null; // cipher algorithm name, default == provider
    File destination = null;  // destination directory File object
    int[] keys = new int[] {128, 192, 256}; // key-length values to test with
    
    final String vkFileName = "ecb_vk.txt"; // variable-key output filename
    final String vtFileName = "ecb_vt.txt"; // variable-text output filename

    // statistics fields
    long encBlocks; // total count of encrypted blocks
    long decBlocks; // total count of decrypted blocks
    long keyCount;  // total count of key creation requests

    Method makeKey = null; // reference to makeKey([B)
    Method encrypt = null; // reference to blockEncrypt([B, int, int)
    Method decrypt = null; // reference to blockDecrypt([B, int, int)


// Own methods
//...........................................................................

    /** Process command line arguments and initialise instance fields. */
    private void processOptions (String[] args) {
        int argc = args.length;
        if (argc == 0)
            printUsage();
        System.out.println(
            "(type \"java NIST.KAT\" with no arguments for help)\n\n");
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
            
            if (cmd.startsWith("-k")) {
                varKey = true;
                next = (cmd.length() == 2);
            } else if (cmd.startsWith("-t")) {
                varText = true;
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

        if (!varKey && !varText)
            varKey = varText = true;

        if (dirName == null)
            dirName = System.getProperty("user.dir");
        destination = new File(dirName);
        if (! destination.isDirectory())
            halt("Destination <" + destination.getName() +
                "> is not a directory");

        String aes = cipherName + "." + cipherName + "_Algorithm";
        try {
            Class algorithm = Class.forName(aes);
            // inspect the _Algorithm class
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
     * @param s  A message to output on System.err
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
    static void notify (String s) { System.out.println("KAT: "+s+"..."); }
    
    /** write help text and quit. */
    void printUsage() {
        System.out.println(
        "NAME\n" +
        "  KAT: A Known Answer Tests data generator/exerciser for any AES\n" +
        "  candidate cipher algorithm.\n\n" +
        "SYNTAX\n" +
        "  java NIST.KAT\n" +
        "    [ -k | -t ]\n" +
        "    [ -l <comma-separated-key-lengths>]\n" +
        "    [ -d <output-directory>]\n" +
        "    <cipher>\n\n" +
        "DESCRIPTION\n" +
        "  For a designated candidate AES cipher algorithm, KAT generates\n" +
        "  and exercises Known Answer Tests data for both Variable Key and\n" +
        "  Variable Text suites.\n" +
        "  KAT's output file format conforms to the layout described in\n" +
        "  Section 3 of NIST's document \"Description of Known Answer Tests\n" +
        "  and Monte Carlo Tests for Advanced Encryption Standard (AES)\n" +
        "  Candidate Algorithm Submissions\" dated January 7, 1998.\n\n" +
        "OPTIONS\n" +
        "  -k   Generate data for variable-key tests only.  By default KAT\n" +
        "       generates both variable-key and variable-text test uites.\n\n" +
        "  -t   Generate data for variable-text tests only. By default KAT\n" +
        "       generates both variable-key and variable-text test suites.\n\n" +
        "  -l <comma-separated-key-lengths>\n" +
        "       Comma separated list (maximum of three) of key lengths to use\n" +
        "       for the tests.  If omitted, the following three values are\n" +
        "       assumed: 128, 192 and 256.\n\n" +
        "  -d <output-directory>\n" +
        "       Pathname of the directory where output files: \"ecb_vk.txt\"\n" +
        "       and \"ecb_vt.txt\" will be generated.  If this destination\n" +
        "       directory is not specified, those files will be placed in\n" +
        "       the current user directory.\n\n" +
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

        if (varKey)
            vkKAT(vkFileName);
        if (varText)
            vtKAT(vtFileName);

        notify("Java interpreter used: Version "+System.getProperty("java.version"));
        notify("Java Just-In-Time (JIT) compiler: "+System.getProperty("java.compiler"));
        // print timing and stats info
        notify("Total execution time (ms): "+(System.currentTimeMillis() - time));
        notify("During this time, "+cipherName+":");
        notify("  Encrypted "+encBlocks+" blocks");
        notify("  Decrypted "+ decBlocks+" blocks");
        notify("  Created "+keyCount+" session keys");
    }


// Variable Key KAT methods
//...........................................................................

    void vkKAT (String fileName) {
        File f = new File(destination, fileName);
        PrintWriter out = null;
        try {
            out = new PrintWriter(new FileWriter(f) , true);
        } catch (IOException x) {
            halt("Unable to initialize <" + fileName + "> as a Writer:\n" +
                x.getMessage());
        }
        out.println();
        out.println("=========================");
        out.println();
        out.println("FILENAME:  \"" + fileName + "\"");
        out.println();
        out.println("Electronic Codebook (ECB) Mode");
        out.println("Variable Key Known Answer Tests");
        out.println();
        out.println("Algorithm Name: " + cipherName);
        out.println("Principal Submitter: " + SUBMITTER);
        out.println();

        try {
            for (int k = 0; k < keys.length; k++)
                vkForKey(keys[k], out);
        } catch (Exception x) {
            halt("Exception encountered in a " + cipherName +
                "_Algorithm method:\n" + x.getMessage());
        }
        out.println("==========");
        out.close();
    }

    void vkForKey (int keysize, PrintWriter out)
    throws IllegalAccessException, InvocationTargetException {
        notify("Generating and testing Variable Key KAT (short); key size: " +
            keysize);

        Object[] args = {};         //actual arguments
        int count = keysize / 8;    // number of bytes in key material
        byte[] keyMaterial = new byte[count];
        byte[] pt = new byte[16];   // plaintext (16=default AES block size)
        byte[] cpt;                 // computed plaintext
        byte[] ct;                  // ciphertext
        int round = 0;              // current round ord. number
        Object skeys;               // algorithm secret key
        
        out.println("==========");
        out.println();
        out.println("KEYSIZE=" + keysize);
        out.println();
        out.println("PT=" + toString(pt));
        out.println();

        // The key bytes are organised and numbered as follows:
        //
        // |<- byte 0 ->|<- byte 1 ->|<- ... ->|<- byte n ->|
        // |<------------- bit_(n-1) to bit_0 ------------->|
        //
        for (int i = 0; i < count; i++) {
            for (int j = 0; j < 8; j++) {
                round++;
                out.println("I=" + round);
                keyMaterial[count-i-1] = (byte)(1 << (7 - j));
                out.println("KEY=" + toString(keyMaterial));

                args = new Object[] { keyMaterial };
                skeys = makeKey.invoke(null, args);
                keyCount++;

                args = new Object[] {pt, new Integer(0), skeys};
                ct = (byte[]) encrypt.invoke(null, args);
                encBlocks++;

                out.print("CT=" + toString(ct));

                args[0] = ct;
                cpt = (byte[]) decrypt.invoke(null, args);
                decBlocks++;

                if (! areEqual(pt, cpt))  // check if results match
                    out.print(" *** ERROR ***");

                out.println();
                out.println();
            }
            keyMaterial[count-i-1] = 0x00;
        }
    }


// Variable Text KAT methods
//...........................................................................

    void vtKAT (String fileName) {
        File f = new File(destination, fileName);
        PrintWriter out = null;
        try {
            out = new PrintWriter(new FileWriter(f) , true);
        } catch (IOException ex1) {
            halt("Unable to initialize <" + fileName + "> as a Writer:\n" +
                ex1.getMessage());
        }
        out.println();
        out.println("=========================");
        out.println();
        out.println("FILENAME:  \"" + fileName + "\"");
        out.println();
        out.println("Electronic Codebook (ECB) Mode");
        out.println("Variable Text Known Answer Tests");
        out.println();
        out.println("Algorithm Name: " + cipherName);
        out.println("Principal Submitter: " + SUBMITTER);
        out.println();

        try {
            for (int k = 0; k < keys.length; k++)
                vtForKey(keys[k], out);
        } catch (Exception x) {
            halt("Exception encountered in a " + cipherName +
                "_Algorithm method:\n" + x.getMessage());
        }
        out.println("==========");
        out.close();
    }

    void vtForKey (int keysize, PrintWriter out)
    throws IllegalAccessException, InvocationTargetException {
        notify("Generating and testing Variable Text KAT (short); key size: " +
            keysize);

        Object[] args = {};         //actual arguments
        byte[] keyMaterial = new byte[keysize / 8];
        byte[] pt = new byte[16];   // plaintext (16=default AES block size)
        byte[] ct;                  // ciphertext
        byte[] cpt;                 // computed plaintext
        int round = 0;              // current round ord. number

        args = new Object[] { keyMaterial };
        Object skeys = makeKey.invoke(null, args); // the cipher's session keys
        keyCount++;

        out.println("==========");
        out.println();
        out.println("KEYSIZE=" + keysize);
        out.println();
        out.println("KEY=" + toString(keyMaterial));
        out.println();

        args = new Object[3];
        args[1] = new Integer(0);
        args[2] = skeys;

        // The plaintext bytes are organised and numbered as follows:
        //
        // |<- byte 0 ->|<- byte 1 ->|<- ... ->|<- byte 15 ->|
        // |<--------------- bit_127 to bit_0 -------------->|
        //
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 8; j++) {
                round++;
                out.println("I=" + round);
                pt[15-i] = (byte)(1 << (7 - j));
                out.println("PT=" + toString(pt));

                args[0] = pt;
                ct = (byte[]) encrypt.invoke(null, args);
                encBlocks++;

                out.print("CT=" + toString(ct));

                args[0] = ct;
                cpt = (byte[]) decrypt.invoke(null, args);
                decBlocks++;

                if (! areEqual(pt, cpt))  // check if results match
                    out.print(" *** ERROR ***");

                out.println();
                out.println();
            }
            pt[15-i] = 0x00;
        }
    }


// utility static methods
// (copied from cryptix.util.core ArrayUtil and Hex classes)
//...........................................................................
    
    /**
     * Compares two byte arrays for equality.
     *
     * @return true if the arrays have identical contents
     */
    private static boolean areEqual (byte[] a, byte[] b) {
        int aLength = a.length;
        if (aLength != b.length)
            return false;
        for (int i = 0; i < aLength; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    private static final char[] HEX_DIGITS = {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };

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
