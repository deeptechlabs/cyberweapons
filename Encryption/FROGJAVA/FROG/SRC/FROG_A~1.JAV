// $Id: $
//
// $Log: $
// Revision 1.0  1998/03/24  raif
// + start of history.
// Modified      1998/06/10 billy
/*

FILENAME:  frog.c

AES Submission: FROG

Principal Submitter: TecApro

Source code is documented according to the Supporting Documentation
of the AES Submission Package.

*/
//               Added the frog algorithm
// Modified      1998/06/11 billy
//               Corrections, got a working version                 
//
// $Endlog$
/*
 * Copyright (c) 1997, 1998 Systemics Ltd on behalf of
 * the Cryptix Development Team. All rights reserved.
 */
package frog;

import java.io.PrintWriter;
import java.security.InvalidKeyException;

/* Internal FROG classes */

class frog_IterKey {
  public int xorBu[];
  public int SubstPermu[];
  public int BombPermu[];

  frog_IterKey()
  {
    xorBu = new int[frog_Algorithm.BLOCK_SIZE];
    SubstPermu = new int[256];
    BombPermu = new int[frog_Algorithm.BLOCK_SIZE];
  }

  public static int size()
  {
    return frog_Algorithm.BLOCK_SIZE*2+256;
  }

  public void setValue( int index, int value )
  {
    if ( value < 0 ) value = 256 + value;
    if ( index < frog_Algorithm.BLOCK_SIZE ) 
	  xorBu[index] = value;
	else if ( index < frog_Algorithm.BLOCK_SIZE + 256 ) 
	  SubstPermu[index-frog_Algorithm.BLOCK_SIZE] = value;
	else
	  BombPermu[index-frog_Algorithm.BLOCK_SIZE-256] = value;  
  }

  public int getValue( int index )
  {
    if ( index < frog_Algorithm.BLOCK_SIZE ) 
	  return xorBu[index];
	else if ( index < frog_Algorithm.BLOCK_SIZE + 256 ) 
	  return SubstPermu[index-frog_Algorithm.BLOCK_SIZE];
	else
	  return BombPermu[index-frog_Algorithm.BLOCK_SIZE-256];  
  }
  public void CopyFrom( frog_IterKey ori )
  {
    int i;
	for (i=0;i<ori.xorBu.length;i++)
	  xorBu[i] = ori.xorBu[i];
	for (i=0;i<ori.SubstPermu.length;i++)
	  SubstPermu[i] = ori.SubstPermu[i];
	for (i=0;i<ori.BombPermu.length;i++)
      BombPermu[i] = ori.BombPermu[i];
  }
}

class frog_procs {
  
  static public int numIter = 8;

  /* Values defined from RAND Corporation's "A Million Random Digits" */

  private static int[] randomSeed = {
	  113, 21,232, 18,113, 92, 63,157,124,193,166,197,126, 56,229,229,
	  156,162, 54, 17,230, 89,189, 87,169,  0, 81,204,  8, 70,203,225,
	  160, 59,167,189,100,157, 84, 11,  7,130, 29, 51, 32, 45,135,237,
	  139, 33, 17,221, 24, 50, 89, 74, 21,205,191,242, 84, 53,  3,230,
	  231,118, 15, 15,107,  4, 21, 34,  3,156, 57, 66, 93,255,191,  3,
	   85,135,205,200,185,204, 52, 37, 35, 24, 68,185,201, 10,224,234,
		7,120,201,115,216,103, 57,255, 93,110, 42,249, 68, 14, 29, 55,
	  128, 84, 37,152,221,137, 39, 11,252, 50,144, 35,178,190, 43,162,
	  103,249,109,  8,235, 33,158,111,252,205,169, 54, 10, 20,221,201,
	  178,224, 89,184,182, 65,201, 10, 60,  6,191,174, 79, 98, 26,160,
	  252, 51, 63, 79,  6,102,123,173, 49,  3,110,233, 90,158,228,210,
	  209,237, 30, 95, 28,179,204,220, 72,163, 77,166,192, 98,165, 25,
	  145,162, 91,212, 41,230,110,  6,107,187,127, 38, 82, 98, 30, 67,
	  225, 80,208,134, 60,250,153, 87,148, 60, 66,165, 72, 29,165, 82,
	  211,207,  0,177,206, 13,  6, 14, 92,248, 60,201,132, 95, 35,215,
	  118,177,121,180, 27, 83,131, 26, 39, 46, 12};
  
  static public int[] makePermutation( int[] permu )
	/*	Receives an arbitrary byte array of (lastElem -1) elements and
		returns a permutation with values between 0 and lastElem.
		Reference Text: section B.1.3   */
  {
    int use[] = new int[256];
	int i, j, k, count, last;
    int lastElem = permu.length - 1;

	/* Initialize use array */
	for (i=0;i<=lastElem;use[i]=i,i++);

	last = lastElem;
    j = 0;
	/* Fill permutation with non-sequencial, unique values */
    for (i=0; i<lastElem; i++ )
    {
      j = (j+permu[i]) % (last+1);
	  permu[i] = use[j];
      /* Remove use[index] value from use array */
	  if ( j < last )
	    for ( k=j; k <= last-1; use[k] = use[k+1], k++ );
      last--;
	  if ( j > last ) j = 0;
    }
    permu[lastElem] = use[0];
	return permu;
  }

  static public int[] invertPermutation( int[] orig )
  /* Inverts a permutation */
  {
    int invert[] = new int[256];
    int i, lastElem = orig.length-1;
    for ( i=0; i<=lastElem; i++ ) invert[orig[i]] = i;
    return invert;
  }
  
  public static byte[] encryptFrog( byte[] plainText, frog_IterKey[] key )
  /* Encrypt plainText using internalKey - (internal cycle) See B.1.1 */
  {
    byte ite, ib;
    for ( ite=0; ite<numIter; ite++ )
    {
      for ( ib=0; ib < frog_Algorithm.BLOCK_SIZE; ib++ )
      {
        plainText[ib] ^= key[ite].xorBu[ib];
	if ( plainText[ib] < 0 )
	  plainText[ib] = (byte) key[ite].SubstPermu[plainText[ib]+256];
	else
	  plainText[ib] = (byte) key[ite].SubstPermu[plainText[ib]];
	if ( ib < frog_Algorithm.BLOCK_SIZE-1 ) 
    	  plainText[ib+1] ^= plainText[ib];
	else
	  plainText[0] ^= plainText[frog_Algorithm.BLOCK_SIZE-1];
	plainText[key[ite].BombPermu[ib]] ^= plainText[ib];
      }
    }
    return plainText;
  }

  public static byte[] decryptFrog( byte[] cipherText, frog_IterKey[] key )
  /* Decrypt cipherText using internalKey - (internal cycle) See B.1.1 */
  {
    int ib, ite;

    for ( ite = numIter-1; ite >= 0; ite-- )
    {
      for ( ib = frog_Algorithm.BLOCK_SIZE-1; ib >= 0; ib-- )
	  {
	    cipherText[key[ite].BombPermu[ib]] ^= cipherText[ib];
	    if ( ib < frog_Algorithm.BLOCK_SIZE-1 )
	      cipherText[ib+1] ^= cipherText[ib];
	    else
		  cipherText[0] ^= cipherText[frog_Algorithm.BLOCK_SIZE-1];
	    if ( cipherText[ib]<0 )
		  cipherText[ib] = (byte)key[ite].SubstPermu[cipherText[ib]+256];
		else
		  cipherText[ib] = (byte)key[ite].SubstPermu[cipherText[ib]];
	    cipherText[ib] ^= key[ite].xorBu[ib];
	  }
    }
	return cipherText;
  }
  
  public static frog_IterKey[] makeInternalKey( byte decrypting, frog_IterKey[] keyori )
  /* Processes unstructured internalKey into a valid internalKey.
     Reference Text: section B.1.2 */
  {
    byte[] used = new byte[frog_Algorithm.BLOCK_SIZE];
    int ite, j, i, k, l;
    int posi;
    byte change;
    frog_IterKey[] key = new frog_IterKey[ frog_procs.numIter ];
    for ( i=0; i < frog_procs.numIter; i++ )
	{
      key[i] = new frog_IterKey();
	  key[i].CopyFrom( keyori[i] );
	}
    posi = 1;
    for ( ite = 0; ite < numIter; ite ++ )
    {
      key[ite].SubstPermu = makePermutation( key[ite].SubstPermu );

	  if ( decrypting == 1 ) key[ite].SubstPermu = invertPermutation(key[ite].SubstPermu);

  	  /* See B.1.1a */
	  key[ite].BombPermu = makePermutation(key[ite].BombPermu );

  	  /* Join smaller cycles in BombPermu into one cycle
	     (See B.1.1b for rational and B.1.4 for code) */
      for ( i=0; i<frog_Algorithm.BLOCK_SIZE; used[i]=0, i++ );
      j = 0;
	  for ( i=0; i<frog_Algorithm.BLOCK_SIZE-1; i++ )
	  {
    	if ( key[ite].BombPermu[j] == 0 )
	    {
	      k = j;
          do {
		    k = ( k + 1 ) % frog_Algorithm.BLOCK_SIZE;
		  } while ( used[k]!=0 );
		  key[ite].BombPermu[j] = k;
		  l = k;
		  while ( key[ite].BombPermu[l]!=k ) l = key[ite].BombPermu[l];
		  key[ite].BombPermu[l] = 0;
	    }
	    used[j] = 1;
	    j = key[ite].BombPermu[j];
	  }

      /* Remove references to next element within BombPermu.
         See B.1.1c for rational and B.1.4.b for code. */
      for (i = 0; i < frog_Algorithm.BLOCK_SIZE; i++) {
        j = (i == frog_Algorithm.BLOCK_SIZE-1) ? 0 : i + 1;
        if (key[ite].BombPermu[i] == j) {
	      k = (j == frog_Algorithm.BLOCK_SIZE-1) ? 0 : j + 1;
	      key[ite].BombPermu[i] = k;
        }
      }
    }
    return key;
  }
  
  static public frog_IterKey[] hashKey(byte[] binaryKey)
  {

	/* Hash binaryKey of keyLen bytes into randomKey
	   Reference Text: section B.1.2 */

    byte[] buffer = new byte[frog_Algorithm.BLOCK_SIZE];
    frog_IterKey[] simpleKey = new frog_IterKey[ frog_procs.numIter ];
    frog_IterKey[] internalKey = new frog_IterKey[ frog_procs.numIter ];
    int iSeed, iFrase;
    int sizeKey,i,posi,size;
    int keyLen, last;
    for ( i = 0; i < frog_procs.numIter; i++ ) simpleKey[i] = new frog_IterKey();
    for ( i = 0; i < frog_procs.numIter; i++ ) internalKey[i] = new frog_IterKey();
    keyLen = binaryKey.length;
    sizeKey = frog_IterKey.size() * frog_procs.numIter;

	/* Initialize SimpleKey with user supplied key material and random seed.
       See B.1.2a */

    iSeed = 0; iFrase = 0;
    for ( i = 0; i < sizeKey; i++ )
    {
      simpleKey[i / frog_IterKey.size()].setValue(
	    i%frog_IterKey.size(), 
		randomSeed[iSeed] ^ binaryKey[iFrase]
	  );
	  if ( iSeed<250 ) iSeed++; else iSeed = 0;
	  if ( iFrase<keyLen-1 ) iFrase++; else iFrase = 0;
    }

    /* Convert simpleKey into a valid internal key (see B.1.2b) */

    simpleKey = makeInternalKey( frog_Algorithm.DIR_ENCRYPT, simpleKey );
    for ( i = 0; i < frog_Algorithm.BLOCK_SIZE; buffer[i++] = 0 );

	/* Initialize IV vector (see B.1.2c) */

    last = keyLen - 1;
    if ( last > frog_Algorithm.BLOCK_SIZE ) last = frog_Algorithm.BLOCK_SIZE-1;
    for ( i = 0; i <= last; buffer[i] ^= binaryKey[i], i++ );
    buffer[0] ^= keyLen;

    posi = 0;

    /* Fill randomKey with the cipher texts produced successive
       encryptions (see B.1.2.c) */

    do {
      buffer = encryptFrog( buffer, simpleKey );
	  size = sizeKey - posi;
	  if ( size > frog_Algorithm.BLOCK_SIZE ) size = frog_Algorithm.BLOCK_SIZE;
	  for (i=0;i<frog_Algorithm.BLOCK_SIZE;i++)
	    if ( buffer[i] < 0 )
	      internalKey[(posi+i)/frog_IterKey.size()].setValue((posi+i)%frog_IterKey.size(), buffer[i]+256 ); 
		else
	      internalKey[(posi+i)/frog_IterKey.size()].setValue((posi+i)%frog_IterKey.size(), buffer[i] ); 
	  posi += size;
    } while ( posi != sizeKey );
    return internalKey;
  }

  static public byte[] shif1bitLeft( byte[] buffer )
  
  /* moves an entire block of size bytes 1 bit to the left */
  
  {
    byte[] result = new byte[ frog_Algorithm.BLOCK_SIZE ];
	int i;
	for ( i = frog_Algorithm.BLOCK_SIZE-1; i >= 0 ; i-- ) result[i] = buffer[i];
	for ( i = frog_Algorithm.BLOCK_SIZE-1; i >= 0 ; i-- )
	{
	  result[i] = (byte) (result[i] << 1);
	  if ( i > 0 ) 
	    result[i] |= result[i-1] >> 7;
	}
	return result;
  }
}

class frog_InternalKey {
  public frog_IterKey[] internalKey, keyE, keyD;
 
  public void setValue( int index, int value )
  {
    internalKey[index / frog_IterKey.size()].setValue( index % frog_IterKey.size(), value );
  }

  public int getValue( int index )
  {
    return internalKey[index / frog_IterKey.size()].getValue( index % frog_IterKey.size() );
  }
}

//...........................................................................
/**
 * frog is ....<p>
 *
 * frog was written by ....<p>
 *
 * Portions of this code are <b>Copyright</b> &copy; 1997, 1998
 * <a href="http://www.systemics.com/">Systemics Ltd</a> on behalf of the
 * <a href="http://www.systemics.com/docs/cryptix/">Cryptix Development Team</a>.
 * <br>All rights reserved.<p>
 *
 * <b>$Revision: $</b>
 * @author  Raif S. Naffah
 */
public final class frog_Algorithm // implicit no-argument constructor
{
// Debugging methods and variables
//...........................................................................

    static final String NAME = "frog_Algorithm";
    static final boolean IN = true, OUT = false;

    static final boolean DEBUG = frog_Properties.GLOBAL_DEBUG;
    static final int debuglevel = DEBUG ? frog_Properties.getLevel(NAME) : 0;
    static final PrintWriter err = DEBUG ? frog_Properties.getOutput() : null;

    static final boolean TRACE = frog_Properties.isTraceable(NAME);

    static void debug (String s) { err.println(">>> "+NAME+": "+s); }
    static void trace (boolean in, String s) {
        if (TRACE) err.println((in?"==> ":"<== ")+NAME+"."+s);
    }
    static void trace (String s) { if (TRACE) err.println("<=> "+NAME+"."+s); }


// Constants and variables
//...........................................................................

    static final int BLOCK_SIZE = 16; // bytes in a data-block
	static final byte DIR_ENCRYPT = 0;
        static final byte DIR_DECRYPT = 1;

    private static final char[] HEX_DIGITS = {
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };


// Static code - to intialise S-box and permutation tables if any
//...........................................................................

    static {
        long time = System.currentTimeMillis();

if (DEBUG && debuglevel > 6) {
System.out.println("Algorithm Name: "+frog_Properties.FULL_NAME);
System.out.println("Electronic Codebook (ECB) Mode");
System.out.println();
}
        //
        // precompute eventual S-box tables
        //
        time = System.currentTimeMillis() - time;

if (DEBUG && debuglevel > 8) {
System.out.println("==========");
System.out.println();
System.out.println("Static Data");
System.out.println();
//
// any other println() statements
//
System.out.println();
System.out.println("Total initialization time: "+time+" ms.");
System.out.println();
}
    }


// Basic API methods
//...........................................................................

    /**
     * Expand a user-supplied key material into a session key.
     *
     * @param key  The 128/192/256-bit user-key to use.
     * @return  This cipher's round keys.
     * @exception  InvalidKeyException  If the key is invalid.
     */
    public static synchronized Object makeKey (byte[] k)
    throws InvalidKeyException {
if (DEBUG) trace(IN, "makeKey("+k+")");
if (DEBUG && debuglevel > 7) {
System.out.println("Intermediate Session Key Values");
System.out.println();
System.out.println("Raw="+toString(k));
}
        //
        //...
        //
        Object sessionKey = null;

        frog_InternalKey intkey = new frog_InternalKey();
 	    /* Fill internal key with hashed keyMaterial */
        intkey.internalKey = frog_procs.hashKey( k );
 	    /* Convert internalKey into a valid format for encrypt and decrypt (see B.1.2.e) */
        intkey.keyE = frog_procs.makeInternalKey( frog_Algorithm.DIR_ENCRYPT, intkey.internalKey );
        intkey.keyD = frog_procs.makeInternalKey( frog_Algorithm.DIR_DECRYPT, intkey.internalKey );
        
        sessionKey = intkey;
        //
        // ...
        //
if (DEBUG && debuglevel > 7) {
System.out.println("...any intermediate values");
System.out.println();
}
if (DEBUG) trace(OUT, "makeKey()");
        return sessionKey;
    }

    /**
     * Encrypt exactly one block of plaintext.
     *
     * @param in          The plaintext.
     * @param inOffset    Index of in from which to start considering data.
     * @param sessionKey  The session key to use for encryption.
     * @return The ciphertext generated from a plaintext using the session key.
     */
    public static byte[]
    blockEncrypt (byte[] in, int inOffset, Object sessionKey) {
if (DEBUG) trace(IN, "blockEncrypt("+in+", "+inOffset+", "+sessionKey+")");
if (DEBUG && debuglevel > 6) System.out.println("PT="+toString(in, inOffset, BLOCK_SIZE));
        //
        // ....
        //
        byte[] result = new byte[BLOCK_SIZE];
    	int i;
	    //
	    // Null - just copy it straight across.
	    // Guarunteed to work, guarunteed to be insecure!
	    //
	    for ( i = 0; i < frog_Algorithm.BLOCK_SIZE; i++ ) result[i] = in[i+inOffset];
	    result = frog_procs.encryptFrog( result, ((frog_InternalKey) sessionKey).keyE );

if (DEBUG && debuglevel > 6) {
System.out.println("CT="+toString(result));
System.out.println();
}
if (DEBUG) trace(OUT, "blockEncrypt()");
        return result;
    }

    /**
     * Decrypt exactly one block of ciphertext.
     *
     * @param in          The ciphertext.
     * @param inOffset    Index of in from which to start considering data.
     * @param sessionKey  The session key to use for decryption.
     * @return The plaintext generated from a ciphertext using the session key.
     */
    public static byte[]
    blockDecrypt (byte[] in, int inOffset, Object sessionKey) {
if (DEBUG) trace(IN, "blockDecrypt("+in+", "+inOffset+", "+sessionKey+")");
if (DEBUG && debuglevel > 6) System.out.println("CT="+toString(in, inOffset, BLOCK_SIZE));
        //
        // ....
        //
        byte[] result = new byte[BLOCK_SIZE];
  	    int i;
	    for ( i = 0; i < frog_Algorithm.BLOCK_SIZE; i++ ) result[i] = in[i+inOffset];
	    result = frog_procs.decryptFrog( result, ((frog_InternalKey) sessionKey).keyD );

if (DEBUG && debuglevel > 6) {
System.out.println("PT="+toString(result));
System.out.println();
}
if (DEBUG) trace(OUT, "blockDecrypt()");
        return result;
    }

    /** A basic symmetric encryption/decryption test. */ 
    public static boolean self_test() { return self_test(BLOCK_SIZE); }


// own methods
//...........................................................................
    
    /** @return The length in bytes of the Algorithm input block. */
    public static int blockSize() { return BLOCK_SIZE; }

    private static boolean self_test (int keysize) {
if (DEBUG) trace(IN, "self_test("+keysize+")");
        boolean ok = false;
        try {
            byte[] kb = new byte[keysize];
            byte[] pt = new byte[BLOCK_SIZE];
            int i;

            for (i = 0; i < keysize; i++)
                kb[i] = (byte) i;
            for (i = 0; i < BLOCK_SIZE; i++)
                pt[i] = (byte) i;

if (DEBUG && debuglevel > 6) {
System.out.println("==========");
System.out.println();
System.out.println("KEYSIZE="+(8*keysize));
System.out.println("KEY="+toString(kb));
System.out.println();
}
            Object key = makeKey(kb);

if (DEBUG && debuglevel > 6) {
System.out.println("Intermediate Ciphertext Values (Encryption)");
System.out.println();
}
            byte[] ct =  blockEncrypt(pt, 0, key);

if (DEBUG && debuglevel > 6) {
System.out.println("Intermediate Plaintext Values (Decryption)");
System.out.println();
}
            byte[] cpt = blockDecrypt(ct, 0, key);

            ok = areEqual(pt, cpt);
            if (!ok)
                throw new RuntimeException("Symmetric operation failed");
        } catch (Exception x) {
if (DEBUG && debuglevel > 0) {
    debug("Exception encountered during self-test: " + x.getMessage());
    x.printStackTrace();
}
        }
if (DEBUG && debuglevel > 0) debug("Self-test OK? " + ok);
if (DEBUG) trace(OUT, "self_test()");
        return ok;
    }

    private static boolean prueba (int keysize) {
        boolean ok = false;
        try {
            byte[] kb = new byte[keysize];
            byte[] pt = new byte[BLOCK_SIZE];
            int i;

            for (i = 0; i < keysize; i++)
                kb[i] = (byte) 0;
            for (i = 0; i < BLOCK_SIZE; i++)
                pt[i] = (byte) 0;
//            pt[15] = -128;

            Object key = makeKey(kb);

            byte[] ct =  blockEncrypt(pt, 0, key);
System.out.println("keysize="+keysize);
            for ( i = 0; i < 16; i++ )
            {
              if ( ct[i]<0 )
                System.out.print( (ct[i]+256)+"," );
              else
                System.out.print( ct[i]+"," );
            }
            System.out.println("");

            byte[] cpt = blockDecrypt(ct, 0, key);

            ok = areEqual(pt, cpt);
            if (!ok)
              System.out.println("No se desencripto bien");
        } catch (Exception x) {
        }
        return ok;
    }
// utility static methods (from cryptix.util.core ArrayUtil and Hex classes)
//...........................................................................
    
    /** @return True iff the arrays have identical contents. */
    private static boolean areEqual (byte[] a, byte[] b) {
        int aLength = a.length;
        if (aLength != b.length)
            return false;
        for (int i = 0; i < aLength; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    /**
     * Returns a string of hexadecimal digits from a byte array. Each
     * byte is converted to 2 hex symbols.
     */
    private static String toString (byte[] ba) {
        return toString(ba, 0, ba.length);
    }
    private static String toString (byte[] ba, int offset, int length) {
        char[] buf = new char[length * 2];
        for (int i = offset, j = 0, k; i < offset+length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }


// main(): use to generate the Intermediate Values KAT
//...........................................................................

    public static void main (String[] args) {
        prueba( 24 );
        self_test(16);
        self_test(24);
        self_test(32);
    }
}
