//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 * pegwit by George Barwood <george.barwood@dial.pipex.com>
 * 100% Public Domain
 * clearsigning code by Mr. Tines <tines@windsong.demon.co.uk>
 * also the filter mode support.
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 * @version 1.0, 6-Jul-1997 
 */

public final class Pegwit {
	public static final String manual =// for command line
	   "Pegwit v8.7\n"
	+  "Usage (init/encrypt/decrypt/sign/verify) :\n"
	+  "-i <secret-key >public-key\n"
	+  "-e public-key plain cipher <random-junk\n"
	+  "-d cipher plain <secret-key\n"
	+  "-s plain <secret-key >signature\n"
	+  "-v public-key plain <signature\n"
	+  "-E plain cipher <key\n"
	+  "-D cipher plain <key\n"
	+  "-S text <secret-key >clearsigned-text\n"
	+  "-V public-key clearsigned-text >text\n"
	+  "-f[operation] [type pegwit -f for details]\n";

	public static final String filterManual = // for command line
  		"Pegwit [filter sub-mode]\n"
	+  "Usage (encrypt/decrypt/sign/verify) :\n"
	+  "-fe public-key random-junk <plain >ascii-cipher\n"
	+  "-fd secret-key <ascii-cipher >plain\n"
	+  "-fE key <plain >ascii-cipher\n"
	+  "-fD key <ascii-cipher >plain\n"
	+  "-fS secret-key <text >clearsigned-text\n"
	+  "-fV public-key <clearsigned-text >text\n";

   // UIF helpers
	public static final String pubkey_magic = "pegwit v8 public key =";
	public static final String err_output = "Pegwit, error writing output, disk full?";
	public static final String err_open_failed  = "Pegwit, error : failed to open ";
	public static final String err_bad_public_key = "Pegwit, error : public key must start with \"";
	public static final String err_signature = "signature did not verify\n";
	public static final String err_decrypt = "decryption failed\n";
	public static final String err_clearsig_header_not_found =
  	"Clearsignature header \"###\" not found\n";

   //Internal formats
   	public static final String begin_ascii = PegwitMsg.begin_clearsign;
	public static final String end_ckarmour = "### end pegwit v8.7 -fE encrypted text\n";
	public static final String end_pkarmour = "### end pegwit v8.7 -fe encrypted text\n";


	
   	public static boolean position (DataInput f_inp)
   	{ /* scan ascii file for ### introducer */
   		String buffer;
		for(;;)
      	{
      		try{buffer = f_inp.readLine();}
         		catch(IOException e) {break;}
         		if(null == buffer) break;
         		if(PegwitMsg.begin_clearsign.substring(0,3).equals(buffer.substring(0,3)))
         		return true;
      	}
      	return false;
   	}

   	private static int readsign(PegwitPrng p, DataInput f_inp,
      						DataOutput f_out)
   	{
   		if(!position(f_inp)) return 1;
      	p.setASCIIMAC(f_inp, f_out, 2, false);
      	return 0;
   	}

	private static final int BIG_BLOCK_SIZE = 0x1000;

	private static int symEncrypt(Vlpoint secret,
   						InputStream f_inp, OutputStream f_out)
   	{
   		Sqblock key = new Sqblock(secret);
      	Sqblock iv = new Sqblock();
      	byte[] buffer = new byte[BIG_BLOCK_SIZE+4];
  		int n = 0, err = 0;
  		byte pad = 0;
      	SquareCts ctx = new SquareCts(key);
      	key.clear();
      	for(;;)
      	{
      		try{ n = f_inp.read(buffer,0,BIG_BLOCK_SIZE);}
         		catch(IOException e) {break;}
         		if(n <= 0) break;
	      	if ( n < BIG_BLOCK_SIZE )
    			{
      			pad = 0;
      			if (n<Sqblock.BLOCKSIZE)
        				pad = (byte) (17-n);
      			else if ((n&1) != 0)
        				pad = 2;
            		for(int i=0; i<pad; ++i) buffer[n+i] = pad;
      			n += pad;
    			}

    			ctx.setIV( iv );
    			iv.increment();

      		ctx.encrypt(buffer, n);
      		try{ f_out.write(buffer, 0, n); }
      		catch(IOException e)
      		{
         			err = 1;
            		break;
      		}
      	}
		ctx.finish();
  		return err;
	}

	private static int symDecrypt( Vlpoint secret, InputStream f_inp,
   							OutputStream f_out) throws IOException
	{
  		Sqblock key = new Sqblock(secret);
      	Sqblock iv = new Sqblock();
      	byte[] b1 = new byte[BIG_BLOCK_SIZE+4];
      	byte[] b2 = new byte[BIG_BLOCK_SIZE+4];

  		SquareCts ctx = new SquareCts(key);

      	key.clear();
	   	int err = 0, n = 0;
		for(;;)
      	{
      		int i = 0;
      		if(n==0 || n == BIG_BLOCK_SIZE)
         		{
      			i = f_inp.read(b1, 0, BIG_BLOCK_SIZE);
         		}

    			if (n != 0)
    			{
      			if ( n < Sqblock.BLOCKSIZE ){err=1; break;}
      			if ( i == 1 )
      			{
        				++n;
        				b2[BIG_BLOCK_SIZE] = b1[0];
        				i = 0;
      			}

            		ctx.setIV(iv);
            		iv.increment();
            		ctx.decrypt(b2, n);

      			if ( (n & 1) != 0 )
      			{
        				byte pad = b2[n-1];
        				/* Check pad bytes are as expected */
        				if ( pad < 1 || pad > Sqblock.BLOCKSIZE ) {err=1; break;}
        				n -= pad;
          				for (int j=0;j<pad;j+=1)
            			if ( b2[n+j] != pad ) {err=1; break;}
      			}
            		try{f_out.write( b2, 0, n );}
            		catch (IOException e) {err=2; break;}
         		} // n nonzero

    			if ( i == 0 ) break;
         		byte[] tmp = b1; b1=b2; b2 = tmp; tmp=null; /* swap */
    			n = i;
  		}
      	ctx.finish();
      	return err;
	}


	public static String keygen(InputStream f_key, DataOutput f_out)//i
	{
  		PegwitPrng p = new PegwitPrng();
		p.setSecret( new ASCIIInputStream(f_key) );

    		Eccrypt secret = p.randomVlpoint();
      	Vlpoint pub = secret.makePublicKey();

      	String retval = null;

      	try{ f_out.writeBytes(pubkey_magic); }
      	catch(IOException e) {retval = e.getMessage();}
      	pub.put(f_out);
      	try{ f_out.writeBytes("\n"); }
      	catch(IOException e) {retval = e.getMessage();}

		secret.clear();
      	p.clear();

		return retval;
   	}

   	public static int pkEncrypt(InputStream f_key, InputStream f_sec,
   							InputStream f_inp, OutputStream f_out)//e
	throws IOException
	{
   		PegwitPrng p = new PegwitPrng();
		Eccrypt pub = new Eccrypt();
      	pub.get(f_key); /* should be a validity check here */

      	if ( f_sec != null ) p.setSecret( f_sec );

		// We need to make 2 passes over the input data, once for hashing 
		// into the session key, once to actually encrypt.

		// Copy into a byte array...
		InputStream f_mac = null;
		InputStream f_text = null;
		byte[] x = null;

		{
			ByteArrayOutputStream s = new ByteArrayOutputStream(BIG_BLOCK_SIZE);
			byte[] buffer = new byte[BIG_BLOCK_SIZE];
      		for(;;)
      		{
				int n;
      			try{ n = f_inp.read(buffer,0,BIG_BLOCK_SIZE);}
         			catch(IOException e) {break;}
				if(n <= 0) break;
				s.write(buffer, 0, n);
			}
			x = s.toByteArray();
			f_mac = new ByteArrayInputStream(x);
			f_text = new ByteArrayInputStream(x);
			x = null;
		}


      	p.setMAC(f_mac, 1);// << this is where the rewind is needed!

		p.setTime();
		Vlpoint session = p.randomVlpoint();
		if(f_out instanceof Base64Output)
			((Base64Output)f_out).writeLiteral(PegwitMsg.begin_clearsign);


      	Vlpoint[] keys;
      	keys = pub.encrypt(session);
      	keys[0].putBinary(f_out);

      	int err = symEncrypt( keys[1], f_text, f_out );

      	f_out.flush();
		if(f_out instanceof Base64Output)
			((Base64Output)f_out).writeLiteral(Pegwit.end_pkarmour);

      	p.clear();
      	session.clear();
      	return err;
	}

//does not position for "###" header
   	public static int pkDecrypt(InputStream f_key, InputStream f_in,
   							OutputStream f_out)//d
	throws IOException
   	{
   		PegwitPrng p = new PegwitPrng();
    		p.setSecret( f_key );

    		Eccrypt secret = p.randomVlpoint();
  		Vlpoint msg = new Vlpoint();
		msg.getBinary(f_in);
	   	Vlpoint session = secret.decrypt(msg);
   		int err = symDecrypt( session, f_in, f_out );

  		f_out.flush();
		p.clear();
   		secret.clear();
      	session.clear();
  		return err;
	}

	public static int sign(InputStream f_key, InputStream f_in,
   						DataOutput f_out) //s
   	{
   		PegwitPrng p = new PegwitPrng();
    		p.setSecret( f_key );
    		Eccrypt secret = p.randomVlpoint();

      	p.setMAC(f_in, 2);
      	Vlpoint mac = p.hashVlpoint(true);

      	Vlpoint session = new Vlpoint();
      	Ecsig sig = new Ecsig();

      	do
      	{
      		session = p.randomVlpoint();
         		secret.sign(session, mac, sig);
      	} while (sig.r.peek(0) == 0);
      	sig.s.put(f_out);
      	try{f_out.write((byte)':');} catch(IOException e) {;}
      	sig.r.put(f_out);

      	secret.clear();
      	p.clear();
      	session.clear();
 		return 0;
	}

   	public static int verify(InputStream f_key, InputStream f_sig,
   			InputStream f_in)//v
   	{
   		PegwitPrng p = new PegwitPrng();
		Eccrypt pub = new Eccrypt();

      	pub.get(f_key);
      	p.setMAC(f_in , 2);
      	Vlpoint mac = p.hashVlpoint(true);

      	Ecsig sig = new Ecsig();
      	sig.s.get(f_sig);
      	sig.r.get(f_sig);

      	int err = pub.verify(mac, sig) ? 0 : 1;

      	p.clear();
      	return err;
   	}

   	public static int ckEncrypt(InputStream f_key, InputStream f_in,
   				OutputStream f_out) throws IOException//E
   	{
   		PegwitPrng p = new PegwitPrng();
    		p.setSecret( f_key );
      	Vlpoint secret = p.hashVlpoint(false);
		if(f_out instanceof Base64Output)
			((Base64Output)f_out).writeLiteral(PegwitMsg.begin_clearsign);

      	int err = symEncrypt(secret, f_in, f_out);
      	p.clear();
      	secret.clear();
      	f_out.flush();
		if(f_out instanceof Base64Output)
			((Base64Output)f_out).writeLiteral(Pegwit.end_ckarmour);
      	return err;
   	}

//does not position for "###" header
	public static int ckDecrypt(InputStream f_key, InputStream f_in,
   				OutputStream f_out) // D
	throws IOException
   	{
   		PegwitPrng p = new PegwitPrng();
    		p.setSecret( f_key );
      	Vlpoint secret = p.hashVlpoint(false);
      	int err = symDecrypt(secret, f_in, f_out);
      	p.clear();
      	secret.clear();
      	f_out.flush();
      	return err;
   	}


	public static String clearsign(InputStream f_key, DataInput f_in,
   						DataOutput f_out) //S
   	{
   		PegwitPrng p = new PegwitPrng();
    		p.setSecret( f_key );
    		Eccrypt secret = p.randomVlpoint();

      	String err = p.clearsign(f_in, f_out);
      	Vlpoint mac = p.hashVlpoint(true);

      	Vlpoint session = new Vlpoint();
      	Ecsig sig = new Ecsig();

      	do
      	{
      		session = p.randomVlpoint();
         		secret.sign(session, mac, sig);
      	} while (sig.r.peek(0) == 0);

      	try{
      		sig.s.put(f_out);
      		f_out.write((byte)'\n');
      		sig.r.put(f_out);
      		f_out.write((byte)'\n');
      	} catch (IOException e) {;}

      	secret.clear();
      	p.clear();
      	session.clear();
 		return err;
	}

// Does not position to "###"
   	public static int clearverify(InputStream f_key, DataInput f_in,
   						DataOutput f_out) // V
   	{
   		PegwitPrng p = new PegwitPrng();
		Eccrypt pub = new Eccrypt();

      	pub.get(f_key);

		p.setASCIIMAC(f_in, f_out, 2, false);
      	Vlpoint mac = p.hashVlpoint(true);

      	Ecsig sig = new Ecsig();
      	sig.s.getASCII(f_in);
      	sig.r.getASCII(f_in);

      	int err = pub.verify(mac, sig) ? 0 : 1;

      	p.clear();
      	return err;
   	}

	public static InputStream get_Pubkey(InputStream f_key)
   	throws IOException
   	{
/* Either the file is in the format output by
** pegwit -i, or contains the key data in one
** or more chunks surrounded by {}.  This should
** allow pegwit to cope with keys malformed
** into .sig files or otherwise chopped into
** sections < 80 clumens in length */

		int i;
   		int c = 0;
   		boolean inChunk = false;

   		for(i=0;i<pubkey_magic.length();++i)
   		{
   			c = f_key.read();
         		if(c != (byte) pubkey_magic.charAt(i)) break;
      	}

   		/* made it to the end - accept it */
   		if(i == pubkey_magic.length()) return f_key;

		/* divergence - check {}'d bits */
		ByteArrayOutputStream b = null;
      	InputStream result = null;

   		for(i=0;;c = f_key.read())
   		{
   			if(-1 == c) break;
			else if((byte) '{' == (byte) c) inChunk = true;
      		else if ((byte)'}' == (byte) c) inChunk = false;
      		else if (inChunk)
      		{
      			/* failed to read magic token */
      			if(i<pubkey_magic.length())
         			{
         				if(c != (byte)pubkey_magic.charAt(i)) break;
            			else ++i;
         			}
         			else
         			{
         				if(b==null) b = new ByteArrayOutputStream();
               			b.write(c);
         			}
			}

   		}
      	if(b!=null)
      	{
      		byte[] buff = b.toByteArray();
         		result = (InputStream) new ByteArrayInputStream(buff);
      	}
		return result;
	}

}


