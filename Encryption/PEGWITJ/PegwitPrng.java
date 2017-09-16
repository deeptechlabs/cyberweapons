//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 * pegwit by George Barwood <george.barwood@dial.pipex.com>
 * 100% Public Domain
 * clearsigning code by Mr. Tines <tines@windsong.demon.co.uk>
 * also the filter mode support.
 *
 * This is the hashing pseudo-random number generator that takes
 * message entropy for session key and elliptic curve keypair generation
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 * @version 1.0, 6-Jul-1997 


*/

public class PegwitPrng { /* Whole structure will be hashed */

  	final static int HW = 5;
  	int count;        /* Count of words */
  	int[] seed = new int [2+HW*3];   /* Used to crank prng */
  	SHA1[] c = new SHA1[2];

  	public PegwitPrng()
  	{
  		clear();
	}

  	public void clear()
  	{
  		count=0;
      	for(int i=0; i<seed.length; ++i) seed[i] = 0;
  	}

	public void setSecret(InputStream f_key)
   	{
   		c[0] = new SHA1();
		hashProcessFile( new ASCIIInputStream(f_key), 1 );
      	c[0].finish();
		c[0].extract(seed, 1);
  		count = 1+HW;
   	}

   	private void initMAC()
   	{
   		c[0] = new SHA1();
      	c[1] = new SHA1();
		c[1].frob();       // pegwit's little anomaly
   	}

	private void hashProcessFile(InputStream f_inp, int barrel)
   	{
   		int n;
      	byte[] buffer = new byte[0x4000];
      	for(;;)
      	{
      		try {n=f_inp.read(buffer);}
      		catch (IOException e) {n=-1;};
      		if(n < 0) break;

         		for(int i=0;i< barrel;++i)
         		for(int j=0; j<n; ++j)
			{
				// This bizarrely seems to be what is required
				if(i==0) c[i].update(buffer[j]);
		}
         	if(n < 0x4000) break;
      	}
   	}

	public void setMAC(InputStream f_inp, int barrel)
   	{
   		int b;
      	initMAC();
		hashProcessFile( f_inp, barrel );
      	c[0].finish();
		c[0].extract(seed, 1+HW);
      	if(barrel > 1)
      	{
      		c[1].finish();
      		c[1].extract(seed, 1+2*HW);
      	}
      	count = 1 + (barrel+1)*HW;
   	}

	private String hashProcessASCII(DataInput f_inp,
   		DataOutput f_out, int barrel, boolean write)
   	{
  		int n;
      	String buffer = "";
      	long bytes = 0;
      	long control = 0;
      	String retval = null;
		boolean noeol;
		barrel = 1; // again, bizarrely, this seems required!
		for(;;)
		{
      		try{buffer = f_inp.readLine();} // does not seem to include EOL character
         		catch(IOException e) {break;}
         		if(null == buffer) break;

         		n = buffer.length();
			noeol = n == 0 || buffer.charAt(n-1) != '\n';


			if(n > 0x2000 && retval == null)
         			retval = PegwitMsg.warn_long_line;
			bytes+=n;

			if(!write) // read - drop out escapes
         		{
				if(buffer.equals(PegwitMsg.end_clearsign.substring
				(0,PegwitMsg.end_clearsign.length()-1))) break;

				if(buffer.length() >= 3)
				if(PegwitMsg.escape.equals(buffer.substring(0,3)))
            		buffer = buffer.substring(3,buffer.length());
         		}
         		// else could canonicalise (but that is truly a pre-filter)

      		for(int i=0; i<n; ++i)
      		{
         			byte b = (byte)buffer.charAt(i);
        			if(b >= 0x7F) ++control;
        			if(b < ' ' && b != '\n' && b != '\r'
          				&& b != '\t') ++control;

          			for(int j = 0; j<barrel; ++j) c[j].update(b);
      		}
			if(noeol)
			{
          			for(int j = 0; j<barrel; ++j) c[j].update((byte)'\n');
			}

	         	if(write)
      	   	{
         			try{
         				if( ((buffer.length() >=5) &&
            				(PegwitMsg.from.equalsIgnoreCase(buffer.substring(0,5)))) ||
						((buffer.length() >= 2) &&
	               			(PegwitMsg.leadEscape.equals(buffer.substring(0,2))))
      	         		) f_out.writeBytes(PegwitMsg.escape);

	            		f_out.writeBytes(buffer);
					if(noeol)f_out.writeBytes("\n");
            		} catch (IOException e)
            		{
            			return e.getMessage();
	            	}
			}
		}

 		if(control*6 > bytes)
		{
      		if (retval == null) retval = PegwitMsg.warn_control_chars;
         		else retval = retval + PegwitMsg.warn_control_chars;
	   	}

      	return retval;
   	}


	public String setASCIIMAC(DataInput f_inp, DataOutput f_out,
   			int barrel, boolean write)
   	{
   		int b;
      	initMAC();
		String err = hashProcessASCII(f_inp, f_out, 2, write);
      	c[0].finish();
		c[0].extract(seed, 1+HW);
      	if(barrel > 1)
      	{
      		c[1].finish();
      		c[1].extract(seed, 1+2*HW);
      	}
      	count = 1 + (barrel+1)*HW;
      	return err;
   	}

   	public String clearsign(DataInput f_inp,
   					DataOutput f_out)
   	{
   		try{
      		f_out.writeBytes(PegwitMsg.begin_clearsign);
      		String err = setASCIIMAC(f_inp, f_out, 2, true);
      		f_out.writeBytes(PegwitMsg.end_clearsign);
      		return err;
      	}
      	catch (IOException e) {return e.getMessage();}
   	}


   	void setTime()
	{
   		// Approximately the number of seconds since 1970
 		seed[1+3*HW] = (int) (System.currentTimeMillis() >> 10) & 0xFFFFFFFF;
  		count = 2 + 3*HW;
   	}

   	int next()
	{
   		int[] tmp = new int[HW];
  		short i,j;
      	SHA1 x = new SHA1();

      	++seed[0];
		for ( i = 0; i < count; ++i )
  		{
    			for ( j = 0; j < 4; ++j )
    			{
      			byte b = (byte)(0xFF & ( seed[i] >> (j*8) ) );
            		x.update(b);
    			}
  		}
		x.finish();
      	x.extract(tmp, 0);
      	return tmp[0];
   	}


	Eccrypt randomVlpoint()
   	{
   		Eccrypt v = new Eccrypt();
      	Vlpoint x = new Vlpoint();

		short[] buffer = new short[15];
		int i;
      	for(i=0; i<15;++i)
      	{
			buffer[i] = (short)(next() & 0xFFFF);
		}
		for(i=14; i>=0; --i)
		{
         		x.set(buffer[i]);
         		if(i != 14) v.shortLshift(16);
         		v.add(x);
      	}
      	x.clear();
      	return v;
   	}

	Vlpoint hashVlpoint(boolean secondBarrel)
   	{
   		int offset = secondBarrel ? 1+HW : 1;
   		Vlpoint v = new Vlpoint();
      	Vlpoint x = new Vlpoint();

      	for(int i=7;i>=0;--i)
      	{
			x.set((short)( 0xFFFF & (seed[i+offset]>>16)) );
			if(i<7) 
			{	v.shortLshift(16);
         			v.add(x);
			}
			x.set((short)( 0xFFFF & (seed[i+offset])) );
			v.shortLshift(16);
         		v.add(x);
      	}
      	x.clear();

      	return v;
   	}

} // end Prng class
