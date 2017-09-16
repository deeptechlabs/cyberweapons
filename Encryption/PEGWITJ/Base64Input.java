//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;

/*
**
**  BASE64 armour reading by Mr. Tines <tines@windsong.demon.co.uk>
*/

public class Base64Input extends FilterInputStream
{
	private final static int LINE_LEN = 48; /* binary bytes per armour line */
	private final static int MAX_LINE_SIZE = 64; /* expands to this plus \n\0 over*/

	private final static String err_decode_failed=
"Pegwit; Out of range characters encountered in ASCII armouring.\n"+
"Terminating.\n";
	private final static byte[] asctobin = {
   	-128,-128,-128,-128,-128,-128,-128,-128,
   	-128,-128,-128,-128,-128,-128,-128,-128,
   	-128,-128,-128,-128,-128,-128,-128,-128,
   	-128,-128,-128,-128,-128,-128,-128,-128,
   	-128,-128,-128,-128,-128,-128,-128,-128,
   	-128,-128,-128,0076,-128,-128,-128,0077,
   	0064,0065,0066,0067,0070,0071,0072,0073,
   	0074,0075,-128,-128,-128,-128,-128,-128,
   	-128,0000,0001,0002,0003,0004,0005,0006,
   	0007,0010,0011,0012,0013,0014,0015,0016,
   	0017,0020,0021,0022,0023,0024,0025,0026,
   	0027,0030,0031,-128,-128,-128,-128,-128,
   	-128,0032,0033,0034,0035,0036,0037,0040,
   	0041,0042,0043,0044,0045,0046,0047,0050,
   	0051,0052,0053,0054,0055,0056,0057,0060,
   	0061,0062,0063,-128,-128,-128,-128,-128};

	private final static byte PAD = (byte) '=';
   	private final static byte ZERO = (byte)'A';

	byte[] binaryBuffer;
	int bytesLeft = 0;
   	boolean more = true;
   	int readHead = 0;

	public Base64Input(DataInputStream in)
   	{
   		super((InputStream)in);
      	binaryBuffer = new byte[LINE_LEN];
   	}

	public int available() throws IOException
   	{
   		return bytesLeft + 3*super.available()/4;
   	}

   	public void mark(int readlimit)
   	{
   	}

   	public boolean markSupported()
   	{
   		return false;
   	}

   	private boolean qppad(byte[] buf, int i)
   	{
   		return
      	buf[i  ] == (byte)'=' &&
      	buf[i+1] == (byte)'3' &&
      	buf[i+2] == (byte)'D' &&
      	buf[i+3] == (byte)'=' &&
      	buf[i+4] == (byte)'3' &&
      	buf[i+5] == (byte)'D';
   	}

	private boolean decodeBuffer(byte[] inBuf) throws IOException
   	{
   		readHead = 0;
      	bytesLeft = 0;
      	boolean hitPadding = false;
		int bp = 0;
      	int c1,c2,c3,c4;

      	while(inBuf[bp] != 0 && !hitPadding)
      	{
			int toWrite = 0;
			if(inBuf[bp+3] == PAD)
         		{
         			hitPadding = true;
            		if(inBuf[bp+2] == PAD || qppad(inBuf, bp+2))
            		{
            			toWrite=1;
               			inBuf[bp+2] = ZERO;
            		}
            		else
            			toWrite=2;
            		inBuf[bp+3] = ZERO;
			}
         		else
         			toWrite = 3;

      		if((inBuf[bp+0] & 0x80) != 0
         						|| ((c1 = asctobin[inBuf[bp+0]]) & 0x80) !=0 ||
            	(inBuf[bp+1] & 0x80) != 0
            					|| ((c2 = asctobin[inBuf[bp+1]]) & 0x80) != 0 ||
      	   	(inBuf[bp+2] & 0x80) != 0
            					|| ((c3 = asctobin[inBuf[bp+2]]) & 0x80) != 0 ||
            	(inBuf[bp+3] & 0x80) != 0
            					|| ((c4 = asctobin[inBuf[bp+3]]) & 0x80) != 0)
         		{
         			throw new IOException(err_decode_failed);
         		}

     			bp += 4;
         		binaryBuffer[bytesLeft] = (byte)((c1 << 2) | (c2 >>> 4));
         		++bytesLeft; if(toWrite<2) continue;
      		binaryBuffer[bytesLeft] = (byte)((c2 << 4) | (c3 >>> 2));
         		++bytesLeft; if(toWrite<3) continue;
      		binaryBuffer[bytesLeft] = (byte)((c3 << 6) | c4);
         		++bytesLeft;
      	}
      	return !hitPadding;
   	}

	public int read() throws IOException
   	{
   		if(bytesLeft >= 1)
      	{
      		int retval = binaryBuffer[readHead] & 0xFF;
         		++readHead;
         		--bytesLeft;
         		return retval;
      	}
		else
      	{
         		if (!more) return -1;
			String line = ((DataInputStream) in).readLine();
         		more = (line!=null);
         		if (more) more = line.charAt(0) != '#';
         		if(more)
         		{
         			byte[] inBuf = new byte[line.length()+1];
         			line.getBytes(0,line.length(),inBuf,0);
         			inBuf[line.length()] = 0;

	         		for(int i = line.length();
					i>0 && inBuf[i] < (byte)' ';
            	 		--i) inBuf[i] = 0;

         			more = decodeBuffer(inBuf);
         			}
         		return read();
      	}
	}//read()

   	public int read(byte[] b) throws IOException
   	{
   		return read(b, 0, b.length);
	}

   	public int read(byte[] b, int offset, int length) throws IOException
   	{
   		int retval = 0;
      	for(;retval<length;++retval)
      	{
      		int k = read();
         		if(k == -1) break;
         		b[retval+offset] = (byte) k;
      	}
		return retval;
	}

	public void reset() throws IOException
   	{
   		throw new IOException("Base64Input does not support mark/reset.");
   	}

   	public long skip(long n) throws IOException
   	{
   		throw new IOException("Base64Input does not support skip");
   	}
}
