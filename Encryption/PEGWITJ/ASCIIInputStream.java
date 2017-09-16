//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 *
 * Nasty hacky machine specific class to filter out stuff that
 * C's ascii mode does (normalising line-ends and such).
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 * @version 1.0, 6-Jul-1997
 */

public class ASCIIInputStream extends FilterInputStream
{
	String sep;
	int hold;
	boolean dos;	

	/**
       * Constructs a new Ainput stream emulating 'C' non-binary I/O
       * @param in - the input stram to filter
       */
	public ASCIIInputStream(InputStream in)
	{
		super(in);
		sep = System.getProperty("line.separator");
		hold = 0;
		dos = sep.equals("\r\n");
	}

	private final int filter(int value)
	{
		if(dos && (value == 26)) return -1;
		else return value;
	}

	public int read() throws IOException
	{
		int retval;
		if(hold != 0) {retval = hold; hold = 0;}
		else retval = in.read();
		if(-1 == retval) return retval;
		if(retval!=sep.charAt(0)) return filter(retval);
		if(1 == sep.length()) return (int)'\n';
		else if (2 == sep.length())
		{
			hold = in.read();
			if(hold == sep.charAt(1))
			{
				hold=0;
				return (int) '\n';
			}
			else return retval;
		}
		else throw new IOException("Line terminator > 2 bytes");
	}


   public void mark(int readlimit)
   {
   }

   public boolean markSupported()
   {
   	return false;
   }

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
   	throw new IOException("ASCIIInputStream does not support mark/reset.");
   }

   public long skip(long n) throws IOException
   {
   	throw new IOException("ASCIIInputStream does not support skip");
   }
}

