//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;

/*
**
**  BASE64 armour reading by Mr. Tines <tines@windsong.demon.co.uk>
*/

public class Base64Output extends FilterOutputStream
{
	private final static int MAX_LINE_SIZE = 64; /* expands to this plus \n\0 over*/
	byte[] asciiBuffer;
	int writeHead = 0;
   	byte[] bin;
   	int space=MAX_LINE_SIZE;
   	int inBin = 0;

 	private static final String bintoasc
   		= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   	private final static byte PAD = (byte) '=';
   	private final static byte ZERO = (byte)'A';

	public Base64Output(DataOutputStream out)
   	{
   		super((OutputStream) out);
      	asciiBuffer = new byte[MAX_LINE_SIZE+2];
      	bin = new byte[3];
   	}

	public void writeLiteral(String tag) throws IOException
	{
		int l = tag.length();
		for(int i=0; i < l; ++i)
		{
      		out.write((byte)tag.charAt(i));
		}
	}


   	public void close() throws IOException
   	{
   		super.close();
   	}

   	private void flushBuffer() throws IOException
   	{
   		if(writeHead == 0) return;
      	asciiBuffer[writeHead] = (byte)'\n';
      	++writeHead;
      	out.write(asciiBuffer, 0, writeHead);
      	writeHead = 0;
      	space=MAX_LINE_SIZE;
   	}

   	private void encode()
   	{
   		if(inBin < 3)
      	{
      		bin[inBin] = 0;
         		asciiBuffer[writeHead+2] =
         		asciiBuffer[writeHead+3] = PAD;
      	}
      	asciiBuffer[writeHead]   = (byte) bintoasc.charAt((0xFF&bin[0])>>>2);
      	asciiBuffer[writeHead+1] = (byte) bintoasc.charAt(((bin[0]<<4) & 0x30)
      									|((bin[1] >>> 4) &0x0F));
      	if(inBin > 1)
      	{
      		asciiBuffer[writeHead+2] = (byte) bintoasc.charAt(((bin[1] << 2) & 0x3C)
                                           | ((bin[2] >>> 6) & 0x03));
      		if(inBin > 2)
         		asciiBuffer[writeHead+3] = (byte) bintoasc.charAt(bin[2] & 0x3F);
      	}
	}

   	private void push3bytes() throws IOException
   	{
		if(space < 4) flushBuffer();
      	encode();
      	inBin = 0;
      	writeHead+=4;
      	space -= 4;
   	}

	public void flush() throws IOException
   	{
   		if(inBin != 0) push3bytes();
      	flushBuffer();
      	out.flush();
   	}

   	public void write(byte  b[]) throws IOException
	{
   		write(b, 0, b.length);
   	}


   	public void write(byte  b[], int  off, int  len) throws IOException
   	{
   		for(int i=0; i<len && i+off < b.length; ++i) write(b[off+i]);
   	}

   	public void write(int  b) throws IOException
   	{
   		bin[inBin] = (byte) b;
      	++inBin;
      	if(3 == inBin)
      	{
      		push3bytes();
         		inBin=0;
      	}
   	}
}

