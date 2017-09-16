//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 * Multiple-precision ("very long") integer arithmetic
 *
 * This public domain software was written by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> based on original C++ software written by
 * George Barwood <george.barwood@dial.pipex.com>
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 *
 * Note that at JDK1.1 there is a BigInteger which can be used instead
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * References:
 *
 * 1.	Knuth, D. E.: "The Art of Computer Programming",
 *		2nd ed. (1981), vol. II (Seminumerical Algorithms), p. 257-258.
 *		Addison Wesley Publishing Company.
 *
 * 2.	Hansen, P. B.: "Multiple-length Division Revisited: a Tour of the Minefield".
 *		Software - Practice and Experience 24:6 (1994), 579-601.
 *
 * 3.	Menezes, A. J., van Oorschot, P. C., Vanstone, S. A.:
 *		"Handbook of Applied Cryptography", CRC Press (1997), section 14.2.5.
 */

public class Vlpoint {

	private final static int VL_UNITS =
		(Ecparam.GF_K*Ecparam.GF_L + 15)/16 + 1;
   private final static int size = VL_UNITS+2;
   private final static int NB = ((Ecparam.GF_M+1+7)/8);
  /* must be large enough to hold a (packed) curve point (plus one element:
  the length) */

  	private short[] b = new short[size];

  	private static char nybbleToHex(short x, short nybNo) // MSNybble first
  	{
  		short nybble = (short)((x >>> 4*(3-nybNo)) & 0xF);
      if (nybble < 10) return (char)('0'+nybble);
      return (char)('a'+nybble-10);
	}

   public void debug()
   {
     for(int i=0; i<= b[0]; ++i)
    	{
		int v = b[i] & 0x0000FFFF;
		System.out.println(""+v);
	}
   }


   public void put(DataOutput f_out)// Human readable
   {
   	for(int i=b[0]; i>0; --i)
      {
      	for(short j=0;j<4;++j)
         {
         	try{
            	f_out.writeByte( (byte)Vlpoint.nybbleToHex(b[i],j) );
               }
            catch(IOException e) {;}
         }
      }
   }

   public void get(InputStream f_inp)//?move to Vlpoint
   {
   	clear();
      int u;
      for(;;)
      {
      	try{ u = f_inp.read(); }
         catch(IOException e) {break;}
         if(u < 0) break;
         if ( u >= '0' && u <= '9' )
      	  	u -= '0';
         else if ( u >= 'a' && u <= 'z' )
      	 	u -= 'a' - 10;
         else if ( u >= 'A' && u <= 'Z' )
      		u -= 'A' - 10;
         else if ( u <= ' ' )
        		continue;
    	 	else
      		break;

         shortLshift (4);
         b[1] |= (u&0xF);
         if(b[0] == 0) b[0]=1;
      }
   }

	public void getASCII(DataInput f_inp)
   {
   	clear();
      String  buffer;
      try{ buffer = f_inp.readLine(); }
      catch(IOException e) {return;}

      for(int i=0;i<buffer.length();++i)
      {

      	int u = buffer.charAt(i);
         if ( u >= '0' && u <= '9' )
        		u -= '0';
    	 	else if ( u >= 'a' && u <= 'z' )
      		u -= 'a' - 10;
     		else if ( u >= 'A' && u <= 'Z' )
     			u -= 'A' - 10;
         else if ( u <= ' ' )
        		continue;
    	 	else
      		break;
         shortLshift (4);
         b[1] |= (u&0xF);
         if(b[0] == 0) b[0]=1;
      }
   }


   public void putBinary(OutputStream f_out)// Machine readable only
   {
		int n = NB;
      int i = 1;
      for(;i<=b[0];++i)
      {
			try{
         		--n; f_out.write(b[i]&0xFF);
         		--n; f_out.write((b[i]&0xFF00)>>>8);
         } catch(IOException e){;}
      }
      while((n--) > 0) try{f_out.write(0);} catch(IOException e){;}
   }

	public void getBinary(InputStream f_in)
   {
   	byte[] u = new byte[NB];
      int n;
      clear();
      try{n = f_in.read(u);}
      catch(IOException e) {return;}
		while(n-- != 0)
      {
        	shortLshift(8);
         b[1] |= (u[n]&0xFF);
         if(b[0] == 0) b[0]=1;
      }

   }


  	public Vlpoint()
  	{
		clear();
  	}

  public Vlpoint (boolean prime)
  {
  		if(!prime) clear();
      else
  		b[0] = (short)16;
      b[1] = (short)0xcd31;
      b[2] = (short)0x42bb;
      b[3] = (short)0x2584;
      b[4] = (short)0x5e0d;
   	b[5] = (short)0x2d8b;
      b[6] = (short)0x4bf7;
      b[7] = (short)0x840e;
      b[8] = (short)0x0547;
      b[9] = (short)0xbec3;
      b[10]= (short)0xed9b;
      b[11]= (short)0x691c;
      b[12]= (short)0x2314;
      b[13]= (short)0x81b8;
      b[14]= (short)0xd850;
      b[15]= (short)0x026d;
      b[16]= (short)0x0001;
	} /* prime_order */

	public static void short2hex(PrintStream out, short i)
   {
   	for(short n=0; n<4; ++n) out.print(nybbleToHex(i,n));
   }

	/* printf prefix tag and the contents of this to file out */
	public void print (PrintStream out, String tag)
   {
   	out.print(tag);
      for(short i=b[0]; i>0; --i)
      {
			short2hex(out, b[i]);
out.print("|");
      }
		out.print("\n");
   }

	/* sets this := <random very long integer value> */
	public void random ()
   {
   	short i;
   	for(i=1; i<= VL_UNITS; ++i)
      	b[i] = (short)(65536 * (Math.random() - 0.5));
      for(;i>0; --i) if(b[i]!=0) break; //find top non-zero value
      b[0] = i;
   }

   public void clear ()
   {
   	for(short i=0; i<VL_UNITS+2; ++i) b[i] = 0;
   }

   public boolean equals(Vlpoint u)
   {
   	if(b[0]!=u.b[0]) return false;
      for(short i=0; i<=b[0]; ++i)
      	if(b[i] != u.b[i]) return false;
      return true;
   }

	public void copy(Vlpoint u)
   {
   	b[0] = u.b[0];
      for(short i=0; i<=b[0]; ++i)
      	b[i] = u.b[i];
   }

   public Vlpoint(short u) // vlShortSet
   {
   	clear();
   	set(u);
   }

   public Vlpoint(Vlpoint u)
   {
   	copy(u);
   }

   public int peek(int i)
   {
   	return u16(b[i]);
   }

   public void set(short u)
   {
   	b[0] = 1;
      b[1] = u;
   }

   public byte getByte(int n)
   {
   	int j = (n/2) + 1;//0,1 => 1; 2,3=>2
      if(j<1) return 0;
      if(j>b[0]) return 0;
		if(n%2 != 0) return (byte)((b[j]>>>8) & 0xFF);
      return (byte)(b[j] & 0xFF);
   }

	/* evaluates to the number of bits of this (index of most
   significant bit, plus one) */
	public int numBits ()
   {
   	if(0 == b[0]) return 0;
      short w = b[b[0]];
      int i = (int)(b[0]<<4);
      int m = 0x8000;
      for(;m!=0;--i)
      {
      	if((w & m)!=0) return i;
         m >>>=1;
      }
      return 0;
   }

	/* evaluates to the i-th bit of k */
	public int  takeBit (short i)
   {
   	if(i >= (b[0] << 4)) return 0;
      if(i<0) return 0;
      return ((b[(i>>>4)+1] >>> (i&15)) &1);
   }

	public static int u16(short i)
   {
   	if(i>=0) return i;
      return 65536+i;
   }


	public void add(Vlpoint v)
   {
   	int i;
		int t;
      /* clear high parts of this*/
      for(i=b[0]+1; i <= v.b[0]; ++i) b[i]=0;
      if(b[0] < v.b[0]) b[0] = v.b[0];
      t = 0;

      for(i=1; i<=v.b[0]; ++i)
      {
			t += u16(b[i]) + u16(v.b[i]);
			b[i] = (short)(t & 0xFFFF); // should wrap OK
         t>>>=16;
      }
      while(t != 0)
      {
      	if(i > b[0])
         {
         	b[i] = 0; ++b[0];
         }
         t = u16(b[i]) + 1;
         b[i] = (short)(t & 0xFFFF);
         t>>>=16;
         ++i;
      }
   }

	public void subtract(Vlpoint v) // v <= this
   {
   	int carry = 0;
      int tmp, i;
		for(i=1; i<=v.b[0]; ++i)
      {
      	tmp = 0x10000 + u16(b[i]) - u16(v.b[i]) - carry;
         carry = 1;
         if(tmp > 0x10000)
         {
         	tmp -= 0x10000;
            carry = 0;
         }
         b[i] = (short)tmp;
      }
      if(carry != 0 )
      {
      	while((i < b.length) && (b[i] == 0)) ++i;
			if(i<b.length) {--b[i];}
      }
		while(b[b[0]] == 0 && b[0] != 0) --b[0];
   }

   public void shortLshift (int n) // 0 <= n <= 16
   {
   	if(b[0] == 0) return; // no-op
      if(n == 0) return;
      if((u16(b[b[0]]) >>> (16-n)) != 0)
      {
      	if(b[0] <= VL_UNITS+1)
         {
         	++b[0]; b[b[0]] = 0;
         }
      } // space set for one more

      for(int i = b[0]; i>1; --i)
      	b[i] = (short)
         (
         	((u16(b[i]) << n) | (u16(b[i-1]) >>> (16-n))) & 0xFFFF
         );
      b[1] <<= n;
	}

	public void shortRshift (int n)
   {
   	if(b[0] == 0) return;
      if(n == 0) return;
      for(int i=1; i<b[0]; ++i)
      	b[i] = (short)
         (
         ((u16(b[i+1]) << (16-n)) | (u16(b[i]) >>> n)) & 0xFFFF
         );

      int j = u16(b[b[0]]) >>> n;
      b[b[0]] = (short)(j&0xFFFF);

      while (b[b[0]] == 0 && b[0] > 0) --b[0];
   }

	/* sets this = q * d, where d is 16-bit unsigned digit */
	public void shortMultiply (Vlpoint q, int d)
   {
   	if(q.b[0] > VL_UNITS) throw
      	new ArithmeticException("ERROR: not enough room for multiplication");
   	if(0 == d) b[0] = 0;
   	else if(1 == d) copy(q);
   	else
   	{
      	int t = 0;
         for(int i=1; i <= q.b[0]; ++i)
         {
         	t+= u16(q.b[i]) * d;
            b[i] = (short)(t & 0xFFFF);
            t>>>=16;
         }
         if(t != 0)
         {
         	b[0] = (short)(q.b[0]+1);
            b[b[0]] = (short)(t & 0xFFFF);
         }
         else b[0] = q.b[0];
   	}
   }

   public boolean greater (Vlpoint q)
   {
   	if(b[0] != q.b[0]) return b[0] > q.b[0];
      for(int i = b[0]; i>0; --i)
      	if(b[i] != q.b[i]) return (b[i]&0x0000FFFF) > (q.b[i] & 0x0000FFFF);
      return false;
   }


	public void remainder (Vlpoint v)
   {
   	int shift = 0;
		Vlpoint t = new Vlpoint();
      t.copy(v);
      while(greater(t))
      {
			t.shortLshift(1);
         ++shift;
      }
      for(;;)
      {
      	if(t.greater(this))
         {
         	if(shift!=0)
            {
            	t.shortRshift(1);
               --shift;
            }
            else break;
         }
         else 
	   {
		subtract(t);
	   }
      }
   }


	public void mulMod (Vlpoint v, Vlpoint w, Vlpoint m)
   {
   	clear();
      Vlpoint t = new Vlpoint();
      t.copy(w);
      for(int i = 1; i <= v.b[0]; ++i)
      {
      	for(int j=0; j<16;++j)
         {
         	if(0 != ((v.b[i]>>>j) & 1))
            {
            	add(t);
               remainder(m);
            }
            t.shortLshift(1);
            t.remainder(m);
         }
      }
	}

	public static void vlSelfTest (int test_count)
   {
   	long startTime = System.currentTimeMillis();
      System.out.println("Executing "+test_count+" vlong self tests...");
      System.out.println("Array size = "+size+" VL_UNITS = "+VL_UNITS);

      Vlpoint m = new Vlpoint();
      Vlpoint p = new Vlpoint();
      Vlpoint q = new Vlpoint();

      int tfail = 0;
      int sfail = 0;
      int afail = 0;

		for(int i=0; i< test_count; ++i)
      {
System.out.print("\r"+i);
			m.random();
//m.print(System.out, "number = ");
			p.shortMultiply(m,3);
			q.clear(); q.add(m); q.add(m); q.add(m);

			if(!q.equals(p))
         {
         	++tfail;
            System.out.println("Triplication test "+i+" failed!");
            break;
         }

         p.copy(m);
         p.shortLshift(i%17);

if(0 == (i%17))
{
			if(!m.equals(p))
         {
         	++sfail;
            System.out.println("LShift by "+(i%17)+" test "+i+" failed!");
m.print(System.out, "number =");
p.print(System.out, "shifted=");
            break;
         }
}


         p.shortRshift(i%17);

			if(!m.equals(p))
         {
         	++sfail;
            System.out.println("Shift by "+(i%17)+" test "+i+" failed!");
m.print(System.out, "number =");
p.print(System.out, "shifted=");
            break;
         }

			p.copy(m); p.add(m);
         q.copy(m); q.shortLshift(1);

  			if(!q.equals(p))
         {
         	++afail;
            System.out.println("Addition test "+i+" failed!");
            break;
         }

		}
      startTime -= System.currentTimeMillis();
      double d = 0.0 - startTime; d/=1000;
      System.out.println(" done, elapsed time = "+d);
      if(tfail > 0)
      	System.out.println("---> "+tfail+" triplications failed <---");
      if(sfail > 0)
      	System.out.println("---> "+sfail+" shifts failed <---");
      if(afail > 0)
      	System.out.println("---> "+afail+" additions failed <---");
	}


}// end of class
