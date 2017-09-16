//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 * Algebraic operations on the finite field GF(2^m)
 *
 * This public domain software was written by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> based on original C++ software written by
 * George Barwood <george.barwood@dial.pipex.com>
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
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
 * 1.	Erik De Win <erik.dewin@esat.kuleuven.ac.be> et alii:
 *		"A Fast Software Implementation for Arithmetic Operations in GF(2^n)",
 *		presented at Asiacrypt96 (preprint).
 *
 */

public final class Gfpoint {

	private final static int GF_POINT_UNITS =	(2*(Ecparam.GF_K+1));

//	private final static int BITS_PER_LUNIT = 16;

   private final static int BASE = 1 << Ecparam.GF_L;
   private final static int TOGGLE = BASE-1;

   private short[] b = new short[GF_POINT_UNITS];

   private static short[] expt = new short[BASE];
   private static short[] logt = new short[BASE];

	static
   {
   	int i,j;
   	int root = BASE | Ecparam.GF_RP;

      expt[0] = 1;
      for (i=1; i<BASE; ++i)
      {
			j = Vlpoint.u16(expt[i-1]) << 1;
         if((j & BASE) != 0) j ^= root;
      	expt[i] = (short)(j & 0xFFFF);
      }
      for(i=0; i<TOGGLE; ++i)
      {
      	logt[Vlpoint.u16(expt[i])] = (short)(i & 0xFFFF);
      }
      logt[0] = (short)(TOGGLE & 0xFFFF); // useful trick
   } // Class initialiser


	public void print (PrintStream out, String tag)
   {
   	out.print(tag);
      boolean plus = false;
      for(short i=b[0]; i>0; --i)
      {
      	if(b[i] == 0) continue;
         if(plus) out.print("+");
         if(i > 2)
         {
				Vlpoint.short2hex(out, b[i]);
            int tmp = i-1;
            out.print("x^"+tmp);
         }
         else if(i==2)
         {
         	Vlpoint.short2hex(out, b[2]);
            out.print("x");
			}
         else Vlpoint.short2hex(out,b[1]);
         plus = true;
      }
      if(!plus) out.print("0");
      out.print("\n");
   }

   public Gfpoint()
   {
   	clear();
   }

   public void set(short u)
   {
   	b[0] = (short)1;
      b[1] = (short)(u&TOGGLE);
   }

   public Gfpoint(boolean xy)
   {
   	b[0] = (short)17;
      if(xy) // x-coord
      {
   		b[1] = (short) 0x38cc;b[2] = (short) 0x052f;
         b[3] = (short) 0x2510;b[4] = (short) 0x45aa;
         b[5] = (short) 0x1b89;b[6] = (short) 0x4468;
         b[7] = (short) 0x4882;b[8] = (short) 0x0d67;
         b[9] = (short) 0x4feb;b[10] = (short) 0x55ce;
         b[11] = (short) 0x0025;b[12] = (short) 0x4cb7;
         b[13] = (short) 0x0cc2;b[14] = (short) 0x59dc;
         b[15] = (short) 0x289e;b[16] = (short) 0x65e3;
         b[17] = (short) 0x56fd;
   	}
      else
      {
   		b[1] = (short) 0x31a7;b[2] = (short) 0x65f2;
         b[3] = (short) 0x18c4;b[4] = (short) 0x3412;
         b[5] = (short) 0x7388;b[6] = (short) 0x54c1;
         b[7] = (short) 0x539b;b[8] = (short) 0x4a02;
         b[9] = (short) 0x4d07;b[10] = (short) 0x12d6;
         b[11] = (short) 0x7911;b[12] = (short) 0x3b5e;
         b[13] = (short) 0x4f0e;b[14] = (short) 0x216f;
         b[15] = (short) 0x2bf2;b[16] = (short) 0x1974;
         b[17] = (short) 0x20da;
      }

   }

	/* sets this := <random field element> - weak PRNG */
	public void random ()
   {
   	b[0] = (short) Ecparam.GF_K;
      for(int i=1; i<b[0]; ++i)
      {
     		b[i] = (short)(32768 * Math.random());
         b[i] &= TOGGLE;
      }
      while(b[0] > 0 && b[b[0]]==0) b[0]--;
   }

   private int slowTrace()
   {
   	Gfpoint t = new Gfpoint();
      t.copy(this);
      for(int i = 1; i < Ecparam.GF_M; ++i)
      {
      	t.square(t);
         t.add(t,this);
      }
      return t.b[0] != 0 ? 1 : 0;
   }

   public boolean equals(Gfpoint u)
   {
   	if(b[0]!=u.b[0]) return false;
      for(short i=0; i<=b[0]; ++i)
      	if(b[i] != u.b[i]) return false;
      return true;
   }

   public void clear()
   {
   	for(short i=0; i<GF_POINT_UNITS; ++i) b[i] = 0;
   }

   public int peek()
   {
   	return b[0];
   }

   public void flipLow()
   {
   	b[1] ^= 1;
   }

   public void copy(Gfpoint u)
   {
      for(short i=0; i<GF_POINT_UNITS; ++i)
      	b[i] = u.b[i];
   }

	public void add (Gfpoint q, Gfpoint r) /* sets this := q + r */
   {
   	int i;
		if(q.b[0]>r.b[0])//xor the the common-degree coefficients:
      {
      	for(i=1; i<=r.b[0]; ++i) b[i] = (short)(q.b[i] ^ r.b[i]);
         for(;i<GF_POINT_UNITS;++i) b[i] = q.b[i];
         b[0] = q.b[0];
      }
      else if (q.b[0]<r.b[0])
      {
      	for(i=1; i<=q.b[0]; ++i) b[i] = (short)(q.b[i] ^ r.b[i]);
         for(;i<GF_POINT_UNITS;++i) b[i] = r.b[i];
         b[0] = r.b[0];
      }
      else
      {
      	for(i=q.b[0]; i>0; --i) if((q.b[i] ^ r.b[i])!=0) break;
			b[0] = (short) i;
         for(;i>0;--i) b[i] = (short)(q.b[i] ^ r.b[i]);
      }
   }

   private void reduce()
	/* reduces p mod the irreducible trinomial x^GF_K + x^GF_T + 1 */
	{
		int i;

		for (i = b[0]; i > Ecparam.GF_K; --i)
      {
			b[i - Ecparam.GF_K] ^= b[i];
			b[i + Ecparam.GF_T - Ecparam.GF_K] ^= b[i];
			b[i] = 0;
		}
		if (b[0] > Ecparam.GF_K)
      {
			/* scan to update deg(p): */
			b[0] = (short) Ecparam.GF_K;
			while (b[0]!=0 && b[b[0]]==0)
				b[0]--;
		}
	}


	/* sets this := p * q mod (x^GF_K + x^GF_T + 1) */
	public void multiply (Gfpoint p, Gfpoint q)
   {
   	short[] lg = new short[2+Ecparam.GF_K];
      int i,j, x, log_pi;

		if(p.b[0]!=0 && q.b[0] != 0)
      {
      	for(j=q.b[0];j>0; --j) lg[j] = logt[Vlpoint.u16(q.b[j])];
			clear();
         for(i=p.b[0]; i>0; --i)
         {
         	log_pi = logt[Vlpoint.u16(p.b[i])];
            if(log_pi != TOGGLE)
            	for(j = q.b[0]; j>0; --j)
               	if(lg[j] != TOGGLE)
                  {
                  	x = log_pi + lg[j];
                  	b[i+j-1] ^= x >= TOGGLE ? expt[x - TOGGLE] : expt[x];
                  }
         }
         b[0] = (short)(p.b[0]+q.b[0] - 1);
         reduce();
         log_pi = 0;
      }
      else
      	clear();

      x=0;
		for(j=q.b[0];j>0; --j) lg[j] = 0;
   }

	/* sets this := q^2 mod (x^GF_K + x^GF_T + 1) */
	public void square (Gfpoint p)
   {
   	if(p.b[0] != 0)
      {
      	int i = p.b[0];
         int x = logt[Vlpoint.u16(p.b[i])];
         if(x != TOGGLE)
         	b[2*i-1] = (x += x) >= TOGGLE ? expt[x-TOGGLE] : expt[x];
         else
         	b[2*i-1] = 0;
         for(--i;i>0;--i)
         {
				b[2*i] = 0;
         	x = logt[Vlpoint.u16(p.b[i])];
         	if(x != TOGGLE)
         		b[2*i-1] = (x += x) >= TOGGLE ? expt[x-TOGGLE] : expt[x];
         	else
         		b[2*i-1] = 0;
         }
         b[0] = (short)(2*p.b[0] - 1);
         reduce();
      }
      else b[0] = 0;
	}


	/* sets p := (b^(-1))*p mod (x^GF_K + x^GF_T + 1) for b != 0 (of course...) */
	public void smallDiv (int d)
   {
		for(int i=b[0]; i>0; --i)
      {
      	int x = logt[Vlpoint.u16(b[i])];
         if(x != TOGGLE)
         {
         	x = x + TOGGLE - logt[d];
            b[i] = x > TOGGLE ? expt[x-TOGGLE] : expt[x];
         }
      }
   }

   private void addMul(int alpha, int j, Gfpoint q)
   {
	  	while(b[0] < j + q.b[0])
      {
      	++b[0]; b[b[0]] =0;
		}
		for(int i=q.b[0]; i>0; --i)
      {
      	int x = logt[Vlpoint.u16(q.b[i])];
         if(x != TOGGLE)
         {
         	x = x + logt[alpha];
            b[i+j] ^= x > TOGGLE ? expt[x-TOGGLE] : expt[x];
         }
      }
      while(b[0] > 0 && b[b[0]]==0) --b[0];
  }


	/* sets p := q^(-1) mod (x^GF_K + x^GF_T + 1) */
	/* warning: this and q must not overlap! */
	public int invert (Gfpoint q)
   {
   	if(q.b[0] == 0) return 1;

      b[0] = 1;
      b[1] = 1;
      Gfpoint c = new Gfpoint();
      Gfpoint f = new Gfpoint(); f.copy(q);
      Gfpoint g = new Gfpoint();
      g.b[0] = (short) (Ecparam.GF_K + 1);
      g.b[1] = 1;
      g.b[Ecparam.GF_T+1] = 1;
      g.b[Ecparam.GF_K+1] = 1;

      boolean swap = false;

		for(;;)
      {
      	int j, x, alpha;

         if(!swap)
         {
				if(f.b[0] == 1)
         	{
         		smallDiv(f.b[1]);
            	j=0; x=0; alpha=0;
            	c.clear(); f.clear(); g.clear(); return 0;
        	 	}
         }
         else
         {
         	if(g.b[0] == 1)
            {
            	c.smallDiv(g.b[1]);
               copy(c);
               j=0; x=0; alpha=0;
            	c.clear(); f.clear(); g.clear(); return 0;
            }
         }

         	if(f.b[0] < g.b[0]) swap = true;
            else swap = false;

			if(!swap)
         {
         	j = f.b[0] - g.b[0];
         	x = logt[f.b[f.b[0]]] - logt[g.b[g.b[0]]] + TOGGLE;
         	alpha = x >= TOGGLE ? expt[x-TOGGLE]: expt[x];
         	f.addMul(alpha, j, g);
         	addMul(alpha,j,c);
         }
         else
         {
         	j = g.b[0] - f.b[0];
         	x = logt[g.b[g.b[0]]] - logt[f.b[f.b[0]]] + TOGGLE;
         	alpha = x >= TOGGLE ? expt[x-TOGGLE]: expt[x];
         	g.addMul(alpha, j, f);
         	c.addMul(alpha,j,this);
         }
      }
   }



	/* sets p := sqrt(b) = b^(2^(GF_M-1)) */
	public void squareRoot (int d)
   {
   	Gfpoint q = new Gfpoint();
		q.b[0] = 1;
      q.b[1] = (short)(d&0xFFFF);
      copy(q); // GF_M - 1 is even
      for(int i = Ecparam.GF_M - 1; i>0; i-=2)
      {
			q.square(this);
         square(q);
      }
   }

	/* quickly evaluates to the trace of p (or an error code) */
	public int  trace()//special case for GF(2^255)
   {
   	return (b[0] > 0) ? b[1]&1 : 0;
   }

	/* sets p to a solution of p^2 + p = q */
	public int  quadSolve (Gfpoint q)
   {
   	if(q.trace() != 0) return 1; // no solution
      copy(q);
      for(int i = 0; i<Ecparam.GF_M/2; ++i)
      {
      	square(this);
         square(this);
         add(this, q);
      }
      return 0;
   }

	/* evaluates to the rightmost (least significant) bit of p
   (or an error code) */
	int  yBit ()
   {
   	return b[0] != 0 ? b[1] & 1 : 0;
	}

	/* packs a field point into a vlPoint */
	public Vlpoint pack ()
   {
		Vlpoint k = new Vlpoint();
      Vlpoint a = new Vlpoint();

      for(int i=b[0]; i>0; --i)
      {
      	k.shortLshift(Ecparam.GF_L);
			a.set(b[i]);
         k.add(a);
      }
      return k;
   }

	/* unpacks a vlPoint into a field point */
	public void unpack (Vlpoint k)
   {
   	Vlpoint x = new Vlpoint(k);
      int n = 0;
      for(;x.peek(0)>0; ++n)
      {
      	b[n+1] = (short)( x.peek(1) & TOGGLE);
         x.shortRshift(Ecparam.GF_L);
      }
      b[0] = (short)n;
   }

	/* perform test_count self tests */
	public static void gfSelfTest (int test_count)
   {
		int i
		,afail = 0
		,mfail = 0
		,dfail = 0
		,sfail = 0
		,ifail = 0
		,rfail = 0
		,tfail = 0
		,qfail = 0
		;
		Gfpoint f = new Gfpoint();
		Gfpoint g = new Gfpoint();
		Gfpoint h = new Gfpoint();
		Gfpoint x = new Gfpoint();
		Gfpoint y = new Gfpoint();
		Gfpoint z = new Gfpoint();

		int d;
		long elapsed;

      System.out.println("Executing "+test_count+" field self tests...");
      System.out.println("Array size = "+GF_POINT_UNITS);
		elapsed = -System.currentTimeMillis();
		for (i = 0; i < test_count; i++)
      {
System.out.print("\r"+i);
			f.random ();
			g.random ();
			h.random ();

			/* addition test: f+g = g+f */
			x.add (f, g);
			y.add (g, f);
			if (!x.equals (y)) {
			afail++;
            System.out.println("Addition test "+i+" failed!");
            break;
			}


			/* multiplication test: f*g = g*f */
			x.multiply (f, g);
			y.multiply (g, f);
			if (!x.equals (y)) {
			mfail++;
            System.out.println("Multiplication test "+i+" failed!");
            break;
			}


			/* distribution test: f*(g+h) = f*g + f*h */
			x.multiply (f, g);
			y.multiply (f, h);
			y.add (x, y);
			z.add (g, h);
			x.multiply (f, z);
			if (!x.equals (y)) {
			dfail++;
            System.out.println("Distribution test "+i+" failed!");
            break;
			}


			/* squaring test: f^2 = f*f */
			x.square (f);
			y.multiply (f, f);
			if (!x.equals (y)) {
			sfail++;
            System.out.println("Squaring test "+i+" failed!");
            break;
         }


			/* inversion test: g*(f/g) = f */
			if (g.b[0] != 0)
         {
				x.invert (g);
				y.multiply (f, x);
				x.multiply (g, y);
				if (!x.equals (f))
         	{
					ifail++;
            	System.out.println("Inversion test "+i+" failed!");
            	break;
				}//==
         }// invertible


			/* square root test: sqrt(b)^2 = b */
     		d = (int)(32767 * Math.random());
			if (d!=0)
         {
				z.b[0] = 1; z.b[1] = (short)(d&0xFFFF);
			}//!=
         else
         {
				z.b[0] = 0;
			}//else
			y.squareRoot (d);
			x.square (y);
         if (!x.equals (z))
         {
				rfail++;
            System.out.println("Sqrt test "+i+" failed!");
            break;
			}//==


			/* trace test: slow tr(f) = tr(f) */
         int t = f.trace();
         int s = f.slowTrace();
			if (s != t)
         {
System.out.println("fast="+t);
System.out.println("slow ="+s);
f.print(System.out,"culprit = ");
				tfail++;
            System.out.println("Trace test "+i+" failed!");
            //break;
			}//!=


			/* quadratic equation solution test: x^2 + x = f (where tr(f) = 0)*/
			if (f.trace () == 0)
         {
				x.quadSolve (f);
				y.square (x);
				y.add (y, x);
         	if (!y.equals (f))
         	{
					qfail++;
            	System.out.println("Quadratic test "+i+" failed!");
            	break;
				}//==
			}// trace
		}// for

		elapsed += System.currentTimeMillis();
      double t = elapsed; t/=1000;
      System.out.println(" done, elapsed time = "+t);
// printf (" done, elapsed time = %.1f s.\n", (float)elapsed/CLOCKS_PER_SEC);
//	if (afail) printf ("---> %d additions failed <---\n", afail);
// if (mfail) printf ("---> %d multiplications failed <---\n", mfail);
//	if (dfail) printf ("---> %d distributions failed <---\n", dfail);
//	if (sfail) printf ("---> %d squarings failed <---\n", sfail);
//	if (ifail) printf ("---> %d inversions failed <---\n", ifail);
//	if (rfail) printf ("---> %d square roots failed <---\n", rfail);
//	if (tfail) printf ("---> %d traces failed <---\n", tfail);
//	if (qfail) printf ("---> %d quadratic equations failed <---\n", qfail);
   }// end selftest
}//end class

