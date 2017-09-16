//package UK.co.demon.windsong.tines.pegwit;
import java.io.*;
/**
 * Elliptic curves over GF(2^m)
 *
 * This public domain software was written by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> based on original C++ software written by
 * George Barwood <george.barwood@dial.pipex.com>
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
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 */

public final class Ecpoint {//aka EC_point


	private Gfpoint x;
   private Gfpoint y;

	public static final Vlpoint prime = new Vlpoint(true);

   public Ecpoint()
   {
   	x = new Gfpoint();
      y = new Gfpoint();
   }

   public Ecpoint(boolean prime)
   {
   	if(prime)
      {
   		x = new Gfpoint(true);
         y = new Gfpoint(false);
      }
      else
      {
   		x = new Gfpoint();
      	y = new Gfpoint();
   	}
   }

	public boolean check()
   {
		/* confirm that y^2 + x*y = x^3 + EC_B for point p */
      Gfpoint t1 = new Gfpoint();
      Gfpoint t2 = new Gfpoint();
      Gfpoint t3 = new Gfpoint();
      Gfpoint b = new Gfpoint();

		b.set((short)Ecparam.EC_B);
      t1.square(y);
      t2.multiply(x,y);
      t1.add(t1,t2); // y^2 + xy
      t2.square(x);
      t3.multiply(t2,x);
      t2.add(t3,b); // x^3 + EC_B
      return t1.equals(t2);
   }

	/* print prefix tag and the contents of p to file out */
   public void print(PrintStream out, String tag)
   {
		out.print(tag+" = (");
      x.print(out,"");
      out.print(",");
      y.print(out,"");
      out.print(")\n");
   }

   public boolean equals(Ecpoint q)
   {
   	return x.equals(q.x) && y.equals(q.y);
   }

	public void random()
   {
   	boolean check = false;
      do{
      	x.random();
         check = calcY(0);
      } while(!check);
   }

   public void clear()
   {
   	x.clear();
      y.clear();
   }

   public void copy(Ecpoint q)
   {
   	x.copy(q.x);
      y.copy(q.y);
   }

	/* given the x coordinate of p, evaluate y
    such that y^2 + x*y = x^3 + EC_B */
	boolean calcY(int ybit)
   {
   	Gfpoint a = new Gfpoint();
   	Gfpoint b = new Gfpoint();
   	Gfpoint t = new Gfpoint();

      b.set((short)Ecparam.EC_B);
      if(x.peek() == 0) // reduces to y^2 = EC_b
      {
      	y.squareRoot(Ecparam.EC_B);
         return true;
      }
      /* evaluate alpha = x^3 + b = (x^2)*x + EC_B: */
		t.square (x); /* keep t = x^2 for beta evaluation */
		a.multiply (t, x);
		a.add (a, b); /* now a == alpha */
		if (a.peek() == 0)
      {
			y.clear();
			/* destroy potentially sensitive data: */
			a.clear(); t.clear();
			return true;
		}
		/* evaluate beta = alpha/x^2 = x + EC_B/x^2 */
		t.smallDiv (Ecparam.EC_B);
		a.invert (t);
		a.add(x, a); /* now a == beta */
		/* check if a solution exists: */
		if (a.trace () != 0)
      {
			/* destroy potentially sensitive data: */
			a.clear(); t.clear();
			return false; /* no solution */
		}
		/* solve equation t^2 + t + beta = 0 so that gfYbit(t) == ybit: */
		t.quadSolve (a);
		if (t.yBit () != ybit)
      {
			t.flipLow();
			}
		/* compute y = x*t: */
		y.multiply (x, t);
		/* destroy potentially sensitive data: */
      a.clear(); t.clear();
      return true;
	}


	public void add (Ecpoint q)
   { /* sets p := p + q */
		Gfpoint lambda = new Gfpoint();
		Gfpoint t = new Gfpoint();
		Gfpoint tx = new Gfpoint();
		Gfpoint ty = new Gfpoint();
		Gfpoint x3 = new Gfpoint();

		/* first check if there is indeed work to do (q != 0): */
		if (q.x.peek()!= 0 || q.y.peek()!= 0)
      {
			if (x.peek() != 0 || y.peek() != 0)
         {
				/* p != 0 and q != 0 */
				if (x.equals(q.x))
            {
					/* either p == q or p == -q: */
					if (y.equals (q.y))
               {
						/* points are equal; double p: */
						doubleUp ();
					}
            	else
               {
						/* must be inverse: result is zero */
						/* (should assert that q->y = p->x + p->y) */
                  x.clear(); y.clear();
					}
				}
            else
            {
					/* p != 0, q != 0, p != q, p != -q */
					/* evaluate lambda = (y1 + y2)/(x1 + x2): */
					ty.add (y, q.y);
					tx.add (x, q.x);
					t.invert (tx);
					lambda.multiply (ty, t);
					/* evaluate x3 = lambda^2 + lambda + x1 + x2: */
					x3.square (lambda);
					x3.add (x3, lambda);
					x3.add (x3, tx);
					/* evaluate y3 = lambda*(x1 + x3) + x3 + y1: */
					tx.add (x, x3);
					t.multiply (lambda, tx);
					t.add (t, x3);
					y.add (t, y);
					/* deposit the value of x3: */
					x.copy (x3);
				}
			}
         else
         {
				/* just copy q into p: */
            x.copy(q.x);
            y.copy(q.y);
 			}
		}
   }


	public void sub (Ecpoint r)
	{/* sets p := p - r */
   	Ecpoint t = new Ecpoint();
      t.x.copy(r.x);
      t.y.add(r.x, r.y);
      add(t);
   }

	public void negate ()
	{/* sets p := -p */
   	y.add(x, y);
	}

	public void doubleUp ()
	{/* sets p := 2*p */
		Gfpoint lambda = new Gfpoint();
		Gfpoint t1 = new Gfpoint();
		Gfpoint t2 = new Gfpoint();

 		/* evaluate lambda = x + y/x: */
		t1.invert (x);
		lambda.multiply (y, t1);
		lambda.add (lambda, x);
		/* evaluate x3 = lambda^2 + lambda: */
		t1.square (lambda);
		t1.add (t1, lambda); /* now t1 = x3 */
		/* evaluate y3 = x^2 + lambda*x3 + x3: */
		y.square (x);
		t2.multiply (lambda, t1);
		y.add (y, t2);
		y.add (y, t1);
		/* deposit the value of x3: */
		x.copy (t1);
	}


	public void multiply (Vlpoint k)
	{/* sets p := k*p */
		Vlpoint h = new Vlpoint();
		int z, hi, ki;
		short i;
		Ecpoint r = new Ecpoint();

		r.x.copy (x); x.clear();
		r.y.copy (y); y.clear();
		h.shortMultiply (k, 3);
		z = h.numBits () - 1; /* so vlTakeBit (h, z) == 1 */
		i = 1;
		for (;;)
      {
			hi = h.takeBit (i);
			ki = k.takeBit (i);
			if (hi == 1 && ki == 0)
         {
				add(r);
			}
			if (hi == 0 && ki == 1)
         {
         	sub(r);
			}
			if (i >= z) break;
			++i;
			r.doubleUp ();
		}
   }

	public int yBit ()
   {/* evaluates to 0 if p->x == 0, otherwise to gfYbit (p->y / p->x) */
   	if(x.peek() == 0) return 0;
      Gfpoint t1 = new Gfpoint();
      t1.invert(x);
      Gfpoint t2 = new Gfpoint();
      t2.multiply(y, t1);
      return t2.yBit();
   }

	public Vlpoint pack ()
   {/* packs a curve point into a vlPoint */
   	Vlpoint k = new Vlpoint();
   	if(x.peek() != 0)
      {
			k=x.pack();
         k.shortLshift(1);
         Vlpoint a = new Vlpoint((short) yBit());
         k.add(a);
      }
      else if(y.peek()!=0)
      	k.set((short)1);
      // zero by default
      return k;
	}

   public Vlpoint xpack()
   {
   	return x.pack();
   }

	public void unpack (Vlpoint k)
	{/* unpacks a vlPoint into a curve point */
   	int yb = k.peek(0) > 0 ? k.peek(1)&1 : 0;
      Vlpoint a = new Vlpoint();
      a.copy(k);
      a.shortRshift(1);
      x.unpack(a);
      if(x.peek()!=0 || yb!=0) calcY(yb);
      else y.clear();
   }

	public static void ecSelfTest (int test_count)
   {
		int i, yb, nfail = 0, afail = 0, sfail = 0,
      cfail = 0, qfail = 0, pfail = 0, yfail = 0;
		Ecpoint f = new Ecpoint();
		Ecpoint g = new Ecpoint();
		Ecpoint x = new Ecpoint();
		Ecpoint y = new Ecpoint();

      Vlpoint m = new Vlpoint();
      Vlpoint n = new Vlpoint();
      Vlpoint p = new Vlpoint();

		long elapsed;

      System.out.println("Executing "+test_count+" curve self tests...");
		elapsed = -System.currentTimeMillis();
		for (i = 0; i < test_count; i++)
      {
System.out.print("\r"+i);
System.out.flush();
			f.random();
         g.random();
         m.random();
         n.random();

			/* negation test: -(-f) = f */
			x.copy (f);
			x.negate ();
			x.negate ();
			if (!f.equals (x))
         {
				nfail++;
            System.out.println("Negation test "+i+" failed!");
            break;
			/* printf ("Addition test #%d failed!\n", i); */
			}

			/* addition test: f+g = g+f */
			x.copy (f); x.add (g);
			y.copy (g); y.add (f);
			if (!x.equals (y))
      	{
				afail++;
            System.out.println("Addition test "+i+" failed!");
            break;
			}

			/* subtraction test: f-g = f+(-g) */
			x.copy (f); x.sub (g);
			y.copy (g); y.negate (); y.add (f);
			if (!x.equals (y))
      	{
				sfail++;
            System.out.println("Subtraction test "+i+" failed!");
            break;
			}


			/* quadruplication test: 2*(2*f) = f + f + f + f */
			x.copy (f); x.doubleUp (); x.doubleUp ();
			y.clear (); y.add(f); y.add(f); y.add(f); y.add(f);
			if (!x.equals (y))
      	{
				qfail++;
            System.out.println("Quadruplication test "+i+" failed!");
            break;
			}
			/* scalar multiplication commutativity test: m*(n*f) = n*(m*f) */
			x.copy (f);
			y.copy (f);
			x.multiply (n); x.multiply (m);
			y.multiply (m); y.multiply (n);
			if (!x.equals (y))
      	{
				cfail++;
            System.out.println("Commutation test "+i+" failed!");
            break;
			}

			/* y calculation test: */
			yb = f.yBit ();
			x.clear ();
			x.x.copy (f.x);
			x.calcY (yb);
			if (!x.equals (f))
      	{
				cfail++;
            System.out.println("Y Computation test "+i+" failed!");
            break;
			}

			/* packing test: unpack (pack (f)) = f */
			p = f.pack ();
			x.unpack (p);
			if (!x.equals (f))
      	{
				pfail++;
            System.out.println("Packing test "+i+" failed!");
            break;
			}
		} // for
		elapsed += System.currentTimeMillis();
      double t = elapsed; t/=1000;
      System.out.println(" done, elapsed time = "+t);

	}
}

