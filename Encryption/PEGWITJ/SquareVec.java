//package UK.co.demon.windsong.tines.pegwit;
/*
 * The Square block cipher; a support class.
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 * This version in-lines a lot for speed (of coding as much as execution)
 * rather than being fully encapsulated - Square looks at the innards
 * of SquareVec for convenience.
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
 */

public class SquareVec {
	private int[] x;

   public SquareVec()
   {
   	x = new int[4];
   }


   public SquareVec(byte[] buffer)
   {
   	x = new int[4];
      for(int i = 0; i<4; ++i)
      {
      	x[i] = 0;
         for(int j=0; j<4; ++j) x[i] |= PUTB(3-j, buffer[4*i + j]);
      }
   }

	public void wipe()
   {
   	x[0] = x[1] = x[2] = x[3] = 0;
   }

	public void debug()
	{
		for(int i = 0; i<4; ++i)
		{
			int j = x[i];
			System.out.print(" "+Integer.toHexString(j));
		}
		System.out.println(" ");
	}

   public void unpack(byte[] buffer)
   {
      for(int i = 0; i<4; ++i)
      {
         for(int j=0; j<4; ++j)
				buffer[4*i+j] = GETB(3-j, x[i]);
      }
   }

// Statics that really ought to belong to some (unsigned) integer classes

   private static int ROTL(int x, int s)
   {
   	return (((x) << (s)) | ((x) >>> (32 - (s))));
   }

   private static int ROTR(int x, int s)
   {
   	return (((x) >>> (s)) | ((x) << (32 - (s))));
   }

   private static byte GETB(int n, int x)
   {
   	return (byte)(0xff & (x >>> 8*(3-n)));
   }

   private static int PUTB(int n, byte x)
   {
   	return (0xFF & x) << 8*(3-n);
   }

	private static int uint8(byte b)
   {
   	if(b>=0) return b;
      return 256+b;
   }

	private static byte mul(byte a, byte b)
   {
   	if(a==0 || b==0) return 0;
      int mtemp = uint8(Sqtab.logtab[uint8(a)])+uint8(Sqtab.logtab[uint8(b)]);
      if(mtemp >= 255) mtemp -= 255;
      return Sqtab.alogtab[mtemp];
   }

   private byte kernel(byte[] S, int byteno, int index)
   {
   	return S[ uint8( GETB(byteno, x[index]) ) ];
   }

   public void xor(SquareVec v)
   {
		x[0] ^= v.x[0];
		x[1] ^= v.x[1];
		x[2] ^= v.x[2];
		x[3] ^= v.x[3];
	}

   public SquareVec copy(SquareVec v)
   {
		x[0] = v.x[0];
		x[1] = v.x[1];
		x[2] = v.x[2];
		x[3] = v.x[3];
      return this;
	}

   public SquareVec copy(Sqblock b)
   {
		x[0] = b.chunk(0);
		x[1] = b.chunk(1);
		x[2] = b.chunk(2);
		x[3] = b.chunk(3);
      return this;
   }

   public SquareVec evolve(SquareVec v, int t)
   {
   		x[0] = v.x[0] ^ ROTR(v.x[3],8) ^ (Sqtab.offset[t-1]);
			x[1] = v.x[1] ^ x[0];
			x[2] = v.x[2] ^ x[1];
			x[3] = v.x[3] ^ x[2];
         return this;
   }

   public void transform()
   {/* apply theta to a roundKey */
		int i, j;
		short mtemp;
		byte[] A = new byte[16];
      byte[] B = new byte[16];
      for(i=0;i<4;++i)
	{
      	for(j=0;j<4;++j)
      		A[4*i+j] = GETB(3-j, x[i]);

	}


		/* B = A * G */
		for (i = 0; i < 4; i++)
	{
			for (j = 0; j < 4; j++)
      {
			B[4*i+j] = (byte)(
				mul (A[4*i], Sqtab.G[j]) ^ // 2nd index increments fastest in 'C'
				mul (A[4*i+1], Sqtab.G[4+j]) ^
				mul (A[4*i+2], Sqtab.G[8+j]) ^
				mul (A[4*i+3], Sqtab.G[12+j])
            );
		}

	}

		for (i = 0; i < 4; i++) {
			x[i] =
			PUTB (3,B[4*i]) ^
			PUTB (2,B[4*i+1]) ^
			PUTB (1,B[4*i+2]) ^
			PUTB (0,B[4*i+3]);
		}
	/* destroy potentially sensitive information: */
		for(mtemp = 0; mtemp<16; ++mtemp)
   		A[mtemp] = B[mtemp] = 0;
   }

   public void round(SquareVec text,
   				int[] T0, int[] T1, int[] T2, int[] T3,
               SquareVec roundKey)
   {
   	x[0] = T0[uint8(GETB(3,text.x[0]))]
			^ T1[uint8(GETB(3,text.x[1]))]
			^ T2[uint8(GETB(3,text.x[2]))]
			^ T3[uint8(GETB(3,text.x[3]))]
			^ roundKey.x[0];
		x[1] = T0[uint8(GETB(2,text.x[0]))]
			^ T1[uint8(GETB(2,text.x[1]))]
			^ T2[uint8(GETB(2,text.x[2]))]
			^ T3[uint8(GETB(2,text.x[3]))]
			^ roundKey.x[1];
		x[2] = T0[uint8(GETB(1,text.x[0]))]
  			^ T1[uint8(GETB(1,text.x[1]))]
			^ T2[uint8(GETB(1,text.x[2]))]
			^ T3[uint8(GETB(1,text.x[3]))]
			^ roundKey.x[2];
		x[3] = T0[uint8(GETB(0,text.x[0]))]
			^ T1[uint8(GETB(0,text.x[1]))]
			^ T2[uint8(GETB(0,text.x[2]))]
			^ T3[uint8(GETB(0,text.x[3]))]
			^ roundKey.x[3];
	}


   public void round8(SquareVec temp,
   						byte[] S,
                     SquareVec roundKey)
	{
   	x[0] = PUTB(3, temp.kernel(S,3,0))
			^ PUTB(2,temp.kernel(S,3,1))
			^ PUTB(1,temp.kernel(S,3,2))
			^ PUTB(0,temp.kernel(S,3,3))
			^ roundKey.x[0];
		x[1] = PUTB(3, temp.kernel(S,2,0))
			^ PUTB(2,temp.kernel(S,2,1))
			^ PUTB(1,temp.kernel(S,2,2))
			^ PUTB(0,temp.kernel(S,2,3))
			^ roundKey.x[1];
		x[2] = PUTB(3, temp.kernel(S,1,0))
			^ PUTB(2,temp.kernel(S,1,1))
			^ PUTB(1,temp.kernel(S,1,2))
			^ PUTB(0,temp.kernel(S,1,3))
			^ roundKey.x[2];
		x[3] = PUTB(3, temp.kernel(S,0,0))
			^ PUTB(2,temp.kernel(S,0,1))
			^ PUTB(1,temp.kernel(S,0,2))
			^ PUTB(0,temp.kernel(S,0,3))
			^ roundKey.x[3];
	}

} // end of SquareVec

