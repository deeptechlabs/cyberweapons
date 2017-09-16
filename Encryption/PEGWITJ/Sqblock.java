//package UK.co.demon.windsong.tines.pegwit;
/*
 * The Square block cipher block.
 *
 * Algorithm developed by Joan Daemen <Daemen.J@banksys.com> and
 * Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *
 * This public domain implementation by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> and George Barwood <george.barwood@dial.pipex.com>
 * based on software originally written by Vincent Rijmen.
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 *
 * ==============================================================================
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

public class Sqblock {

	public static final int BLOCKSIZE = 16; // bytes
   byte[] x = null;

   public Sqblock(Vlpoint v)
   {
   	x = new byte[BLOCKSIZE];
		for(int n=0; n<BLOCKSIZE; ++n) x[n] = v.getByte(n);
   }

	public Sqblock()
   {
   	x = new byte[BLOCKSIZE];
   	clear();
   }

   public Sqblock(Sqblock s)
   {
   	x = new byte[BLOCKSIZE];
   	copy(s);
   }

   public Sqblock(byte[] b, int offset)
   {
   	x = new byte[BLOCKSIZE];
      pack(b,offset);
   }

   public void pack(byte[] b, int offset)
   {
   	for(int i=0; i<BLOCKSIZE; ++i) x[i] = b[i+offset];
   }

	public void debug()
	{
		int i, j;
		if(null == x) {System.out.println("null block"); return;}
		for(i=0; i<4;++i)
		{
			for(j=0; j<4; ++j)
			{
				int k = x[4*i+j] & 0xFF;
				System.out.print(" "+Integer.toHexString(k));

			}
			System.out.println(" ");
		}
	}

	public void unpack(byte[] b, int offset)
   {
   	for(int i=0; i<BLOCKSIZE; ++i) b[i+offset] = x[i];
	}

   public void unpackBuf(byte[] b, int offset, int bytes)
   {
   	for(int i=0; i<bytes && i<BLOCKSIZE; ++i) b[i+offset] = x[i];
	}

   public void clear()
   {
   	for(int i=0; i<BLOCKSIZE; ++i) x[i] = 0;
   }

   public void xor(Sqblock s)
   {
   	for(int i=0; i<BLOCKSIZE; ++i) x[i] ^= s.x[i];
   }

   public void xorbuf(byte[] b, int offset, int bytes)
   {
   	for(int i=0; i<bytes && i<BLOCKSIZE; ++i) x[i] ^= b[offset+i];
   }

   public void copy(Sqblock s)
   {
   	for(int i=0; i<BLOCKSIZE; ++i) x[i] = s.x[i];
   }

	public void increment()
   {
   	int i = 0;
      while (x[i] == 0xff) x[i++] = 0;
      ++x[i];
   }

   public int chunk(int i)// This index order for SqVec.copy(Sqblock)
   {
		 return ((0xFF & x[4*i+3])<<24) | 
                    ((0xFF & x[4*i+2])<<16) | 
                    ((0xFF & x[4*i+1])<<8) | 
			   (0xFF & x[4*i+0]);
   }
}

