//package UK.co.demon.windsong.tines.pegwit;
/*
	Ciphertext Stealing (CTS) mode support

	IMPORTANT REMARKS:

	1.	This is a variant of  Cipher Block Chaining which relaxes the restriction
		that the buffer length be a multiple of  SQUARE_BLOCKSIZE.  Note that the
		buffer length must still be >= SQUARE_BLOCKSIZE.
	2.	The IV is encrypted to avoid the possibility of being correlated with the
		plaintext.
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
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

  
public class SquareCts extends Square {
	Sqblock mask;

   public SquareCts(Sqblock s)
   {
   	super(s);
   }

   public SquareCts(Sqblock s, boolean both)
   {
   	super(s,both);
   }

	public void setIV(Sqblock iv)
   {
   	mask = new Sqblock(iv);
      super.encrypt(mask);
   }

   public void encrypt(byte[] buffer, int l)
   {
//		int l = buffer.length;
      int i = 0;
		Sqblock chunk = new Sqblock();
      Sqblock localMask = new Sqblock(mask);

      while(l >= Sqblock.BLOCKSIZE)
      {
			/* mask and encrypt the current block: */
         chunk.pack(buffer, i);
         chunk.xor(localMask);
         super.encrypt(chunk);

			/* update the mask: localMask "points to" buffer[i] */
			localMask.copy(chunk);
         chunk.unpack(buffer, i);

			/* proceed to the next block, if any: */
			i += Sqblock.BLOCKSIZE;
			l -= Sqblock.BLOCKSIZE;
		}
		/* save last encrypted block in context */
      mask.copy(localMask);

		if (l != 0)
      {
			/* "ciphertext stealing" (using mask as temporary buffer) */
      	mask.xorbuf(buffer, i, l);
			localMask.unpackBuf(buffer, i, l);/* last, incomplete block */
      	super.encrypt(mask);
         localMask.copy(mask); /* next-to-last, complete block */
			/* note that mask contains an encrypted block still unused as mask */
      	localMask.unpack(buffer, i-Sqblock.BLOCKSIZE);
		}
		localMask.clear();
	} /* squareCtsEncrypt */

	public void decrypt(byte[] buffer, int l)
   {
//		int l = buffer.length;
      Sqblock temp = new Sqblock();
      Sqblock chunk = new Sqblock();
      int i = 0;

		while (l >= 2*Sqblock.BLOCKSIZE)
      {
			/* save the current block for chaining: */
         temp.pack(buffer, i);
         chunk.copy(temp);

			/* decrypt and unmask the block: */
         super.decrypt(chunk);
         chunk.xor(mask);
         chunk.unpack(buffer, i);
			/* update the mask: */
         mask.copy(temp);
			/* proceed to the next block, if any: */
			i += Sqblock.BLOCKSIZE;
			l -= Sqblock.BLOCKSIZE;
		}
		/* now SQUARE_BLOCKSIZE <= length < 2*SQUARE_BLOCKSIZE */

		/* save the current block for chaining: */
      temp.pack(buffer, i);
      chunk.copy(temp);
      super.decrypt(chunk);
		if (l > Sqblock.BLOCKSIZE)
      {
         chunk.unpack(buffer, i);
         /* decrypt and unmask the last, incomplete block: */

			for (int j = 0; j < l - Sqblock.BLOCKSIZE; ++j)
         {
				/* at this point, buffer[i + SQUARE_BLOCKSIZE]  contains */
				/* a cipherbyte C, and buffer[i] contains the XOR of the */
				/* same cipherbyte with the corresponding plainbyte P... */
				buffer[i+j] ^= (buffer[i + j+ Sqblock.BLOCKSIZE] ^= buffer[i+j]);
				/* ... now buffer[i] contains only the cipherbyte C, and */
				/* buffer[i + SQUARE_BLOCKSIZE] contains the plainbyte P */
         }
			/* decrypt the next-to-last, complete block: */
         chunk.pack(buffer, i);
         super.decrypt(chunk);
		}
		chunk.xor(mask);
      chunk.unpack(buffer, i);
		/* update the mask: */
      mask.copy(temp);

		/* destroy potentially sensitive data: */
      temp.clear();
		/* N.B. this cleanup is in principle unnecessary */
		/* as temp only contains encrypted (public) data */
	} /* squareCtsDecrypt */


	public void finish ()
	{
   	super.finish();
		if(mask != null) mask.clear();
	} /* squareCtsFinal */
} //EoC
