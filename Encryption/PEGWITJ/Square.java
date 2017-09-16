//package UK.co.demon.windsong.tines.pegwit;
/*
 * The Square block cipher.
 *
 * Algorithm developed by Joan Daemen <Daemen.J@banksys.com> and
 * Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *
 * This public domain implementation by Paulo S.L.M. Barreto
 * <pbarreto@uninet.com.br> and George Barwood <george.barwood@dial.pipex.com>
 * based on software originally written by Vincent Rijmen.
 *
 * Caveat: this code assumes 32-bit words and probably will not work
 * otherwise.
 *
 * @author Java conversion by Mr. Tines<tines@windsong.demon.co.uk>
 * This version in-lines a lot for speed (of coding as much as execution)
 * rather than being fully encapsulated - Square looks at the innards
 * of SquareVec for convenience.
 *
 * Version 2.5 (1997.04.25)
 *
 * =============================================================================
 *
 * Differences from version 2.4 (1997.04.09):
 *
 * - Changed all initialization functions so that the IV (when applicable)
 *   is separately loaded.
 *
 * - Ciphertext Stealing (CTS) mode added.
 *
 * - Output Feedback (OFB) mode added.
 *
 * - Cipher Block Chaining (CBC) mode added.
 *
 * - Split square.c int several files according to the specific functionality
 *   (basic functions, modes, testing).
 *
 * - Flipped tables according to the endianness of the subjacent platform
 *   for best performance.
 *
 * - Changed "maketabs.c" to "sqgen.c" for compatibility with the Pegwit system.
 *
 * =============================================================================
 *
 * Differences from version 2.3 (1997.04.09):
 *
 * - Defined function squareExpandKey() to enhance performance of both CFB
 *   initialization and hash computation (not yet implemented).
 *
 * - Changed definition of function squareTransform() to accept a single in-out
 *   parameter, and optimized function squareGenerateRoundKeys accordingly.
 *
 * =============================================================================
 *
 * Differences from version 2.2 (1997.03.03):
 *
 * - Cipher feedback (CFB) mode added (heavily based on an old public domain CFB
 *   shell written by Colin Plumb for the IDEA cipher).
 *
 * - Fixed word size problem (64 bits rather than 32) arising on the Alpha.
 *
 * - Reformatted indented sections of compiler directives for use with old,
 *   non-ANSI compliant compilers.
 *
 * Differences from version 2.1 (1997.03.03):
 *
 * - Added optional Microsoft x86 assembler version, which can boost performance
 *   by up to 20% depending on the target machine, and generates smaller code.
 *
 * Differences from version 2.0 (1997.02.11):
 *
 * - Added typecasts to the build-up of out[] in function squareTransform()
 *   to make it portable to 16-bit (MSDOS) systems.
 *
 * - Truncated alogtab[] back to 256 elements and changed the mul() macro
 *   accordingly.  Using an extended table to avoid a division seemed an
 *   unnecessary storage overhead (it could be useful to speed up hash
 *   functions derived from Square, but other optimizations are likely to be
 *   more effective).
 *
 * Differences from version 2.0 (1997.02.11):
 *
 * - Updated definition of Square algorithm (version 1.0 implemented an
 *   embryonic form of Square).
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

public class Square {

	SquareVec[] keyschedE = null;
   SquareVec[] keyschedD = null;

   public Square()
   {
   	keyschedE = new SquareVec[Sqtab.ROUNDS+1];
   	keyschedD = new SquareVec[Sqtab.ROUNDS+1];
	for(int i=0; i<=Sqtab.ROUNDS;++i)
	{
		keyschedE[i] = new SquareVec();
		keyschedD[i] = new SquareVec();
	}
   }

	public static final String squareBanner =
	"Square cipher v.2.5 Java implementation\n";


	public Square(Sqblock s)
   {
	this();
		generateRoundKeys(s);
   }

	public void debug()
	{
		if(keyschedE != null) 
			for(int i=0; i<keyschedE.length; ++i) keyschedE[i].debug();
		if(keyschedD != null) 
			for(int i=0; i<keyschedD.length; ++i) keyschedD[i].debug();
	}

   public Square(Sqblock s, boolean both)
   {
   	keyschedE = new SquareVec[Sqtab.ROUNDS+1];
	for(int i=0; i<=Sqtab.ROUNDS;++i)
	{
		keyschedE[i] = new SquareVec();
	}
   	if(both)
      {	keyschedD = new SquareVec[Sqtab.ROUNDS+1];
		for(int i=0; i<=Sqtab.ROUNDS;++i)
		{
			keyschedD[i] = new SquareVec();
		}
			generateRoundKeys(s);
   	}
      else expandKey(s);
   }


   private void generateRoundKeys(Sqblock key)
   {
		keyschedE[0].copy(key);

		/* apply the key evolution function: */
      for(int t=1; t<Sqtab.ROUNDS+1; ++t)
      {
			keyschedD[Sqtab.ROUNDS-t].copy(
         	keyschedE[t].evolve(keyschedE[t-1], t)
         );
			/* apply the theta diffusion function: */
         keyschedE[t-1].transform();

		}
		keyschedD[Sqtab.ROUNDS].copy(keyschedE[0]);
	}

   private void expandKey(Sqblock key)
   {
      	keyschedE[0].copy(key);

	/* apply the key evolution function: */
      for(int t=1; t<Sqtab.ROUNDS+1; ++t)
      {
      	keyschedE[t].evolve(keyschedE[t-1], t);
			/* apply the theta diffusion function: */
         keyschedE[t-1].transform();
		}
	}



   public void encrypt(Sqblock buffer) // a 16-byte buffer order as read
   {
   	SquareVec text = new SquareVec(buffer.x);
      SquareVec temp = new SquareVec();
		/* initial key addition */
		text.xor(keyschedE[0]);

		/* R - 1 full rounds */
		temp.round(text, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[1]);
		text.round(temp, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[2]);
		temp.round(text, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[3]);
		text.round(temp, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[4]);
		temp.round(text, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[5]);
		text.round(temp, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[6]);
		temp.round(text, Sqtab.Te0, Sqtab.Te1,
      					   Sqtab.Te2, Sqtab.Te3, keyschedE[7]);

		/* last round (diffusion becomes only transposition) */
      text.round8(temp, Sqtab.Se, keyschedE[Sqtab.ROUNDS]);

		text.unpack(buffer.x);

		/* destroy sensitive data: */
		temp.wipe();
		text.wipe();

	}

   public void decrypt(Sqblock buffer)
   {
   	SquareVec text = new SquareVec(buffer.x);
      SquareVec temp = new SquareVec();

		/* initial key addition */
		text.xor(keyschedD[0]);

		/* R - 1 full rounds */
		temp.round(text, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[1]);
		text.round(temp, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[2]);
		temp.round(text, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[3]);
		text.round(temp, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[4]);
		temp.round(text, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[5]);
		text.round(temp, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[6]);
		temp.round(text, Sqtab.Td0, Sqtab.Td1,
      					   Sqtab.Td2, Sqtab.Td3, keyschedD[7]);

		/* last round (diffusion becomes only transposition) */
      text.round8(temp, Sqtab.Sd, keyschedD[Sqtab.ROUNDS]);

		text.unpack(buffer.x);

		/* destroy sensitive data: */
		temp.wipe();
		text.wipe();
	}

   public void finish()
   {
   	if( keyschedE != null)
      	for(int i=0; i<keyschedE.length; ++i) keyschedE[i].wipe();
   	if( keyschedD != null)
      	for(int i=0; i<keyschedD.length; ++i) keyschedD[i].wipe();
   }
}


