//package UK.co.demon.windsong.tines.pegwit;
//import java.io.*;
/*
 * Elliptic curve cryptographic primitives
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

public class Eccrypt extends Vlpoint {

	public Eccrypt()
   {
   	super();
   }

	public Vlpoint makePublicKey ()
	{
   	Ecpoint pubkey = new Ecpoint(true);
      pubkey.multiply(this);
      return pubkey.pack();
   }

   public Vlpoint[] encrypt(Vlpoint secret)
   {
	Vlpoint [] result = new Vlpoint[2];

		Ecpoint q = new Ecpoint(true);
      q.multiply(secret);
      result[0] = q.pack();
      q.unpack(this);
      q.multiply(secret);
      result[1] = q.xpack();
	return result;
	}


	public Vlpoint decrypt(Vlpoint message)
   {
		Ecpoint q = new  Ecpoint();
		Vlpoint plaintext = new Vlpoint();
      q.unpack(message);
      q.multiply(this);
		plaintext = q.xpack();
	return plaintext;
   }

	public void sign(Vlpoint k, Vlpoint digest, Ecsig sig)
   {
   	Ecpoint q = new Ecpoint(true);
      q.multiply(k);
      sig.r = q.xpack();
      sig.r.add(digest);
      sig.r.remainder(Ecpoint.prime);
      if(sig.r.peek(0) == 0) return;

      Vlpoint tmp = new Vlpoint();
      tmp.mulMod(this, sig.r, Ecpoint.prime);
      sig.s.copy (k);
      if(tmp.greater(sig.s)) sig.s.add(Ecpoint.prime);
      sig.s.subtract(tmp);
   }

   public boolean verify(Vlpoint digest, Ecsig sig)
   {
   	Ecpoint t1 = new Ecpoint(true);
      t1.multiply(sig.s);
      Ecpoint t2 = new Ecpoint();
      t2.unpack(this);
      t2.multiply(sig.r);
      t1.add(t2);
      Vlpoint t4 = t1.xpack();
      t4.remainder(Ecpoint.prime);
      Vlpoint t3 = new Vlpoint();
      t3.copy(sig.r);
      if(t4.greater(t3)) t3.add(Ecpoint.prime);
      t3.subtract(t4);
      return t3.equals(digest);
	}
}

