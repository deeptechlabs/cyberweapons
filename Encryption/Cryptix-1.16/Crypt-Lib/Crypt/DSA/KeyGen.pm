#
# Copyright (C) 1997 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.1.1.1 $
# $State: Exp $
#

package Crypt::DSA::KeyGen;

use strict;
use integer;

use Math::BigInteger;
use Math::Random;
use Crypt::DSA::SecretKey;


sub createQ
{
	my $ris = shift;
	my $keylen = shift;

    S=randfunc(20)
    hash1=sha.new(S).digest()
    hash2=sha.new(Int2Str(Str2Int(S)+1)).digest()
    q = bignum(0)
    for i in range(0,20):
        c=ord(hash1[i])^ord(hash2[i])
        if i==0: c=c | 128
        if i==19: c= c | 1
        q=q*256+c
    while (not PrimeNumber(q)):
        q=q+2
    if pow(2,159L)<q<pow(2,160L): return S, q
    raise error, 'Bad q value generated'
}

sub createKey
{
	my $ris = shift;
	my $keylen = shift;
	my $cb = shift;

	my $p = Math::Random::randomSpecial($ris, $keylen, "1", "1");
	do {
		$p--; $p--;
		defined($cb) && &{$cb}(0);
	} while (!Math::TestPrime::isPrime($p));


	# g is a random number between 1 and 64 bits shorter than p
	my $bits = $keylen - (1 + ord($ris->read(1)) % 64);
	my $g = Math::Random::randomSpecial($ris, $bits, "1", "1");

	# x is a random number between 1 and 256 bits shorter than p
	$bits = $keylen - (1 + ord($ris->read(1)));
	my $x = Math::Random::randomSpecial($ris, $bits, "1", "1");

	# y = g**x mod p
	my $y = new Math::BigInteger;
	Math::BigInteger::mod_exp($y, $g, $x, $p);

	return new Crypt::DSA::SecretKey $p, $g, $y, $x;
}

1;
keydata=['y', 'x', 'g', 'p', 'q']

    
# Generate a DSA modulus with L bits
def generate(L, randfunc, verbose=None):
    if L<160: raise error, 'Key length <160 bits'
    obj=DSAobj()
    # Generate string S and prime q
    if verbose: apply(verbose, ('p, q\n',))
    while (1):
        S, obj.q = generateQ(L, randfunc)
        n=(L-1)/160
        C, N, V = 0, 2, {}
	b=(obj.q >> 5) & 15
	powb=pow(bignum(2), b)
	powL1=pow(bignum(2), L-1)
        while C<4096:
            for k in range(0, n+1):
		V[k]=Str2Int(sha.new(S+str(N)+str(k)).digest())
            W=V[n] % powb
            for k in range(n-1, -1, -1): W=(W<<160L)+V[k]
            X=W+powL1
            p=X-(X%(2*obj.q)-1)
            if powL1<=p and PrimeNumber(p): break
            C, N = C+1, N+n+1
        if C<4096: break
	if verbose: apply(verbose, ('4096 multiples failed\n',) )
    obj.p = p
    power=(p-1)/obj.q
    if verbose: apply(verbose, ('h,g\n',))
    while (1):
        h=Str2Int(randfunc(L)) % (p-1)
        g=pow(h, power, p)
        if 1<h<p-1 and g>1: break
    obj.g=g
    if verbose: apply(verbose, ('x,y\n',))
    while (1):
        x=Str2Int(randfunc(20))
        if 0<x<obj.q: break
    obj.x, obj.y=x, pow(g, x, p)
    return obj
