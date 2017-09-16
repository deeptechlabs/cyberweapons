BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

use strict;

use Math::BigInteger;
use Math::PRSG;
use Math::PseudoRandomStream;
use Math::TestPrime;

my $bi = new Math::BigInteger 76543;
print "$bi\n";
print Math::TestPrime::smallFactor($bi), "\n";
print Math::TestPrime::isPrime($bi), "\n";
Math::TestPrime::isPrime($bi) || print "not ";
print "ok\n";

print "1..18\n";

my $prsg = new Math::PRSG pack("H*", "0123456789ABCDEF0123456789ABCDEF01234567");

print "1 ";
(unpack("H*", $prsg->clock()) eq "c091a2b3c4d5e6f78091a2b3c4d5e6f7c091a2b3") || print "not ";
print "ok\n";

print "2 ";
(unpack("H*", $prsg->clock()) eq "a048d159e26af37bc048d159e26af37ba048d159") || print "not ";
print "ok\n";

print "3 ";
(unpack("H*", $prsg->clock()) eq "902468acf13579bde02468acf13579bd902468ac") || print "not ";
print "ok\n";

print "4 ";
for (1..100) { $prsg->clock(); }
(unpack("H*", $prsg->clock()) eq "ce17614bad2da758f2c1b2e7d4812345227b74f4") || print "not ";
print "ok\n";

print "5 ";
for (1..100000) { $prsg->clock(); }
(unpack("H*", $prsg->clock()) eq "b0d927dd87d8b63859643d40ea736bb6379656b1") || print "not ";
print "ok\n";



$prsg = new Math::PseudoRandomStream pack("H*", "0123456789ABCDEF0123456789ABCDEF01234567");

print "6 ";
(unpack("H*", $prsg->read(20)) eq "c091a2b3c4d5e6f78091a2b3c4d5e6f7c091a2b3") || print "not ";
print "ok\n";

print "7 ";
(unpack("H*", $prsg->read(20)) eq "a048d159e26af37bc048d159e26af37ba048d159") || print "not ";
print "ok\n";

print "8 ";
(unpack("H*", $prsg->read(20)) eq "902468acf13579bde02468acf13579bd902468ac") || print "not ";
print "ok\n";

print "9 ";
$prsg->skip(2000);
(unpack("H*", $prsg->read(20)) eq "ce17614bad2da758f2c1b2e7d4812345227b74f4") || print "not ";
print "ok\n";

print "10 ";
$prsg->skip(2000000);
(unpack("H*", $prsg->read(20)) eq "b0d927dd87d8b63859643d40ea736bb6379656b1") || print "not ";
print "ok\n";

print "11 ";
# dropped extra 'my' from hereon as causes warnings in later Perls
$bi = new Math::BigInteger 34567;
Math::TestPrime::isPrime($bi) && print "not ";
print "ok\n";

print "12 ";
$bi = new Math::BigInteger 76543;
Math::TestPrime::isPrime($bi) || print "not ";
print "ok\n";

print "13 ";
$bi = restore Math::BigInteger pack("H*", "D9BEAD898AAB1AEE84D7E1740C63D293D30689FE7F2CA169");
Math::TestPrime::isPrime($bi) && print "not ";
print "ok\n";

print "14 ";
$bi++; $bi++;
Math::TestPrime::isPrime($bi) || print "not ";
print "ok\n";

print "15 ";
$bi++; $bi++;
Math::TestPrime::isPrime($bi) && print "not ";
print "ok\n";

print "16 ";
$bi = restore Math::BigInteger pack("H*", "F3F075C82B5CEB105103ABDFF97545CEDAB935B47FA68FFF");
Math::TestPrime::isPrime($bi) && print "not ";
print "ok\n";

print "17 ";
$bi++; $bi++;
Math::TestPrime::isPrime($bi) || print "not ";
print "ok\n";

print "18 ";
$bi++; $bi++;
Math::TestPrime::isPrime($bi) && print "not ";
print "ok\n";
