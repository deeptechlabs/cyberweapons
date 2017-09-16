BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
# 

package Math::BigInteger;

use Exporter;
use DynaLoader;
@ISA = (Exporter, DynaLoader);

bootstrap Math::BigInteger;


print "1..16\n";

my $n = new Math::BigInteger;

$n->inc();
$n->dec();
(unpack("H*", $n->save()) eq "") && print "1 ok\n";
$n->inc();
(unpack("H*", $n->save()) eq "01") && print "2 ok\n";
$n->inc();
(unpack("H*", $n->save()) eq "02") && print "3 ok\n";
$n->dec();
(unpack("H*", $n->save()) eq "01") && print "4 ok\n";

my $n2 = Math::BigInteger::clone($n);
(unpack("H*", $n2->save()) eq "01") && print "5 ok\n";
$n2->inc();
(unpack("H*", $n2->save()) eq "02") && print "6 ok\n";

Math::BigInteger::mul($n, $n2, $n2);
Math::BigInteger::mul($n2, $n, $n);
Math::BigInteger::mul($n, $n2, $n2);
Math::BigInteger::mul($n2, $n, $n);
Math::BigInteger::mul($n, $n2, $n2);
Math::BigInteger::mul($n2, $n, $n);
Math::BigInteger::mul($n, $n2, $n2);
Math::BigInteger::mul($n2, $n, $n);
Math::BigInteger::mul($n, $n2, $n2);
Math::BigInteger::mul($n2, $n, $n);

(unpack("H*", $n->save()) eq "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") && print "7 ok\n";

(unpack("H*", $n2->save()) eq "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") && print "8 ok\n";


$n2->mul($n, $n);
$n2->dec();
$n2->dec();

(unpack("H*", $n2->save()) eq "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe") && print "9 ok\n";

my $n3 = restore Math::BigInteger $n2->save();
$n3->dec();

(unpack("H*", $n3->save()) eq "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd") && print "10 ok\n";


#
#	Test for strange bug
#
my $zero = new Math::BigInteger;
my $i = new Math::BigInteger 1;

print "11 ", (unpack("H*", $zero->save()) eq "") ? "ok" : "not ok", "\n";
print "12 ", (unpack("H*", $i->save()) eq "01") ? "ok" : "not ok", "\n";
print "13 ", (unpack("H*", $zero->save()) eq "") ? "ok" : "not ok", "\n";

#
# Test initialisation works correctly, especially over 65535
#
$i = new Math::BigInteger 12345;
print "14 ", (unpack("H*", $i->save()) eq "3039") ? "ok" : "not ok", "\n";

$i = new Math::BigInteger 76543;
print "15 ", (unpack("H*", $i->save()) eq "012aff") ? "ok" : "not ok", "\n";

my $rem = new Math::BigInteger;
my $d = new Math::BigInteger 2;
$i->div($rem, $i, $d);
print "16 ", (unpack("H*", $i->save()) eq "957f") ? "ok" : "not ok", "\n";
