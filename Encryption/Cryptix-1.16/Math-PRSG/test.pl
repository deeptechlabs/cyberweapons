BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#

package Math::PRSG;

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);

bootstrap Math::PRSG;


$prsg = new Math::PRSG pack("H*", "0123456789ABCDEF0123456789ABCDEF01234567");

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



