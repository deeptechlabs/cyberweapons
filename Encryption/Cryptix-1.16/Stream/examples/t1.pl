#!/usr/local/bin/perl -w -I.

use DataEncoding qw(/^encode/ /^decode/);

my $t0 = encodeLength(0);
print unpack("H*", $t0), "\n";
my $t0 = decodeLength($t0);
print $t0, "\n";

my $t0 = encodeLength(0);
my $t1 = encodeLength(1);
my $t2 = encodeLength(127);
my $t3 = encodeLength(128);
my $t4 = encodeLength(129);
my $t5 = encodeLength(16382);
my $t6 = encodeLength(16383);
my $t7 = encodeLength(16384);
my $t8 = encodeLength(16385);

print unpack("H*", $t0), "\n";
print unpack("H*", $t1), "\n";
print unpack("H*", $t2), "\n";
print unpack("H*", $t3), "\n";
print unpack("H*", $t4), "\n";
print unpack("H*", $t5), "\n";
print unpack("H*", $t6), "\n";
print unpack("H*", $t7), "\n";
print unpack("H*", $t8), "\n";

my $t0 = decodeLength($t0);
my $t1 = decodeLength($t1);
my $t2 = decodeLength($t2);
my $t3 = decodeLength($t3);
my $t4 = decodeLength($t4);
my $t5 = decodeLength($t5);
my $t6 = decodeLength($t6);
my $t7 = decodeLength($t7);
my $t8 = decodeLength($t8);

print $t0, "\n";
print $t1, "\n";
print $t2, "\n";
print $t3, "\n";
print $t4, "\n";
print $t5, "\n";
print $t6, "\n";
print $t7, "\n";
print $t8, "\n";


