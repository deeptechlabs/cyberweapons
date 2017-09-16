BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }


package Crypt::MD5;

use Exporter;
use DynaLoader;
@ISA = qw(Exporter DynaLoader);

bootstrap Crypt::MD5;

package main;

sub do_test
{
    my ($label, $str, $expect) = @_;

    my $md5 = new Crypt::MD5;
	ref($md5) || print "Error - $md5\n";

    $md5->add($str);

	print "not " unless ($expect eq unpack("H*", $md5->digest()));

	print "ok $label\n";
}


print "1..7\n";

do_test("1", "", "d41d8cd98f00b204e9800998ecf8427e");
do_test("2", "a", "0cc175b9c0f1b6a831c399e269772661");
do_test("3", "abc", "900150983cd24fb0d6963f7d28e17f72");
do_test("4", "message digest", "f96b697d7cb7938d525a2f31aaf161d0");
do_test("5", "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
do_test("6", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
   "d174ab98d277d9f5a5611c2c9f419d9f");
do_test("7", "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
   "57edf4a22be3c955ac49da2e2107b67a");


