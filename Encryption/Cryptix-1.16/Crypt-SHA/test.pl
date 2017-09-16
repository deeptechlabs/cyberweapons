BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }


package Crypt::SHA;

use Exporter;
use DynaLoader;
@ISA = qw(Exporter DynaLoader);

bootstrap Crypt::SHA;

package main;

sub do_test
{
    my ($label, $str, $expect) = @_;

    my $sha = new Crypt::SHA;
	ref($sha) || print "Error - $sha\n";

    $sha->add($str);

	print "not " unless ($expect eq unpack("H*", $sha->digest()));

	print "ok $label\n";
}


print "1..3\n";

#
# If the following results don't match, check that you have\ncorrectly set LITTLE_ENDIAN
# in sha_func.c, and that USE_MODIFIED_SHA is undefined.
# I have no test cases for the modified SHA algorithm.
#
do_test("1", "abc",
	"a9993e364706816aba3e25717850c26c9cd0d89d");
do_test("2", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"84983e441c3bd26ebaae4aa1f95129e5e54670f1");
do_test("3", "a" x 1000000,
	"34aa973cd4c4daa4f61eeb2bdbad27316534016f");
