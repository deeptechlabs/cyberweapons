BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }


package Crypt::SHA0;

use Exporter;
use DynaLoader;
@ISA = qw(Exporter DynaLoader);

bootstrap Crypt::SHA0;

package main;

sub do_test
{
    my ($label, $str, $expect) = @_;

    my $sha = new Crypt::SHA0;
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
	"0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
do_test("2", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"d2516ee1acfa5baf33dfc1c471e438449ef134c8");
do_test("3", "a" x 1000000,
	"3232affa48628a26653b5aaa44541fd90d690603");
