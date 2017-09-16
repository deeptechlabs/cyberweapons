#! /usr/local/bin/perl

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.

my $revstr = '$State: Release_1_16 $';
my ($junk, $major, $minor);
($junk, $major, $minor) = split('_', $revstr);

my $version = sprintf "%d.%02d", $major, $minor;


WriteMakefile(
	'NAME' => 'Cryptix',
	'VERSION' => $version,
	'DIR' => [
		'Crypt-Lib',
		'Crypt-Blowfish',
		'Crypt-DES',
		'Crypt-IDEA',
		'Crypt-MD5',
		'Crypt-SHA',
		'Crypt-SHA0',
		'Math-Lib',
		'Math-BigInteger',
		'Math-PRSG',
		'Math-TrulyRandom',
		'Stream'
	],
	'dist'   => {COMPRESS=>'gzip', SUFFIX=>'gz'},
);

# bug: the above generates empty removes 'rm -f ' for target realclean.
