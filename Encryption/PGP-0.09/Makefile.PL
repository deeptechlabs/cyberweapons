#! /usr/local/bin/perl

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.

my $revstr = '$State: Release_0_09 $';
my ($junk, $major, $minor);
($junk, $major, $minor) = split('_', $revstr);

my $version = sprintf "%d.%02d", $major, $minor;

WriteMakefile(
	'NAME' => 'PGP',
	'VERSION' => $version,
	'dist'   => {COMPRESS=>'gzip', SUFFIX=>'gz'},
);
