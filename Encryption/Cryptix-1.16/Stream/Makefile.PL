#! /usr/local/bin/perl

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.

my $revstr = '$Revision: 1.1.1.1 $';      
my ($junk, $rev, $junk2);
($junk, $rev, $junk2) = split('\s', $revstr);
my ($major, $minor);
($major, $minor, $junk) = split('\.', "$rev");

my $version = sprintf "%d.%02d", $major, $minor;

WriteMakefile(
	'NAME' => 'Stream',
	'VERSION' => $version,
	'dist'   => {COMPRESS=>'gzip', SUFFIX=>'gz'},
);
