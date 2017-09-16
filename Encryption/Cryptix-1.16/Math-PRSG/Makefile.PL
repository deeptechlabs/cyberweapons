#! /usr/local/bin/perl

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.

#
# Object linkage in Crypt-Lib/Crypt/*.pm not file revision?
#
my $version = "1.03";

# my $revstr = '$Revision: 1.2 $';      
# my ($junk, $rev, $junk2);
# ($junk, $rev, $junk2) = split('\s', $revstr);
# my ($major, $minor);
# ($major, $minor, $junk) = split('\.', "$rev");
# 
# my $version = sprintf "%d.%02d", $major, $minor;

WriteMakefile(
	'NAME' => 'Math::PRSG',
	'DISTNAME' => 'Math-PRSG',
	'VERSION' => $version,
	'OBJECT' => 'PRSG.o prsg.o',
	'dist'   => {COMPRESS=>'gzip', SUFFIX=>'gz'}
);
