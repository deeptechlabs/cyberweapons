# SCCS ID @(#)Makefile.PL	1.8 96/03/14
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile being created.

#
# Object linkage in Crypt-Lib/Crypt/*.pm.
#
my $version = '1.08';

WriteMakefile(
	NAME => 'Crypt::MD5',
	DISTNAME => 'Crypt-MD5',
	VERSION => $version,
	OBJECT => q[MD5$(OBJ_EXT) md5c$(OBJ_EXT)],
	XSPROTOARG => '-noprototypes',
	'dist'   => {COMPRESS=>'gzip', SUFFIX=>'gz'}
);
