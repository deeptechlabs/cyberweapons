#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

#
#	Comments on the randomness and security of this stream
#	would be much appreciated - Gary@systemics.com
#

package PGP::RandomStream;

use Crypt::CSRandomStream;
@ISA = qw( Crypt::CSRandomStream );

use strict;
use IO::File;
use English;
use Math::TrulyRandom;
use Crypt::SHA;



sub new
{
	my $type = shift;

	my $seed = (-f '/dev/random') ? seedFromRandomDevice() : generateFastSeed();

	my $self = new Crypt::CSRandomStream $seed;

	bless $self, $type;
}



#
#	NB - The seed for the random number generator should
#	ideally use a milli/microsecond timer between commands.
#
sub generateFastSeed
{
	my $md = new Crypt::SHA;
	$md->add(time());
	$md->add($BASETIME);
	$md->add($SYSTEM_FD_MAX);
	$md->add($$);
	$md->add($<);
	$md->add($>);
	$md->add($();
	$md->add($));
	$md->add(getppid());
	my $val = readSeedFile();
	$md->add(time());
	unless (defined $val)
	{
		$val = Math::TrulyRandom::rand();
	}
	$md->add($val);
	$md->add(time());
	$md->digest();
}

sub seedWithoutSaving
{
	my $self = shift;

	$self->seed(generateFastSeed());
}

sub fastSeed
{
	my $self = shift;

	$self->seed(generateFastSeed());
	$self->updateSeedFile();
}

sub runCmd
{
	my $file = shift;
	my @data;

	open(RANDOM_FH, "$file 2>&1 |");
	@data = <RANDOM_FH>;
	close(RANDOM_FH);
	@data;
}

sub seedFromRandomDevice
{
	my $self = shift;

	my $fh = new IO::File "</dev/random";
	my $rnd = '';
	read($fh, $rnd, 50) || die "Error reading from /dev/random ($!)";

	my $md = new Crypt::SHA;
	$md->add($rnd);
	$self->seed($md->digest());
	$self->updateSeedFile();
}

sub goodSeed
{
	my $self = shift;

	my $md = new Crypt::SHA;
	$md->add(generateFastSeed());

	my $i;
	for ($i=0; $i < 10; $i++)
	{
		my $val = Math::TrulyRandom::rand();
		$md->add($val);
		$md->add(time());
	}

	$md->add(runCmd("ls -latr /"));
	$md->add(time());
	$md->add(runCmd("ps -auxw"));
	$md->add(time());
	$md->add(runCmd("netstat -n"));
	$md->add(time());

	$self->seed($md->digest());
	$self->updateSeedFile();
}

sub readSeedFile
{
	my $file = $ENV{'HOME'} . "/.random";
	my $s = '';

	if (open(RANDOM_FH, "< $file"))
	{
		read(RANDOM_FH, $s, 20);
		close(RANDOM_FH);
	}
	$s;
}

sub updateSeedFile
{
	my $self = shift;

	my $file = $ENV{'HOME'} . "/.random";

	open(RANDOM_FH, "> $file") || croak("Cannot create .random");
	print RANDOM_FH $self->read(20);
	close(RANDOM_FH);
}

1;
