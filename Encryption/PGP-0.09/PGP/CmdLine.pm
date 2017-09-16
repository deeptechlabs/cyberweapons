#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::CmdLine;

use strict;


sub new
{
	my $type = shift; my $self = {}; bless $self, $type;

	STDOUT->autoflush(1);

	$self;
}

sub getPassphrase
{
	print STDERR shift, ": ";
	system("stty -echo");
	my $passphrase = <STDIN>;
	if (defined $passphrase)
	{
		chop($passphrase);
	}
	else
	{
		$passphrase = "";
	}
	print STDERR "\n";
	system("stty echo");
	$passphrase;
}

sub getNewPassphrase
{
	for (;;)
	{
		my $pass1 = getPassphrase("Please enter your passphrase");
		my $pass2 = getPassphrase("Please re-enter your passphrase");
		return $pass1 if ($pass1 eq $pass2);
		print STDERR "Passphrases do not match - please retry.\n";
	}
}

1;
