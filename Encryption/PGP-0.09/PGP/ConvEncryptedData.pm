#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::ConvEncryptedData;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

#
#	This is a hack!
#	We need a block cipher factory,
#	not hard coded IDEA
#
use Crypt::IDEA;
use PGP::CFB;


sub new
{   
	my $type = shift; my $self = {}; bless $self, $type;
	my $key = shift;
	my $msg = shift;
	my $ris = shift;

	ref($ris) || return "random-input-stream parameter missing";

	my $block_cipher = new Crypt::IDEA $key;
	my $cipher = new PGP::CFB $block_cipher;
	my $pre = $ris->read(8);
	$pre .= substr($pre, -2, 2);
	$self->{'ciphertext'} = $cipher->encrypt($pre);

	$cipher->decrypt(substr($self->{'ciphertext'}, 2, 8));	# Set the iv

	$self->{'ciphertext'} .= $cipher->encrypt($msg);

	$self;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	$self->{'ciphertext'} = $dis->readAll();

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;
	   
	$dos->write($self->{'ciphertext'});
}

sub asString
{
	my $self = shift;

	"Data: \t" . unpack("H*", $self->{'ciphertext'});
}

sub decrypt
{
	my $self = shift;
	my $key = shift;

	my $block_cipher = new Crypt::IDEA $key;
	my $cipher = new PGP::CFB $block_cipher;

	my $plaintext = $cipher->decrypt(substr($self->{'ciphertext'}, 0, 10));
	my $pre = substr($plaintext, 6, 2);
	my $check = substr($plaintext, 8, 2);

#	$cipher->decrypt(substr($self->{'ciphertext'}, 2, 8));	# Set the iv, since PGP sucks

	$plaintext = $cipher->decrypt(substr($self->{'ciphertext'}, 10));
	return unless ($pre eq $check);

	$plaintext;
}

1;
