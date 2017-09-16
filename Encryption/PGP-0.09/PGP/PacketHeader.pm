#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::PacketHeader;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;


sub type { shift->{'type'} }
sub len { shift->{'len'} }
sub lensize { shift->{'lensize'} }

sub new
{
	usage("type length [length-size]") unless (@_ == 3 || @_ == 4);

	my $class = shift; my $self = {}; bless $self, $class;

	my $type = shift;
	my $len = shift;
	my $lensize = shift;	# Required size of length field

	$self->{'type'} = $type;
	$self->{'len'} = $len;
	$self->{'lensize'} = $lensize;
	$self;
}

sub restoreFromDataStream
{
	usage("input-stream") unless @_ == 2;

	my $type = shift;
	my $dis = shift;

	return "dis undefined" if (!defined($dis));

	my $ctb = $dis->readByte();
	return unless defined $ctb;

	my $ctb_type = ($ctb & 0x3C) >> 2;
	my $t = $ctb & 0x03;
	my $ctb_len = 0;
	if ($t == 0)
		{ $ctb_len = $dis->readByte(); }
	elsif ($t == 1)
		{ $ctb_len = $dis->readInt16(); }
	elsif ($t == 2)
		{ $ctb_len = $dis->readInt32(); }
	elsif ($t == 3)
		{ $ctb_len = undef; }
	else
		{ return "Bad value for CTB ($t)"; }

	$type->new($ctb_type, $ctb_len);
}

sub saveToDataStream
{
	usage("output-stream") unless @_ == 2;

	my $self = shift;
	my $dos = shift;

	my $ctb_len = $self->len();
	my $ctb_type = $self->type();
	my $lensize = $self->lensize();

	#
	#	PGP is brain dead in this area.
	#	The problem is that packets such as UserID packets
	#	must have only a one byte header, and others
	#	such as PublicKeyCertificate must have a two byte
	#	header.
	#	This is why a length size parameter can be used
	#

#
#	This needs re-writing
#	What should be done is:
#		If lensize == 1, then an error if ctb_len >= 256
#		If lensize == 2, then an int16 or int32 should be written out
#
#	Gary.Howland@systemics.com
#

	unless ($lensize)
	{
		if (!defined($ctb_len))
		{
			$lensize = 0;
		}
		elsif ($ctb_len < 256)
		{
			$lensize = 1;
		}
		elsif ($ctb_len < 65536)
		{
			$lensize = 2;
		}
		else
		{
			$lensize = 4;
		}
	}

	if ($lensize == 1 && $ctb_len > 255) { die "packet overflow\n"; }
	if ($lensize == 2 && $ctb_len > 65535) { $lensize = 3; }

	if ($lensize == 0)
	{
		$dos->writeByte(128 + ($ctb_type << 2) + 3);
	}
	elsif ($lensize == 1)
	{
		$dos->writeByte(128 + ($ctb_type << 2));
		$dos->writeByte($ctb_len);
	}
	elsif ($lensize == 2)
	{
		$dos->writeByte(128 + ($ctb_type << 2) + 1);
		$dos->writeInt16($ctb_len);
	}
	else
	{
		$dos->writeByte(128 + ($ctb_type << 2) + 2);
		$dos->writeInt32($ctb_len);
	}
}


sub display
{
	my $self = shift;

	print "Packet Header:\n";
	print " Type = ", $self->type(), "\n";
	if (defined $self->len())
	{
		print " Length = ", $self->len(), "\n";
	}
	else
	{
		print " Length undefined\n";
	}
}

1;
