
#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
#

package Stream::Streamable;

@Streamable::ISA = qw(Stream::Streamable);

use strict;
use Carp;

use Stream::DataInput;
use Stream::DataOutput;
use Stream::StringInput;
use Stream::StringOutput;
use Stream::FileInput;
use Stream::FileOutput;


sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}

sub save
{
	usage unless @_ == 1;

	my $sos = new Stream::StringOutput;
	shift->saveToDataStream(new Stream::DataOutput $sos);
	$sos->data();
}

sub restore
{
	usage("data") unless @_ == 2;

    my $type = shift;
	my $sis_data = shift;

	(defined $sis_data) || return "Cannot restore from undefined data!";

	my $sis = new Stream::StringInput $sis_data;
	my $dis = new Stream::DataInput $sis;

	my $self = restoreFromDataStream $type $dis;
	return $self unless (ref($self) eq $type);

	unless ($dis->eoi())
	{
		return "Incorrect length input (".length($dis->readAll())." bytes too many)";
	}

	$self;
}

#
#	Restore an object from a file
#
sub restoreFromFile
{
	usage("filename") unless @_ == 2;

	my $type = shift;
	my $filename = shift;

	my $fis = new Stream::FileInput $filename;
	return $fis unless ref $fis;
	my $dis = new Stream::DataInput $fis;

	restoreFromDataStream $type $dis;
}

#
#	Save an object to a file
#
sub saveToFile
{
	usage("filename") unless @_ == 2;

	my $self = shift;
	my $filename = shift;

	my $fos = new Stream::FileOutput $filename;
	my $dos = new Stream::DataOutput $fos;

	$self->saveToDataStream($dos);
}

1;
