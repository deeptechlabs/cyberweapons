BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#

package Crypt::IDEA;

require Exporter;
require DynaLoader;

@ISA = (Exporter, DynaLoader);


bootstrap Crypt::IDEA;


use strict;
use Carp;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}


sub blocksize { 8; }
sub keysize { 16; }

sub new
{
	usage("new IDEA key") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'ks'} = Crypt::IDEA::expand_key(shift);

	$self;
}

sub encrypt
{
	usage("encrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::IDEA::crypt($data, $data, $self->{'ks'});

	$data;
}

sub decrypt
{
	usage("decrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	#
	# Cache Decrypt key schedule
	#
	$self->{'dks'} = Crypt::IDEA::invert_key($self->{'ks'})
										unless exists $self->{'dks'};

	Crypt::IDEA::crypt($data, $data, $self->{'dks'});

	$data;
}

package main;


# 00010002000300040005000600070008  0000000100020003  11FBED2B01986DE5
# 00010002000300040005000600070008  0102030405060708  540E5FEA18C2F8B1
# 00010002000300040005000600070008  0019324B647D96AF  9F0A0AB6E10CED78
# 00010002000300040005000600070008  F5202D5B9C671B08  CF18FD7355E2C5C5
# 00010002000300040005000600070008  FAE6D2BEAA96826E  85DF52005608193D
# 00010002000300040005000600070008  0A141E28323C4650  2F7DE750212FB734
# 00010002000300040005000600070008  050A0F14191E2328  7B7314925DE59C09
# 0005000A000F00140019001E00230028  0102030405060708  3EC04780BEFF6E20
# 3A984E2000195DB32EE501C8C47CEA60  0102030405060708  97BCD8200780DA86
# 006400C8012C019001F4025802BC0320  05320A6414C819FA  65BE87E7A2538AED
# 9D4075C103BC322AFB03E7BE6AB30006  0808080808080808  F5DB1AC45E5EF9F9


my $key = pack("H*", "00010002000300040005000600070008");
my $in = pack("H*", "0000000100020003");
my $out = pack("H*", "11FBED2B01986DE5");

my $cipher = new Crypt::IDEA $key;


#
#	Adding the above tests into this program is
#	left as an exercise for the reader
#

print "1..2\n";

print "not " unless ($cipher->encrypt($in) eq $out);
print "ok 1\n";

print "not " unless ($cipher->decrypt($out) eq $in);
print "ok 2\n";

