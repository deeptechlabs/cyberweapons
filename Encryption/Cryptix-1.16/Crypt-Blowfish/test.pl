BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

package Crypt::Blowfish;

require Exporter;
require DynaLoader;

@ISA = (Exporter, DynaLoader);

bootstrap Crypt::Blowfish;



use strict;
use Carp;

sub usage
{
    my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)"; 
}


sub blocksize { 8; }
sub keysize { 0; }

sub new
{
	usage("new Blowfish key") unless @_ == 2;

	my $type = shift; my $self = {}; bless $self, $type;

	$self->{'ks'} = Crypt::Blowfish::init(shift);

	$self;
}

sub encrypt
{
	usage("encrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::Blowfish::crypt($data, $data, $self->{'ks'}, 0);

	$data;
}

sub decrypt
{
	usage("decrypt data[8 bytes]") unless @_ == 2;

	my $self = shift;
	my $data = shift;

	Crypt::Blowfish::crypt($data, $data, $self->{'ks'}, 1);

	$data;
}


package main;


#
# '6162636465666768696a6b6c6d6e6f707172737475767778797a',
#			'424c4f5746495348', '324ed0fef413a203',
#
# '57686f206973204a6f686e2047616c743f', 'fedcba9876543210', 'cc91732b8022f684')
#
# "Ayn Rand" FEDCBA9876543210 e113f4102cfcce43
#

print "1..3\n";

# dropped all duplicate 'my' variables, later Perls warn against this
my $key;
my $in;
my $out;
my $cipher;

$key = pack("H*", "6162636465666768696a6b6c6d6e6f707172737475767778797a");
$in = pack("H*", "424c4f5746495348");
$out = pack("H*", "324ed0fef413a203");

$cipher = new Crypt::Blowfish $key;

print "not " unless ($cipher->encrypt($in) eq $out);
print "ok 1\n";

$key = pack("H*", "57686f206973204a6f686e2047616c743f");
$in = pack("H*", "fedcba9876543210");
$out = pack("H*", "cc91732b8022f684");

$cipher = new Crypt::Blowfish $key;

print "not " unless ($cipher->decrypt($out) eq $in);
print "ok 2\n";

$key = "Ayn Rand";
substr($key, 3, 1) = pack("C", ord(substr($key, 3, 1))+128);
substr($key, 7, 1) = pack("C", ord(substr($key, 7, 1))+128);
$in = pack("H*", "fedcba9876543210");
$out = pack("H*", "e113f4102cfcce43");

$cipher = new Crypt::Blowfish $key;

print "not " unless ($cipher->encrypt($in) eq $out);
print "ok 3\n";
