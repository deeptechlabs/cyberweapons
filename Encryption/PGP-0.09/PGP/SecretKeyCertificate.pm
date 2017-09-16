#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::SecretKeyCertificate;

#
#	Cipher_init should be an object
#

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;
use POSIX;
use Carp;

use Math::MPI;
use PGP::SecretKey;
use PGP::KeyCertificate;


#
#	This is a hack!
#	We need a block cipher factory,
#	not hard coded IDEA
#
use Crypt::IDEA;
use Crypt::MD5;
use PGP::CFB;

use overload
	'""' => \&asString;


#
#	TODO
#
#	Make a key factory so that this code
#	doesn't have to deal with algorithm bytes
#


sub cert { shift->{'cert'}; }
sub secretKey { shift->{'sk'}; }
sub encrypted { shift->{'cc_alg'}; }

sub fingerprint { shift->publicKey()->fingerprint(); }
sub size { shift->{'sk'}->size(); }
# sub id { shift->{'sk'}->id(); }
sub id { substr(shift->{'n'}->save(), -8, 8); }	# Hack!

sub publicKey
{
	my $self = shift;
	new PGP::PublicKey $self->{'n'}, $self->{'e'};
}

sub publicKeyCertificate
{
	my $self = shift;
	new PGP::PublicKeyCertificate -key => $self->publicKey(),
				-version => $self->cert()->version(),
				-timestamp => $self->cert()->timestamp(),
				-validity => $self->cert()->validity(),
				-alg => $self->cert()->alg();
}

sub new
{
	my $type = shift; my $self = {}; bless $self, $type;
	my %args = @_;

	my $sk = $args{-sk};
	ref $sk || return "-sk argument missing";

	my $passphrase = $args{-passphrase};

	my $ris = $args{-ris};
	ref $ris || return "-ris argument missing";

	my $cert = new PGP::KeyCertificate %args;
	ref $cert || return $cert;

	$self->{'cert'} = $cert;
	$self->{'sk'} = $sk;
	$self->{'n'} = $sk->n();
	$self->{'e'} = $sk->e();


	#
	#	Need to store the encrypted part as hdr/body
	#

	$self->{'dh'} = pack("n", $sk->d()->bits());
	$self->{'ph'} = pack("n", $sk->p()->bits());
	$self->{'qh'} = pack("n", $sk->q()->bits());
	$self->{'uh'} = pack("n", $sk->u()->bits());

	$self->{'db'} = $sk->d()->save();
	$self->{'pb'} = $sk->p()->save();
	$self->{'qb'} = $sk->q()->save();
	$self->{'ub'} = $sk->u()->save();

	$self->{'csum'} = $self->csum();

	if (!defined($passphrase))
	{
		$self->{'cc_alg'} = 0;
		$self->{'cipher_init'} = "\0" x 8;
	}
	else
	{
		ref($ris) || return "random-input-stream undefined";
		$self->encrypt($passphrase, $ris)
	}

	$self;
}

sub generate
{
	my $class = shift;
	my %args = @_;

	ref $args{'-ris'} || return "-ris argument missing";
	defined $args{'-size'} || return "-size argument missing";

	my $sk = generate PGP::SecretKey %args;
	ref $sk || return $sk;

	$class->new(-sk => $sk, %args);
}

sub readCryptedMPI
{
	my $dis = shift;

	my $hdr = $dis->read(2);
	return unless (defined($hdr) && length($hdr) == 2);
	my $len = unpack("n", $hdr);
	my $body = $dis->read(int(($len-1)/8)+1);
	return unless (defined($body));
	($hdr, $body);
}

sub csum
{
	my $self = shift;

	my $sum = 0;
	$sum += unpack("%16C*", $self->{'dh'});
	$sum += unpack("%16C*", $self->{'db'});
	$sum += unpack("%16C*", $self->{'ph'});
	$sum += unpack("%16C*", $self->{'pb'});
	$sum += unpack("%16C*", $self->{'qh'});
	$sum += unpack("%16C*", $self->{'qb'});
	$sum += unpack("%16C*", $self->{'uh'});
	$sum += unpack("%16C*", $self->{'ub'});
	($sum & 0xFFFF);
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;


	my $cert = restoreFromDataStream PGP::KeyCertificate $dis;
	ref $cert || return $cert;


	my $n = restoreFromDataStream Math::MPI $dis;
	my $e = restoreFromDataStream Math::MPI $dis;

	$self->{'cc_alg'} = $dis->readByte();

	$self->{'cipher_init'} = $dis->read(8);

	($self->{'dh'}, $self->{'db'}) = readCryptedMPI($dis);
	($self->{'ph'}, $self->{'pb'}) = readCryptedMPI($dis);
	($self->{'qh'}, $self->{'qb'}) = readCryptedMPI($dis);
	($self->{'uh'}, $self->{'ub'}) = readCryptedMPI($dis);

	# Just in case they were not read in correctly ...
	return "problems reading D" unless (defined $self->{'db'});
	return "problems reading P" unless (defined $self->{'pb'});
	return "problems reading Q" unless (defined $self->{'qb'});
	return "problems reading U" unless (defined $self->{'ub'});

	$self->{'csum'} = $dis->readInt16();

	$self->{'n'} = $n->asBigInteger();
	$self->{'e'} = $e->asBigInteger();

	#
	#	If unencrypted
	#
	if ($self->{'cc_alg'} == 0)
	{
		my $d = restore Math::BigInteger $self->{'db'};
		my $p = restore Math::BigInteger $self->{'dp'};
		my $q = restore Math::BigInteger $self->{'dq'};
		my $u = restore Math::BigInteger $self->{'du'};

		my $sk = new PGP::SecretKey $self->{'n'}, $self->{'e'}, $d, $p, $q, $u;
		ref $sk || return $sk;
		$self->{'sk'} = $sk;
	}

	$self->{'cert'} = $cert;
	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;

	my $mpi_n = new Math::MPI $self->{'n'};
	my $mpi_e = new Math::MPI $self->{'e'};

	$self->cert()->saveToDataStream($dos);
	$mpi_n->saveToDataStream($dos);
	$mpi_e->saveToDataStream($dos);
	$dos->writeByte($self->{'cc_alg'});
	$dos->write($self->{'cipher_init'});
	$dos->write($self->{'dh'});
	$dos->write($self->{'db'});
	$dos->write($self->{'ph'});
	$dos->write($self->{'pb'});
	$dos->write($self->{'qh'});
	$dos->write($self->{'qb'});
	$dos->write($self->{'uh'});
	$dos->write($self->{'ub'});
	$dos->writeInt16($self->{'csum'});
}


sub encrypt
{
	my $self = shift;
	my $passphrase = shift;
	my $ris = shift;

	defined $ris || return "random-input undefined";
	defined $self->{'sk'} || return "Strange - sk not defined";

	my $key = Crypt::MD5->hash($passphrase);
	my $block_cipher = new Crypt::IDEA $key->data();
	my $cipher = new PGP::CFB $block_cipher;
	$self->{'cipher_init'} = $cipher->encrypt($ris->read(8));

	$self->{'cc_alg'} = 1;
	$self->{'db'} = $cipher->encrypt($self->{'db'});
	$self->{'pb'} = $cipher->encrypt($self->{'pb'});
	$self->{'qb'} = $cipher->encrypt($self->{'qb'});
	$self->{'ub'} = $cipher->encrypt($self->{'ub'});

# Note - PGP documentation is wrong
#	$self->{'csum'} = unpack("n", $cipher->encrypt(pack("n", $self->{'csum'})));
}

sub decrypt
{
	my $self = shift;
	my $passphrase = shift;


	my $key = Crypt::MD5->hash($passphrase);
	my $block_cipher = new Crypt::IDEA $key->data();
	my $cipher = new PGP::CFB $block_cipher;

	my $r = $cipher->decrypt($self->{'cipher_init'});

	my $db = $self->{'db'};
	my $pb = $self->{'pb'};
	my $qb = $self->{'qb'};
	my $ub = $self->{'ub'};

	$self->{'db'} = $cipher->decrypt($db);
	$self->{'pb'} = $cipher->decrypt($pb);
	$self->{'qb'} = $cipher->decrypt($qb);
	$self->{'ub'} = $cipher->decrypt($ub);

# Note - PGP documentation is wrong
#	$self->{'csum'} = unpack("n", $cipher->decrypt(pack("n", $self->{'csum'})));

	unless ($self->{'csum'} == $self->csum())
	{
		# Restore the values
		$self->{'db'} = $db;
		$self->{'pb'} = $pb;
		$self->{'qb'} = $qb;
		$self->{'ub'} = $ub;

		return "Bad checksum";
	}

	my $d = restore Math::BigInteger $self->{'db'};
	my $p = restore Math::BigInteger $self->{'pb'};
	my $q = restore Math::BigInteger $self->{'qb'};
	my $u = restore Math::BigInteger $self->{'ub'};

	my $sk = new PGP::SecretKey $self->{'n'}, $self->{'e'}, $d, $p, $q, $u;
	unless (ref $sk)
	{
		# Restore the values
		$self->{'db'} = $db;
		$self->{'pb'} = $pb;
		$self->{'qb'} = $qb;
		$self->{'ub'} = $ub;

		return $sk;
	}

	$self->{'cc_alg'} = 0;	# Decrypted
	$self->{'sk'} = $sk;
	$sk;
}


sub asString
{
	my $self = shift;

	my $retval = $self->cert()->asString();
	$retval .= "Conventional alg: \t" . $self->{'cc_alg'} . "\n";

	if (ref($self->{'sk'}))
	{
		$retval .= "Secret key:\n";
		$retval .= $self->{'sk'}->asString();
	}
	else
	{
		$retval .= "Secret key is encrypted\n";
	}
	$retval;
}

1;
