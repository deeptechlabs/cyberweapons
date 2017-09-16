#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::Signature;

use Stream::Streamable;
@ISA = qw( Stream::Streamable );

use strict;

use Crypt::MD5;
use PGP::DEK;
use PGP::HashFactory;

use overload
	'""' => \&asString;


sub version { 2; }
sub keyID { shift->{'keyid'}; }
sub classification { shift->{'classification'}; }
sub isRevocation { (shift->{'classification'} == 32); }


sub new
{
	my $type = shift; my $self = {}; bless $self, $type;

	my $sk = shift;
	my $msg = shift;
	my $classification = shift;
	my $validity = shift;
	my $ris = shift;

	ref($ris) || return "random-input-stream argument missing";


	$classification = 0 unless (defined($classification));
	$validity = 0 unless (defined($validity));

	$self->{'version'} = $self->version();
	$self->{'keyid'} = $sk->id();

	$self->{'classification'} = $classification;
	$self->{'timestamp'} = time();
	$self->{'validity'} = $validity;
	$self->{'keyid'} = $sk->id();
	$self->{'pk_alg'} = 1;

	my $sos = new Stream::StringOutput;
	my $dos = new Stream::DataOutput $sos;
	$dos->writeByte($self->{'classification'});
	$dos->writeTime($self->{'timestamp'});

	($self->{'validity'} != 0) && $dos->writeByte($self->{'validity'});

	my $md = new Crypt::MD5;
	$md->add($msg);
	$md->add($sos->data());
	my $hash = $md->digestAsHash();

	$self->{'md_chk'} = substr($hash->save(), 0, 2);

	my $bi = encode(PGP::HashFactory::saveAsString($hash), $sk->size(), $ris);
	$self->{'c'} = $sk->privateEncrypt($bi);

	$self;
}

sub restoreFromDataStream
{
	my $type = shift; my $self = {}; bless $self, $type;
	my $dis = shift;

	my $version = $dis->readByte();
	($version >= 1 && $version <= 3) || return "Unsupported version";

	my $length = $dis->readByte();
	croak("Invalid length field") if ($length != 5 && $length != 7);

	$self->{'classification'} = $dis->readByte();
	$self->{'timestamp'} = $dis->readTime();
	$self->{'validity'} = $dis->readInt16() if ($length == 7);
	$self->{'keyid'} = $dis->read(8);
	$self->{'pk_alg'} = $dis->readByte();
	$self->{'md_alg'} = $dis->readByte();
	$self->{'md_chk'} = $dis->read(2);
	my $mpi = restoreFromDataStream Math::MPI $dis;

	$self->{'c'} = $mpi->asBigInteger();

	$self;
}

sub saveToDataStream
{
	my $self = shift;
	my $dos = shift;
	   
	$dos->writeByte($self->version());

	(defined $self->{'validity'} && $self->{'validity'}) ? $dos->writeByte(7) : $dos->writeByte(5);

	$dos->writeByte($self->{'classification'});
	$dos->writeTime($self->{'timestamp'});
	(defined $self->{'validity'} && $self->{'validity'}) && $dos->writeInt16($self->{'validity'});

	$dos->write($self->{'keyid'});
	$dos->writeByte($self->{'pk_alg'});
	$dos->writeByte($self->{'md_alg'});
	$dos->write($self->{'md_chk'});

	my $mpi = new Math::MPI $self->{'c'};
	$mpi->saveToDataStream($dos);
}

sub verify
{
	my $self = shift;
	my $pk = shift;
	my $msg = shift;

	my $p = $pk->encrypt($self->{'c'});
	ref($p) || return "Decryption failed";

	my $plain = $p->save();

	my $p_hdr = substr($plain, 0, 8);
	($p_hdr eq pack("H*", "01ffffffffffffff"))
			|| return "Bad start of message digest packet (" . pack("H*", $p_hdr) . ")";


	my $smd = substr($plain, -16, 16);
	(substr($smd, 0, 2) eq $self->{'md_chk'})
				|| return "Message digest does not match checksum (wrong key?) ("
													. pack("H*", $plain) . ")";


	my $md = new Crypt::MD5;
	$md->add($msg);

	my $sos = new Stream::StringOutput;
	my $dos = new Stream::DataOutput $sos;

	$dos->writeByte($self->{'classification'});
	$dos->writeTime($self->{'timestamp'});
	$dos->writeInt16($self->{'validity'}) if (defined($self->{'validity'}));

	$md->add($sos->data());
	my $cmd = $md->digest();

#	print "Signed MD: \t", unpack("H*", $smd), "\n";
#	print "Calculated MD: \t", unpack("H*", $cmd), "\n";

	($smd eq $cmd);
}

sub asString
{
	my $self = shift;

	my $classification = $self->{'classification'};
	my $timestamp = $self->{'timestamp'};
	my $validity = $self->{'validity'};
	my $pk_alg = $self->{'pk_alg'};
	my $md_alg = $self->{'md_alg'};
	my $md_chk = $self->{'md_chk'};
	my $c = $self->{'c'};

	my $retval = "Signature classification:\t$classification\n";
	$retval .= "Timestamp:\t" . POSIX::ctime($timestamp) . "\n";
	$retval .= "Validity (days):\t$validity\n" if (defined $validity);
	$retval .= "Public key alg:\t$pk_alg\n";
	$retval .= "Message digest alg:\t$md_alg\n";
	$retval .= "Message digest check digits:\t" . unpack("H*", $md_chk) . "\n";
	$retval .= "ciphertext:\t$c\n";
	$retval;
}

1;
