#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Release_0_09 $
#

package PGP::KeyGen;

use strict;

use Crypt::RSAKeyGen;
use Crypt::RSASecretKeyPair;
use PGP::SecretKeyCertificate;
use PGP::UserId;


my $sk = Crypt::RSAKeyGen::generateKeys($ris, 384, undef);
ref($sk) || die $sk;

my $passphrase = $ui->getNewPassphrase();
my $skc = new PGP::SecretKeyCertificate $sk, $passphrase, $ris;


my $fos = new Stream::FileOutput("secring.pgp");
my $dos = new Stream::DataOutput($fos);

my $ret = PGP::PacketFactory::save($dos, $skc);
defined $ret && die $ret;

my $id = new PGP::UserId 'Gary Howland <gary@systemics.com>';

$ret = PGP::PacketFactory::save($dos, $id);
defined $ret && die $ret;
