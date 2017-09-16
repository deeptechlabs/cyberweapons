BEGIN { push @INC, qw(. .. ../lib ../../lib ../../../lib) }

use strict;
use PGP::Armoury;
use PGP::PacketFactory;


print "1..2\n";


print "1 ";

my $pk_asc = '
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQBNAjHjxcoAAAECAP///Put+your+vanity+message+here//yEtOygXSPmHs5
2UkPtYTew5xY30ZprW2tyRKc7d2sqdS/iJpH74UAAwe0A2pvZQ==
=+47k
-----END PGP PUBLIC KEY BLOCK-----
';

my ($err, $pk_pkt);
($pk_pkt, $err) = PGP::Armoury::readPacketFromString($pk_asc);
defined($err) && print "not ";

print "ok\n";

print "2 ";
my $pk = PGP::PacketFactory::restoreFromString($pk_pkt);
(ref($pk) eq "PGP::PublicKeyCertificate") || print "not ";
print "ok\n";


#
#	The rest of the tests (hundreds, probably)
#	are left as an excercise to the reader
#
