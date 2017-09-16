#
# Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.
#
# $Revision: 1.2 $
# $State: Exp $
# 
# This library and applications are FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
# as long as the following conditions are adheared to.
# 
# Copyright remains Systemics Ltd, and as such any Copyright notices in
# the code are not to be removed.  If this code is used in a product,
# Systemics should be given attribution as the author of the parts used.
# This can be in the form of a textual message at program startup or
# in documentation (online or textual) provided with the package.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#    This product includes software developed by Systemics Ltd (http://www.systemics.com/)   
# 
#    THIS SOFTWARE IS PROVIDED BY SYSTEMICS LTD ``AS IS'' AND
#    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#    ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#    SUCH DAMAGE.
# 
#    The licence and distribution terms for any publically available version or
#    derivative of this code cannot be changed.  i.e. this code cannot simply be
#    copied and put under another distribution licence
#    [including the GNU Public Licence.]
#

package Math::BigInteger;

use Exporter;
use DynaLoader;
@ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default
@EXPORT = qw();

# Other items we are prepared to export if requested
@EXPORT_OK = qw();

my $VERSION = "1.03";                       # see Math-*/Makefile.PL
bootstrap Math::BigInteger $VERSION;



use strict;
use integer;
use Carp;


sub usage
{
	my ($package, $filename, $line, $subr) = caller(1);
	$Carp::CarpLevel = 2;
	croak "Usage: $subr(@_)";
}



use overload
	'=' => \&clone_sub,
	'+' => \&add_sub,
	'-' => \&sub_sub,
	'*' => \&mul_sub,
#	'%' => sub { my $r = new Math::BigInteger; $r->mod($_[0], $_[1]); $r; },
#	'%' => \&mod_sub,
# 	'/' => "div_sub",
	'cmp' => sub {$_[2]? ($_[1] cmp ${$_[0]}) : (${$_[0]} cmp $_[1])},
	'<=>' => sub {$_[2]? ($_[1] cmp ${$_[0]}) : (${$_[0]} cmp $_[1])},
	'""' => "asString",
	'bool' => \&bool,
	'0+' => \&saveAsInt,
	'++' => "inc_sub",
	'--' => "dec_sub";


sub clone_sub { shift->clone(); }
sub add_sub { my $r = new Math::BigInteger; $r->add(shift, shift); $r; }
sub sub_sub { my $r = new Math::BigInteger; $r->sub(shift, shift); $r; }
sub mul_sub { my $r = new Math::BigInteger; $r->mul(shift, shift); $r; }
sub mod_sub { my $r = new Math::BigInteger; $r->mod(shift, shift); $r; }
# sub div_sub { my $r = shift; $r->sub($r, undef, shift); $r; }
# sub cmp_sub { Math::BigInteger::cmp(shift, shift); }
# sub cmp_sub { shift->cmp(shift); }
sub inc_sub { shift->inc(); }
sub dec_sub { shift->dec(); }
sub bool { shift->save() ne ""; }	# Probably a faster method somewhere



sub saveAsInt
{
#	usage("") unless @_ == 1;

	my $d = shift->save();
	return 0 if ($d eq "");
	hex unpack("H*", $d);
}


sub asString
{
#	usage("") unless @_ == 1;

	my $d = shift->save();
	return "00" unless (defined $d && $d ne "");
	unpack("H*", $d);
}


#
#	Return the number of bits in the number
#
sub bits { shift->num_bits(); }

1;
