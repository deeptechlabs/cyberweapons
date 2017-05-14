package ow::datetime;
use strict;
#
# datetime.pl - date/time routines supporting timezone and daylightsaving
#
# This module uses gmtime(), timegm() to convert time between date array and seconds 
# It uses time_gm2local(), time_local2gm() with parameter $timeoffset, $daylightsaving
# to convert time between gm seconds and local seconds, 
# so it can handle multiple timezones other than where the server is.
#

use Time::Local;
use vars qw(%months @month_en @wday_en %tzoffset);

%months = qw(Jan 1 Feb 2 Mar 3 Apr 4  May 5  Jun 6
             Jul 7 Aug 8 Sep 9 Oct 10 Nov 11 Dec 12);
@month_en = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
@wday_en =  qw(Sun Mon Tue Wed Thu Fri Sat);

%tzoffset = qw(
    ACDT +1030  ACST +0930  ADT  -0300  AEDT +1100  AEST +1000  AHDT -0900
    AHST -1000  AST  -0400  AT   -0200  AWDT +0900  AWST +0800  AZST +0400
    BAT  +0300  BDST +0200  BET  -1100  BST  -0300  BT   +0300  BZT2 -0300
    CADT +1030  CAST +0930  CAT  -1000  CCT  +0800  CDT  -0500  CED  +0200
    CEST +0200  CET  +0100  CST  -0600
    EAST +1000  EDT  -0400  EED  +0300  EET  +0200  EEST +0300  EST  -0500
    FST  +0200  FWT  +0100
    GMT  +0000  GST  +1000
    HDT  -0900  HST  -1000
    IDLE +1200  IDLW -1200  IST  +0530  IT   +0330
    JST  +0900  JT   +0700
    MDT  -0600  MED  +0200  MET  +0100  MEST +0200  MEWT +0100  MST  -0700
    MT   +0800
    NDT  -0230  NFT  -0330  NT   -1100  NST  +0630  NZ   +1100  NZST +1200
    NZDT +1300  NZT  +1200
    PDT  -0700  PST  -0800
    ROK  +0900
    SAD  +1000  SAST +0900  SAT  +0900  SDT  +1000  SST  +0200  SWT  +0100
    USZ3 +0400  USZ4 +0500  USZ5 +0600  USZ6 +0700  UT   +0000  UTC  +0000
    UZ10 +1100
    WAT  -0100  WET  +0000  WST  +0800
    YDT  -0800  YST  -0900
    ZP4  +0400  ZP5  +0500  ZP6  +0600);

########## GETTIMEOFFSET #########################################
# notice! th difference between localtime and gmtime includes the dst shift
# so we remove the dstshift before return timeoffset
# since whether dst shift should be used depends on the date to be converted
sub gettimeoffset {
   my $t=time();		# the UTC sec from 1970/01/01
   my @l=localtime($t);
   my $sec=timegm(@l[0..5])-$t;	# diff between local and UTC

   $sec-=3600 if ($l[8]);	# is dst? (returned by localtime)
   return sprintf(seconds2timeoffset($sec));
}
########## END GETTIMEOFFSET #####################################

########## TIMEOFFSET2SECONDS ####################################
sub timeoffset2seconds {
   my $seconds=0;
   if ($_[0]=~/^[+\-]?(\d\d)(\d\d)$/) {	# $_[0] is timeoffset
      $seconds=($1*60+$2)*60;
      $seconds*=-1 if ($_[0]=~/^\-/);
   }
   return($seconds);
}

sub seconds2timeoffset {
   my $seconds=abs($_[0]);
   return(sprintf( "%s%02d%02d",
	($_[0]>=0)?'+':'-', int($seconds/3600), int(($seconds%3600)/60) ));
}
########## END TIMEOFFSET2SECONDS ################################

########## SECONDS <-> DATEARRAY #################################
sub seconds2array {
   return gmtime($_[0]);
}

sub array2seconds {
   my ($sec,$min,$hour, $d,$m,$y)=@_;
   # avoid unexpected error exception from timegm
   my @t=gmtime();
   $sec= $t[0] if ($sec<0||$sec>59);
   $min= $t[1] if ($min<0||$min>59);
   $hour=$t[2] if ($hour<0||$hour>23);
   $d   =$t[3] if ($d<1||$d>31);
   $m   =$t[4] if ($m<0||$m>11);
   $y   =$t[5] if ($y<70||$y>137);	# invalid if outside 1970...2037
   if ($d>28) {
      my @days_in_month = qw(0 31 28 31 30 31 30 31 31 30 31 30 31);
      my $year=1900+$y;
      $days_in_month[2]++ if ( $year%4==0 && ($year%100!=0||$year%400==0) );
      $d=$days_in_month[$m+1] if ($d>$days_in_month[$m+1]);
   }
   return timegm($sec,$min,$hour, $d,$m,$y);
}
########## END SECONDS <-> DATEARRAY #############################

########## IS_DST ################################################
# Check if gmtime should be DST for timezone $timeoffset.
# Since we use only 2 rules to calc daylight saving time for all timezones,
# it is not very accurate but should be enough in most cases
# reference: http://webexhibits.org/daylightsaving/g.html
sub is_dst {
   my ($gmtime, $timeoffset)=@_;
   my ($month,$year)=(seconds2array($gmtime))[4,5];	# $month 0..11
   my $seconds=timeoffset2seconds($timeoffset);

   my ($gm, $lt, $dow);
   if ($seconds >= -9*3600 && $seconds <= -3*3600 ) {	# dst rule for us
      return 1 if ($month>3 && $month<9);
      if ($month==3) {
         $lt=array2seconds(0,0,2, 1,3,$year);	# localtime Apr/1 2:00
         $dow=(seconds2array($lt))[6];		# weekday of localtime Apr/1 2:00:01
         $gm=$lt+(7-$dow)*86400-$seconds;	# gmtime of localtime Apr/1st Sunday
         return 1 if ($gmtime>=$gm);
      } elsif ($month==9) {
         $lt=array2seconds(0,0,2, 30,9,$year);	# localtime Oct/30 2:00
         $dow=(seconds2array($lt))[6];		# weekday of localtime Oct/30
         $gm=$lt-$dow*86400-$seconds;		# gmtime of localtime Oct/last Sunday
         return 1 if ($gmtime<=$gm);
      }
   } elsif ($seconds >= 0 && $seconds <= 6*3600 ) {	# dst rule for europe
      return 1 if ($month>2 && $month<9);
      if ($month==2) {
         $gm=array2seconds(0,0,1, 31,2,$year);	# gmtime Mar/31 1:00
         $dow=(seconds2array($gm))[6];		# weekday of gmtime Mar/31
         $gm-=$dow*86400;			# gmtime Mar/last Sunday
         return 1 if ($gmtime>=$gm);
      } elsif ($month==9) {
         $gm=array2seconds(0,0,1, 30,9,$year);	# gmtime Oct/30 1:00
         $dow=(seconds2array($gm))[6];		# weekday of gmtime Oct/30
         $gm-=$dow*86400;			# gmtime Oct/last Sunday
         return 1 if ($gmtime<=$gm);
      }
   }
   return 0;
}
########## END IS_DST ############################################

########## TIME GM <-> LOCAL #####################################
sub time_gm2local {
   my ($g2l, $timeoffset, $daylightsaving)=@_;
   if ($daylightsaving eq 'on' ||
       ($daylightsaving eq 'auto' && is_dst($g2l,$timeoffset)) ) {
      $g2l+=3600; # plus 1 hour if is_dst at this gmtime
   }
   $g2l+=timeoffset2seconds($timeoffset) if ($timeoffset);
   return $g2l;
}

sub time_local2gm {
   my ($l2g, $timeoffset, $daylightsaving)=@_;
   $l2g-=timeoffset2seconds($timeoffset);
   if ($daylightsaving eq 'on' ||
       ($daylightsaving eq 'auto' && is_dst($l2g,$timeoffset)) ) {
      $l2g-=3600; # minus 1 hour if is_dst at that gmtime
   }
   return $l2g;
}
########## END TIME GM <-> LOCAL #################################

########## GMTIME <-> DATESERIAL #################################
# dateserial is used as an equivalent internal format to gmtime
# the is_dst effect won't be not counted in dateserial until
# the dateserial is converted to datefield, delimeterfield or str
sub gmtime2dateserial {
   # time() is used if $_[0] undefined
   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=seconds2array($_[0]||time());
   return(sprintf("%4d%02d%02d%02d%02d%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec));
}

sub dateserial2gmtime {
   $_[0]=~/(\d\d\d\d)(\d\d)(\d\d)(\d\d)?(\d\d)?(\d\d)?/;
   my ($year, $mon, $mday, $hour, $min, $sec)=($1, $2, $3, $4, $5, $6);
   return array2seconds($sec,$min,$hour, $mday,$mon-1,$year-1900);
}
########## END GMTIME <-> DATESERIAL #############################

########## DELIMITER <-> DATESERIAL ##############################
sub delimiter2dateserial {	# return dateserial of GMT
   my ($delimiter, $deliver_use_GMT, $daylightsaving)=@_;

   # extract date from the 'From ' line, it must be in this form
   # From Tung@turtle.ee.ncku.edu.tw Fri Jun 22 14:15:33 2001
   # From Tung@turtle.ee.ncku.edu.tw Mon Aug 20 18:24 CST 2001
   # From Nssb@thumper.bellcore.com   Wed Mar 11 16:27:37 EST 1992
   return('') if ($delimiter !~ /(\w\w\w)\s+(\w\w\w)\s+(\d+)\s+(\d+):(\d+):?(\d*)\s+([A-Z]{3,4}\d?\s+)?(\d\d+)/);

   my ($wdaystr, $monstr, $mday, $hour, $min, $sec, $zone, $year)
					=($1, $2, $3, $4, $5, $6, $7, $8);
   if ($year<50) {	# 2 digit year
      $year+=2000;
   } elsif ($year<=1900) {
      $year+=1900;
   }
   my $mon=$months{$monstr};

   my $t=array2seconds($sec,$min,$hour, $mday,$mon-1,$year-1900);
   if (!$deliver_use_GMT) {
      # we don't trust the zone abbreviation in delimiter line because it is not unique.
      # see http://www.worldtimezone.com/wtz-names/timezonenames.html for detail
      # since delimiter is written by local deliver, so we use gettimeoffset() instead
      $t=time_local2gm($t, gettimeoffset(), $daylightsaving);
   }
   return(gmtime2dateserial($t));
}

sub dateserial2delimiter {
   my ($dateserial, $timeoffset, $daylightsaving)=@_;

   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=
      seconds2array(time_gm2local(dateserial2gmtime($dateserial), $timeoffset, $daylightsaving));

   # From Tung@turtle.ee.ncku.edu.tw Fri Jun 22 14:15:33 2001
   return(sprintf("%3s %3s %2d %02d:%02d:%02d %4d",
              $wday_en[$wday], $month_en[$mon],$mday, $hour,$min,$sec, $year+1900));
}
########## END DELIMITER <-> DATESERIAL ##########################

########## DATEFIELD <-> DATESERIAL ##############################
sub datefield2dateserial {	# return dateserial of GMT
   my $datefield=$_[0];
   my ($sec,$min,$hour, $mday,$mon,$year, $timeoffset,$timezone, $ampm);

   $datefield=~s/GMT//;
   foreach my $s (split(/[\s,]+/, $datefield)) {
      if ($s=~/^\d\d?$/) {
         if ($s<=31 && $mday eq "") {
            $mday=$s;
         } else {
            $year=$s+1900;
            $year+=100 if ($year<1970);
         }
      } elsif ($s=~/^[A-Z][a-z][a-z]/ ) {
         for my $i (0..11) {
            if ($s=~/^$month_en[$i]/i) {
               $mon=$i+1; last;
            }
         }
      } elsif ($s=~/^\d\d\d\d$/) {
         $year=$s;
      } elsif ($s=~/^(\d+):(\d+):?(\d+)?$/) {
         $hour=$1; $min=$2; $sec=$3;
      } elsif ($s=~/^\(?([A-Z]{3,4}\d?)\)?$/) {
         $timezone=$1;
      } elsif ($s=~/^([\+\-]\d\d:?\d\d)$/) {
         $timeoffset=$1;
         $timeoffset=~s/://;
      } elsif ($s=~/^pm$/i) {
         $ampm='pm';
      }
   }
   $hour+=12 if ($hour<12 && $ampm eq 'pm');
   $timeoffset=$tzoffset{$timezone} if ($timeoffset eq "");

   # NOTICE! The date field in msg header is generated by other machine
   #         Both datetime and the timezone str in date field include the dst shift,
   #         so we don't do daylightsaving here
   my $gm=time_local2gm(array2seconds($sec,$min,$hour, $mday,$mon-1,$year-1900), $timeoffset, 0);
   return(gmtime2dateserial($gm));
}

sub dateserial2datefield {
   my ($dateserial, $timeoffset, $daylightsaving)=@_;

   # both datetime and the timezone str in date field include the dst shift
   # so we calc datetime, timeoffset_with_dst through timegm and timelocal
   my $timegm=dateserial2gmtime($dateserial);
   my $timelocal=time_gm2local($timegm, $timeoffset, $daylightsaving);
   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=seconds2array($timelocal);
   my $timeoffset_with_dst=seconds2timeoffset($timelocal-$timegm);

   #Date: Wed, 9 Sep 1998 19:30:17 +0800 (CST)
   return(sprintf("%3s, %d %3s %4d %02d:%02d:%02d %s",
              $wday_en[$wday], $mday,$month_en[$mon],$year+1900, $hour,$min,$sec, $timeoffset_with_dst));
}
########## END DATEFIELD <-> DATESERIAL ##########################

########## DATESERIAL2STR ########################################
sub dateserial2str {
   my ($dateserial, $timeoffset, $daylightsaving, $format, $hourformat)=@_;

   my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=
      seconds2array(time_gm2local(dateserial2gmtime($dateserial), $timeoffset, $daylightsaving));
   $year+=1900; $mon++;

   my $str;
   if ( $format eq "mm/dd/yyyy") {
      $str=sprintf("%02d/%02d/%04d", $mon, $mday, $year);
   } elsif ( $format eq "dd/mm/yyyy") {
      $str=sprintf("%02d/%02d/%04d", $mday, $mon, $year);
   } elsif ( $format eq "yyyy/mm/dd") {
      $str=sprintf("%04d/%02d/%02d", $year, $mon, $mday);

   } elsif ( $format eq "mm-dd-yyyy") {
      $str=sprintf("%02d-%02d-%04d", $mon, $mday, $year);
   } elsif ( $format eq "dd-mm-yyyy") {
      $str=sprintf("%02d-%02d-%04d", $mday, $mon, $year);
   } elsif ( $format eq "yyyy-mm-dd") {
      $str=sprintf("%04d-%02d-%02d", $year, $mon, $mday);

   } elsif ( $format eq "mm.dd.yyyy") {
      $str=sprintf("%02d.%02d.%04d", $mon, $mday, $year);
   } elsif ( $format eq "dd.mm.yyyy") {
      $str=sprintf("%02d.%02d.%04d", $mday, $mon, $year);
   } elsif ( $format eq "yyyy.mm.dd") {
      $str=sprintf("%04d.%02d.%02d", $year, $mon, $mday);

   } else {
      $str=sprintf("%02d/%02d/%04d", $mon, $mday, $year);
   }

   if ( $hourformat eq "12") {
      my ($h, $ampm)=hour24to12($hour);
      $str.=sprintf(" %02d:%02d:%02d $ampm", $h, $min, $sec);
   } else {
      $str.=sprintf(" %02d:%02d:%02d", $hour, $min, $sec);
   }
   return($str);
}
########## END DATESERIAL2STR ####################################

########## HOUR24TO12 ############################################
sub hour24to12 {
   my $hour=$_[0];
   my $ampm="am";

   $hour =~ s/^0(.+)/$1/;
   if ($hour==24||$hour==0) {
      $hour = 12;
   } elsif ($hour > 12) {
      $hour = $hour - 12;
      $ampm = "pm";
   } elsif ($hour == 12) {
      $ampm = "pm";
   }
   return($hour, $ampm);
}
########## END HOUR24TO12 ########################################

########## GREGORIAN_EASTER ######################################
# ($month, $day) = gregorian_easter($year);
# This subroutine returns the month and day of Easter in the given year,
# in the Gregorian calendar, which is what most of the world uses.
# Adapted from Rich Bowen's Date::Easter module ver 1.14
sub gregorian_easter {
   my $year = $_[0];
   my ( $G, $C, $H, $I, $J, $L, $month, $day, );
   $G = $year % 19;
   $C = int( $year / 100 );
   $H = ( $C - int( $C / 4 ) - int( ( 8 * $C ) / 25 ) + 19 * $G + 15 ) % 30;
   $I = $H - int( $H / 28 ) *
     ( 1 - int( $H / 28 ) * int( 29 / ( $H + 1 ) ) * int( ( 21 - $G ) / 11 ) );
   $J    = ( $year + int( $year / 4 ) + $I + 2 - $C + int( $C / 4 ) ) % 7;
   $L    = $I - $J;
   $month = 3 + int( ( $L + 40 ) / 44 );
   $day   = $L + 28 - ( 31 * int( $month / 4 ) );
   return ( $month, $day );
}
########## END GREGORIAN_EASTER ##################################

########## EASTER_MATCH ##########################################
# Allow use of expression 'easter +- offset' for month and day field in $idate
# Example: Mardi Gras is ".*,easter,easter-47,.*"
# Written by James Dugal, jpd@louisiana.edu, Sept. 2002
sub easter_match {
   my ($year,$month,$day, $easter_month,$easter_day, $idate) = @_;
   return (0) unless ($idate =~ /easter/i);    # an easter record?
   my @fields = split(/,/,$idate);
   return (0) unless ($year =~ /$fields[0]/);  # year matches?

   $fields[1] =~ s/easter/$easter_month/i;
   $fields[2] =~ s/easter/$easter_day/i;
   if ($fields[1] =~ /^([\d+-]+)$/) {  #untaint
      $fields[1] = eval($1);      # allow simple arithmetic: easter-7  1+easter
   } else {
      return (0);  # bad syntax, only 0-9 + -  chars allowed
   }
   if ($fields[2] =~ /^([\d+-]+)$/) {  #untaint
      $fields[2] = eval($1);      # allow simple arithmetic: easter-7  1+easter
   } else {
      return (0);  # bad syntax, only 0-9 + -  chars allowed
   }
   # days_in_month ought to be pre-computed just once per $year, externally!
   my @days_in_month = qw(0 31 28 31 30 31 30 31 31 30 31 30 31);
   if ( ($year%4)==0 && ( ($year%100)!=0 || ($year%400)==0 ) ) {
      $days_in_month[2]++;
   }
   if ($fields[1] > 0) { # same year, so proceed
      while($fields[2] > $days_in_month[$fields[1]]) {
         $fields[2] -= $days_in_month[$fields[1]];
         $fields[1]++;
      }
      while($fields[2] < 1) {
         $fields[1]--;
         $fields[2] += $days_in_month[$fields[1]];
      }
      return (1) if ($month == $fields[1] && $day == $fields[2]);
   }
   return (0);
}
########## END EASTER_MATCH ######################################

1;
