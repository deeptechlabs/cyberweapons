package ow::enriched;
use strict;
#
# enriched.pl - text/enriched -> text/html transformation routine
#
# 2004/05/12 tung.AT.turtle.ee.ncku.edu.tw
#

use vars qw($nofill_i @nofill_list);
sub enriched2html {
   my $t=$_[0];

   $nofill_i=0; @nofill_list=();
   $t=~s#<nofill>(.*?)</nofill>#_enriched_nofill_save($1)#igems;

   $t=~s#<<#&lt;#g;

   $t=~s#\n(\n*)# $1#sg;
   $t=~s#\n#<br>\n#sg;

   $t=~s#<bold>#<b>#ig;
   $t=~s#</bold>#</b>#ig;
   $t=~s#<italic>#<i>#ig;
   $t=~s#</italic>#</i>#ig;
   $t=~s#<underline>#<u>#ig;
   $t=~s#</underline>#</u>#ig;
   $t=~s#<fixed>#<tt>#ig;
   $t=~s#</fixed>#</tt>#ig;

   $t=~s#<excerpt>#<blockquote>#ig;
   $t=~s#</excerpt>#</blockquote>#ig;

   $t=~s#<bigger>#<font size=+2>#ig;
   $t=~s#<smaller>#<font size=-2>#ig;
   $t=~s#</(?:bigger|smaller)># </font>#ig;

   $t=~s#<flushright>#<div align=right>#ig;
   $t=~s#<flushleft>#<div align=left>#ig;
   $t=~s#<flushboth>#<div>#ig;
   $t=~s#</flush(?:right|left|both)>#</div>#ig;

   $t=~s#<indentright>#<dl><dd>#ig;
   $t=~s#</indentright>#</dl>#ig;
   $t=~s#<indent>#<dl><dd>#ig;
   $t=~s#</indent>#</dl>#ig;

   $t=~s#<color>\s*<param>(.*?)</param>(.*?)</color>#_enriched_color_string($1, $2)#igems;
   $t=~s#<fontfamily>\s*<param>(.*?)</param>(.*?)</fontfamily>#<font face=$1>$2</font>#igs;
   $t=~s#<paraindent>\s*<param>\s*left\s*</param>(.*?)</paraindent>#<dl><dd>$1</dl>#igs;

   $t=~s#</?paraindent>##igs;
   $t=~s#<param>.*?</param>##igs;

   $t=~s!(https?|ftp|mms|nntp|news|gopher|telnet)://([\w\d\-\.]+?/?[^\s\(\)\<\>\x80-\xFF]*[\w/])([\b|\n| ]*)!<a href="$1://$2" target="_blank">$1://$2</a>$3!gs;
   $t=~s!([\b|\n| ]+)(www\.[\w\d\-\.]+\.[\w\d\-]{2,4})([\b|\n| ]*)!$1<a href="http://$2" target="_blank">$2</a>$3!igs;
   $t=~s!([\b|\n| ]+)(ftp\.[\w\d\-\.]+\.[\w\d\-]{2,4})([\b|\n| ]*)!$1<a href="ftp://$2" target="_blank">$2</a>$3!igs;

   $t=~s#NOFILL_(\d+)#_enriched_nofill_restore($1)#igems;
   $nofill_i=0; @nofill_list=();

   return($t);
}

sub _enriched_nofill_save {
   $nofill_list[$nofill_i]=$_[0]; $nofill_i++;   
   return('NOFILL_'.($nofill_i-1));
}
   
sub _enriched_nofill_restore {
   return("<pre>\n".$nofill_list[$_[0]]."</pre>\n");
}

sub _enriched_color_string {
   my ($color, $string)=@_;
   $color="#$1$2$3" if ($color=~/([0-9a-f][0-9a-f])[0-9a-f][0-9a-f]\s*,\s*([0-9a-f][0-9a-f])[0-9a-f][0-9a-f]\s*,\s*([0-9a-f][0-9a-f])[0-9a-f][0-9a-f]/i);
   return(qq|<font color="$color">$string</font>|);
}

1;
