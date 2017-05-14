package ow::htmlrender;
use strict;
#
# htmlrender.pl - html page rendering routines
#
# 2001/12/21 tung.AT.turtle.ee.ncku.edu.tw
#
# it is suggested calling these following routine in the following order:
# html4nobase, html4link, html4disablejs, html4disableemblink,
# html4attachment, html4mailto, html2table
#

require "modules/tool.pl";

# since this routine deals with base directive,
# it must be called first before other html...routines when converting html
sub html4nobase {
   my $html=$_[0];
   my $urlbase;

   if ( $html =~ m!\<base\s+href\s*=\s*"?([^\<\>]*?)"?\>!i ) {
      $urlbase=$1;
      $urlbase=~s!/[^/]+$!/!;
   }

   $html =~ s!\<base\s+([^\<\>]*?)\>!!gi;
   if ( ($urlbase ne "") && ($urlbase !~ /^file:/) ) {
      $html =~ s!(\<a\s+href|background|src|method|action)(=\s*"?)!$1$2$urlbase!gi;
      # recover links that should not be changed by base directive
      $html =~ s!\Q$urlbase\E(http://|https://|ftp://|mms://|cid:|mailto:|#)!$1!gi;
   }
   return($html);
}

my @jsevents=('onAbort', 'onBlur', 'onChange', 'onClick', 'onDblClick',
              'onDragDrop', 'onError', 'onFocus', 'onKeyDown', 'onKeyPress',
              'onKeyUp', 'onLoad', 'onMouseDown', 'onMouseMove', 'onMouseOut',
              'onMouseOver', 'onMouseUp', 'onMove', 'onReset', 'onResize',
              'onSelect', 'onSubmit', 'onUnload', 'window.open');

# this routine is used to add target=_blank to links in a html message
# so clicking on it will open a new window
sub html4link {
   my $html=$_[0];
   $html=~s/(<a\s+[^\<\>]*?>)/_link_target_blank($1)/igems;
   return($html);
}

sub _link_target_blank {
   my $link=$_[0];
#   foreach my $event (@jsevents) {
#      return($link) if ($link =~ /$event/i);
#   }
   if ($link =~ /(?:target=|javascript:|href="?#)/i ) {
      return($link);
   }
   $link=~s/<a\s+([^\<\>]*?)>/<a $1 target=_blank>/is;
   return($link);
}

# this routine is used to resolve frameset in html by
# converting <frame ...> into <iframe width="100%"..></iframe>
# so html with frameset can be displayed correctly inside the message body
sub html4noframe {
   my $html=$_[0];
   $html=~s/(<frame\s+[^\<\>]*?>)/_frame2iframe($1)/igems;
   return($html);
}

sub _frame2iframe {
   my $frame=$_[0];
   return "" if ( $frame!~/src=/i );
   $frame=~s/<frame /<iframe width="100%" height="250" /is;
   $frame.=qq|</iframe>|;
   return($frame);
}

# this routine disables the javascript in a html message
# to avoid user being hijacked by some evil programs
sub html4disablejs {
   my $html=$_[0];
   foreach my $event (@jsevents) {
      $html=~s/$event/_$event/isg;
   }
   $html=~s/<script([^\<\>]*?)>/<disable_script$1>\n<!--\n/isg;
   $html=~s/<!--\s*<!--/<!--/isg;
   $html=~s/<\/script>/\n\/\/-->\n<\/disable_script>/isg;
   $html=~s/\/\/-->\s*\/\/-->/\/\/-->/isg;
   $html=~s/<([^\<\>]*?)javascript:([^\<\>]*?)>/<$1disable_javascript:$2>/isg;

   return($html);
}

# this routine disables embed, applet, object tags in a html message
# to avoid user being hijacked by some evil programs
sub html4disableembcode {
   my $html=$_[0];
   foreach my $tag (qw(embed applet object)) {
      $html=~s!<\s*$tag([^\<\>]*?)>!<disable_$tag$1>!isg;
      $html=~s!<\s*/$tag([^\<\>]*?)>!</disable_$tag$1>!isg;
   }
   $html=~s!<\s*param ([^\<\>]*?)>!<disable_param $1>!isg;
   return($html);
}

# this routine disables the embedded CGI in a html message
# to avoid user email addresses being confirmed by spammer through embedded CGIs
sub html4disableemblink {
   my ($html, $range, $blankimg)=@_;
   $html=~s!(src|background)\s*=\s*("?https?://[\w\.\-]+?/?[^\s<>]*)([\b|\n| ]*)!_clean_emblink($1,$2,$3,$range,$blankimg)!egis;
   return($html);
}

sub _clean_emblink {
   my ($type, $url, $end, $range, $blankimg)=@_;
   if ($url !~ /\Q$ENV{'HTTP_HOST'}\E/is) { # non-local URL found
      if ($range eq 'cgionly' && $url=~/\?/s) {
         $url=~s/["']//g;
         return(qq|border="1" |.
                qq|$type="$blankimg" |.	# blank img url
                qq|alt="Embedded CGI removed by webmail.\n$url" |.
                qq|onclick="window.open('$url', '_extobj');" |.
                $end);
      } elsif ($range eq 'all') {
         $url=~s/["']//g;
         return(qq|border="1" |.
                qq|$type="$blankimg" |.	# blank img url
                qq|alt="Embedded link removed by webmail.\n$url" |.
                qq|onclick="window.open('$url', '_extobj');" |.
                $end);
      }
   }
   return("$type=$url".$end);
}

# this routine is used to resolve cid or loc in a html message to
# the cgi openwebmail-viewatt.pl links of cross referenced mime objects
# this is for read message
sub html4attachments {
   my ($html, $r_attachments, $scripturl, $scriptparm)=@_;

   for (my $i=0; $i<=$#{$r_attachments}; $i++) {
      my $filename=ow::tool::escapeURL(${${$r_attachments}[$i]}{filename});
      my $link=qq|$scripturl/$filename?$scriptparm&amp;|.
               qq|attachment_nodeid=${${$r_attachments}[$i]}{nodeid}&amp;|;
      my $cid="cid:"."${${$r_attachments}[$i]}{'content-id'}";
      my $loc=${${$r_attachments}[$i]}{'content-location'};

      if ( ($cid ne "cid:" && $html =~ s#\Q$cid\E#$link#sig ) ||
           ($loc ne "" && $html =~ s#\Q$loc\E#$link#sig ) ||
           ($filename ne "" && 			# ugly hack for strange CID
              ($html =~ s#CID:\{[\d\w\-]+\}/$filename#$link#sig ||
               $html =~ s#(background|src)\s*=\s*"[^\s\<\>"]{0,256}?/$filename"#$1="$link"#sig) )
         ) {
         # this attachment is referenced by the html
         ${${$r_attachments}[$i]}{referencecount}++;
      }
   }
   return($html);
}

# this routine is used to resolve cid or loc in a html message to
# the cgi openwebmail-viewatt.pl links of cross referenced mime objects
# this is for message composing
sub html4attfiles {
   my ($html, $r_attfiles, $scripturl, $scriptparm)=@_;

   for (my $i=0; $i<=$#{$r_attfiles}; $i++) {
      my $filename=ow::tool::escapeURL(${${$r_attfiles}[$i]}{name});
      my $link=qq|$scripturl/$filename?$scriptparm&amp;|.
               qq|attfile=|.ow::tool::escapeURL(${${$r_attfiles}[$i]}{file}).qq|&amp;|;
      my $cid="cid:"."${${$r_attfiles}[$i]}{'content-id'}";
      my $loc=${${$r_attfiles}[$i]}{'content-location'};

      if ( ($cid ne "cid:" && $html =~ s#\Q$cid\E#$link#sig ) ||
           ($loc ne "" && $html =~ s#\Q$loc\E#$link#sig ) ||
           ($filename ne "" && 			# ugly hack for strange CID
              ($html =~ s#CID:\{[\d\w\-]+\}/$filename#$link#sig ||
               $html =~ s#(background|src)\s*=\s*"[^\s\<\>"]{0,256}?/$filename"#$1="$link"#sig) )
         ) {
         # this attachment is referenced by the html
         ${${$r_attfiles}[$i]}{referencecount}++;
      }
   }
   return($html);
}

# this routine is used to revert links of crossreferenced mime objects
# backto their cid or loc. the reverse operation of html4attfiles()
# the is for messag sending
sub html4attfiles_link2cid {
   my ($html, $r_attfiles, $scripturl)=@_;
   $html=~s!(src|background|href)\s*=\s*("?https?://[\w\.\-]+?/?[^\s<>]*[\w/"])([\b|\n| ]*)!_link2cid($1,$2,$3, $r_attfiles, $scripturl)!egis;
   return($html);
}

sub _link2cid {
   my ($type, $url, $end, $r_attfiles, $scripturl)=@_;
   for (my $i=0; $i<=$#{$r_attfiles}; $i++) {
      my $filename=ow::tool::escapeURL(${${$r_attfiles}[$i]}{name});
      my $attfileparm=qq|attfile=|.ow::tool::escapeURL(${${$r_attfiles}[$i]}{file});
      if ($url=~ /\Q$scripturl\E/ && $url=~ /\Q$attfileparm\E/) {
         ${${$r_attfiles}[$i]}{referencecount}++;

         my $cid="cid:${${$r_attfiles}[$i]}{'content-id'}";
         my $loc=${${$r_attfiles}[$i]}{'content-location'};
         return(qq|$type="$cid"$end|) if ($cid ne "cid:");
         return(qq|$type="$loc"$end|) if ($loc);
         # construct strange CID from attserial
         ${${$r_attfiles}[$i]}{file}=~/([\w\d\-]+)$/;
         return(qq|$type="CID:{$1}/$filename"$end|) if ($filename);
      }
   }
   return("$type=$url".$end);
}

# this routine chnage mailto: into webmail composemail function
# to make it works with base directive, we use full url
# to make it compatible with undecoded base64 block,
# we put new url into a seperate line
sub html4mailto {
   my ($html, $scripturl, $scriptparm)=@_;
   $html =~ s/(=\s*"?)mailto:\s?([^\s]*?)\s?(\s|"?\s*\>)/$1\n$scripturl\?$scriptparm&amp;to=$2\n$3/ig;
   return($html);
}


sub html2table {	# for msg reading
   my $html=_htmlclean($_[0]);
   $html =~ s#\<body([^\<\>]*?)\>#<table width=100% border=0 cellpadding=2 cellspacing=0 $1><tr><td>#is;
   $html =~ s#\</body\>#</td></tr></table>#i;
   return $html;
}

sub html2block {	# for msg composing
   my $html=_htmlclean($_[0]);
   $html =~ s#\<body([^\<\>]*?)\>##is;
   $html =~ s#\</body\>##i;
   return $html;
}

sub _htmlclean {
   my $html=$_[0];

   $html =~ s#<!doctype[^\<\>]*?>##i;
   $html =~ s#<html[^\<\>]*?>##i;
   $html =~ s#</html>##i;
   $html =~ s#<head>.*?</head>##is;
   $html =~ s#<head>##i;
   $html =~ s#</head>##i;
   $html =~ s#<meta[^\<\>]*?>##gi;
   $html =~ s#<!--.*?-->##gis;
   $html =~ s#<style[^\<\>]*?>#\n<!-- style begin\n#gi;
   $html =~ s#</style>#\nstyle end -->\n#gi;
   $html =~ s#<[^\<\>]*?stylesheet[^\<\>]*?>##gi;
   $html =~ s#(<div[^\<\>]*?)position\s*:\s*absolute\s*;([^\<\>]*?>)#$1$2#gi;
   return($html);
}

1;
