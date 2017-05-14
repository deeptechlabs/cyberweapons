package ow::htmltext;
use strict;
#
# htmltext.pl - html/text transformation routine
#
# 2001/12/21 tung.AT.turtle.ee.ncku.edu.tw
#

sub html2text {
   my $t=$_[0];

   # turn <pre>...</pre> into pure html with <br>
   $t=~s|<!--+-->|\n|isg;
   $t=~s!\s*<pre[^\<\>]*?>(.*?)</pre>\s*!_pre2html($1)!iges;

   $t=~s!¡@!  !g;	# clean chinese big5 space char
   $t=~s!&nbsp;! !g;
   $t=~s![ \t]+! !g;
   $t=~s!^\s+!!mg; $t=~s!\s+$! !mg;
   $t=~s![\r\n]+!!g;

   $t=~s|<!--.*?-->||sg;
   $t=~s!<style(?: [^\<\>]*)?>.*?</style>!!isg;
   $t=~s!<script(?: [^\<\>]*)?>.*?</script>!!isg;
   $t=~s!<noframes(?: [^\<\>]*)?>.*?</noframes>!!isg;
   $t=~s!<i?frame[^\<\>]* src="?([^\<\>\s\"]*)"?[^\<\>]*>(.*?</iframe>)?!\n$1\n!isg;

   $t=~s!<p(?: [^\<\>]*)?>!ESCAPE_P!ig;
   $t=~s!<div(?: [^\<\>]*)?>!ESCAPE_DIV!ig;

   # this should be processed before </td> <-> space replacement,
   # or </p>|</div>|\s before </td> won't be found
   $t=~s!<(?:span|font|b|i|a)(?: [^\<\>]*)?>!!isg;
   $t=~s!</(?:th|tr|span|font|b|i|a)>!!ig;

   # this should be processed before <table> <-> \n replacement,
   # or it will eat \n of <table> in recursive table
   $t=~s!<td(?: [^\<\>]*)?>(?:ESCAPE_P|ESCAPE_DIV|</p>|</div>|\s)*</td>!!isg;
   $t=~s!<td(?: [^\<\>]*)?>(?:ESCAPE_P|ESCAPE_DIV|\s)*! !isg;
   $t=~s!(?:</p>|</div>|\s)*</td>! !isg;

   $t=~s!<(?:table|tbody|th|tr)(?: [^\<\>]*)?>!\n!isg;
   $t=~s!</(?:table|tbody)>!\n!ig;

   $t=~s!<(?:ol|ul)(?: [^\<\>]*)?>!\n!ig;
   $t=~s!</(?:ol|ul)>!\n!ig;
   $t=~s!(?:</p>|</div>|\s)*<li>(?:ESCAPE_P|ESCAPE_DIV|\s)*!\n* !isg;

   $t=~s!ESCAPE_P\s*(?:</p>)*!\n\n!isg;
   $t=~s!</p>!\n\n!ig;

   $t=~s!ESCAPE_DIV\s*(?:</div>)*!\n\n!isg;
   $t=~s!</div>!\n\n!ig;

   $t=~s!<select(?: [^\<\>]*)?>(<option(?: [^\<\>]*)?>)?!(!isg;
   $t=~s!</select>!)!ig;
   $t=~s!<option(?: [^\<\>]*)?>!,!isg;
   $t=~s!<input[^\<\>]* type=['"]?radio['"]?[^\<\>]*>! *!isg;

   $t=~s!</?title>!\n\n!ig;
   $t=~s!<br ?/?>!\n!ig;
   $t=~s!<hr(?: [^\<\>]*)?>!\n-----------------------------------------------------------------------\n!ig;

   $t=~s!<[^\<\>]+?>!!sg;

   $t=~s!&lt;!<!g;
   $t=~s!&gt;!>!g;
   $t=~s!&amp;!&!g;
   $t=~s!&quot;!\"!g;
   $t=~s!&copy;!(C)!g;

   $t=~s!^\s+!!;
   $t=~s!(?:[ |\t]*\n){2,}!\n\n!sg;

   return($t);
}

sub _pre2html {
   my $t=$_[0];

#   $t=~s/\"/&quot;/g; $t=~s/</&lt;/g; $t=~s/>/&gt;/g;
   $t=~s!</(?:p|div|table|th|tr)> *\r?\n!</$1>ESCAPE_NEWLINE!ig;
   $t=~s!\n!<br>\n!g;
   $t=~s!ESCAPE_NEWLINE!\n!ig;
   return($t);
}

sub text2html {
   my $t=$_[0];

   $t=~s/&#(\d\d\d+);/ESCAPE_UNICODE_$1/g;
   $t=~s/&/ESCAPE_AMP/g;

   $t=~s/\"/ &quot; /g;
   $t=~s/</ &lt; /g;
   $t=~s/>/ &gt; /g;

   $t=~s!(https?|ftp|mms|nntp|news|gopher|telnet)://([\w\d\-\.]+?/?[^\s\(\)\<\>\x80-\xFF]*[\w/])([\b|\n| ]*)!<a href="$1://$2" target="_blank">$1://$2</a>$3!gs;
   $t=~s!([\b|\n| ]+)(www\.[\w\d\-\.]+\.[\w\d\-]{2,4})([\b|\n| ]*)!$1<a href="http://$2" target="_blank">$2</a>$3!igs;
   $t=~s!([\b|\n| ]+)(ftp\.[\w\d\-\.]+\.[\w\d\-]{2,4})([\b|\n| ]*)!$1<a href="ftp://$2" target="_blank">$2</a>$3!igs;

   # remove the blank inserted just now
   $t=~s/ (&quot;|&lt;|&gt;) /$1/g;

   $t=~s/ {2}/ &nbsp;/g;
   $t=~s/\t/ &nbsp;&nbsp;&nbsp;&nbsp;/g;
   $t=~s/\n/ <BR>\n/g;

   $t=~s/ESCAPE_AMP/&amp;/g;
   $t=~s/ESCAPE_UNICODE_(\d\d\d+)/&#$1;/g;

   return($t);
}

sub str2html {
   my $t=$_[0];

   $t=~s/&#(\d\d\d\d);/ESCAPE_UNICODE_$1/g;
   $t=~s/&/ESCAPE_AMP/g;

   $t=~s/\"/&quot;/g;
   $t=~s/</&lt;/g;
   $t=~s/>/&gt;/g;

   $t=~s/ESCAPE_AMP/&amp;/g;
   $t=~s/ESCAPE_UNICODE_(\d\d\d\d)/&#$1;/g;

   return($t);
}

1;
