<script language="JavaScript">
<!--
   function showmsg (charset, title, msg, button, name, width, height, seconds) {
      var hWnd = window.open("", name,"width="+width+",height="+height+",resizable=no,scrollbars=no");
      hWnd.document.write('<html><head><meta HTTP-EQUIV="Content-Type" CONTENT="text/html; charset='+charset+'">\n');
      hWnd.document.write('<title>'+title+'</title></head><body bgcolor="#ffffff">\n');
      hWnd.document.write('<center><table width="90%" cellspacing="0" cellpadding="0" border="0"><tr><td>\n');
      hWnd.document.write(msg);
      hWnd.document.write('</td></tr></table><br>\n');
      hWnd.document.write('<form name="showmsg"><input type="button" NAME="ok" value="'+button+'" onclick="window.close();"/></form>\n');
      hWnd.document.write('<script language="JavaScript">\n');
//      hWnd.document.write('document.showmsg.ok.focus();\n');
      hWnd.document.write('setTimeout("close()", '+seconds+'*1000);\n');
      hWnd.document.write('</script>\n');
      hWnd.document.write('</body></html>\n');
      hWnd.focus();
   }
//-->
</script>
