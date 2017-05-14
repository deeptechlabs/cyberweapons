<script language="JavaScript">
<!--
   // alert before session end
   var remainingseconds=@@@REMAININGSECONDS@@@;
   var url = "@@@PREFSURL@@@?action=timeoutwarning&sessionid=@@@SESSIONID@@@&session_noupdate=1";
   var tid;
   var hWnd;
   var warn=0;

   function timeoutcheck () {
      remainingseconds=remainingseconds-1;
      if (remainingseconds>0) {
         tid=setTimeout("timeoutcheck()", 1*1000);
         if (remainingseconds<65) {
            if (remainingseconds>6) {
               window.defaultStatus="session time : "+ (remainingseconds-5) +" seconds left";
            } else if (remainingseconds>=5) {
               window.defaultStatus="session time : "+ (remainingseconds-5) +" second left";
            }
            if (!warn) {
               warn=1;
               @@@JSCODE@@@
               hWnd = window.open(url,"_timeoutwarning","width=400,height=140,resizable=no,scrollbars=no");
               hWnd.focus();
            }
         }
      } else {
         window.defaultStatus="session timeout";
         clearTimeout(tid);
      }
   }

   timeoutcheck();
//-->
</script>
