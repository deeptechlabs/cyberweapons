<script type="text/javascript" language="javascript">
<!--
// When you want to include this popup in a page you MUST:
// 1) create a named div for the popup to attach to in the page.
//    It should look like <div id="mypopup"></div>. Do not put
//    the div anywhere in a table. It should be outside tables.
// 2) create a stylesheet id selector entry for your div. It
//    MUST be position absolute and should look like:
//    #mypopup{ position: absolute;
//              visibility: hidden;
//              background-color: @@@MENUBAR@@@;
//              layer-background-color: @@@MENUBAR@@@; }
// 3) call the popup with code that looks like
//    <a href="#" onClick="calPopup(this,'mypopup',-175,15,'additemform','valiDate');">
//    where -175 and 15 are your desired x and y offsets from the link.
//    The final argument indicates the validation script to run after
//    the popup makes a change to the form. This argument is optional.

var nn4 = (document.layers) ? true : false;
var ie  = (document.all) ? true : false;
var dom = (document.getElementById && !document.all) ? true : false;
var popups = new Array(); // keeps track of popup windows we create
var calHtml = '';

// language and preferences
wDay = new Array(@@@WDAY_ARRAY@@@);
wDayAbbrev = new Array(@@@WDAYABBREV_ARRAY@@@);
wMonth = new Array(@@@WMONTH_ARRAY@@@);
wOrder = new Array(@@@WORDER_ARRAY@@@);
wStart = @@@WSTART@@@;

function calPopup(obj, id, xOffset, yOffset, formName, validationScript) {
   attachListener(id);
   registerPopup(id);
   calHtml = makeCalHtml(id,null,null,null,formName,validationScript);
   writeLayer(id,calHtml);
   setLayerPos(obj,id,xOffset,yOffset);
   showLayer(id);
   return true;
}

function attachListener(id) {
   var layer = new pathToLayer(id)
   if (layer.obj.listening == null) {
      document.oldMouseupEvent = document.onmouseup;
      if (document.oldMouseupEvent != null) {
         document.onmouseup = new Function("document.oldMouseupEvent(); hideLayersNotClicked();");
      } else {
         document.onmouseup = hideLayersNotClicked;
      }
      layer.obj.listening = true;
   }
}

function registerPopup(id) {
   // register this popup window with the popups array
   var layer = new pathToLayer(id);
   if (layer.obj.registered == null) {
      var index = popups.length ? popups.length : 0;
      popups[index] = layer;
      layer.obj.registered = 1;
   }
}

function makeCalHtml(id, calYear, calMonth, calDay, formName, validationScript) {
   var calYear = calYear ? calYear : document.forms[formName].elements['year'].options[document.forms[formName].elements['year'].selectedIndex].value;
   var calMonth = calMonth ? calMonth : document.forms[formName].elements['month'].options[document.forms[formName].elements['month'].selectedIndex].value;
   var calDay = calDay ? calDay : document.forms[formName].elements['day'].options[document.forms[formName].elements['day'].selectedIndex].value;

   var daysInMonth = new Array(0,31,28,31,30,31,30,31,31,30,31,30,31);
   if ((calYear % 4 == 0 && calYear % 100 != 0) || calYear % 400 == 0) {
      daysInMonth[2] = 29;
   }

   var calDate = new Date(calYear,calMonth-1,calDay);

   //-----------------------------------------
   // check if the currently selected day is
   // more than what our target month has
   //-----------------------------------------
   if (calMonth < calDate.getMonth()+1) {
     calDay = calDay-calDate.getDate();
     calDate = new Date(calYear,calMonth-1,calDay);
   }

   var calNextYear  = calDate.getMonth() == 11 ? calDate.getFullYear()+1 : calDate.getFullYear();
   var calNextMonth = calDate.getMonth() == 11 ? 1 : calDate.getMonth()+2;
   var calLastYear  = calDate.getMonth() == 0 ? calDate.getFullYear()-1 : calDate.getFullYear();
   var calLastMonth = calDate.getMonth() == 0 ? 12 : calDate.getMonth();

   var todayDate = new Date();

   //---------------------------------------------------------
   // this relies on the javascript bug-feature of offsetting
   // values over 31 days properly. Negative day offsets do NOT
   // work with Netscape 4.x, and negative months do not work
   // in Safari. This works everywhere.
   //---------------------------------------------------------
   var calStartOfThisMonthDate = new Date(calYear,calMonth-1,1);
   var calOffsetToFirstDayOfLastMonth = calStartOfThisMonthDate.getDay() >= wStart ? calStartOfThisMonthDate.getDay()-wStart : 7-wStart-calStartOfThisMonthDate.getDay()
   if (calOffsetToFirstDayOfLastMonth > 0) {
      var calStartDate = new Date(calLastYear,calLastMonth-1,1); // we start in last month
   } else {
      var calStartDate = new Date(calYear,calMonth-1,1); // we start in this month
   }
   var calStartYear = calStartDate.getFullYear();
   var calStartMonth = calStartDate.getMonth();
   var calCurrentDay = calOffsetToFirstDayOfLastMonth ? daysInMonth[calStartMonth+1]-(calOffsetToFirstDayOfLastMonth-1) : 1;

   var html = '';
   // writing the <html><head><body> causes some browsers (Konquerer) to fail
   html += '<table cellpadding="0" cellspacing="1" border="0" bgcolor="#000000">\n';
   html += '<tr>\n';
   html += '<td valign="top">\n';
   html += '<table cellpadding="0" cellspacing="2" border="0" bgcolor=@@@MENUBAR@@@>\n';
   html += '<tr>\n';
   html += '<td valign="top">\n';
   html += '<table cellpadding="3" cellspacing="1" border="0">\n';
   html += '<tr>\n';
   html += '<td><a class="stylecal" href="#" onClick="updateCal(\''+id+'\','+calLastYear+','+calLastMonth+','+calDay+',\''+formName+'\',\''+validationScript+'\'); return false;">&lt;&lt;</a></td>\n';
   html += '<td class="stylecal" align="center" colspan="5">&nbsp;' +wMonth[calDate.getMonth()]+ ' ' +calDate.getFullYear()+ '&nbsp;</td>\n';
   html += '<td><a class="stylecal" href="#" onClick="updateCal(\''+id+'\','+calNextYear+','+calNextMonth+','+calDay+',\''+formName+'\',\''+validationScript+'\'); return false;">&gt;&gt;</a></td>\n';
   html += '</tr>\n';
   for (var row=1; row <= 7; row++) {
      // check if we started a new month at the beginning of this row
      upcomingDate = new Date(calStartYear,calStartMonth,calCurrentDay);
      if (upcomingDate.getDate() <= 8 && row > 5) {
         continue; // skip this row
      }

      html += '<tr>\n';
      for (var col=0; col < 7; col++) {
         var tdColor = col % 2 ? '@@@TABLEROW_DARK@@@' : '@@@TABLEROW_LIGHT@@@';
         if (row == 1) {
            html += '<td bgcolor='+tdColor+' align="center" class="stylecal">'+wDayAbbrev[(wStart+col)%7]+'</td>\n';
         } else {
            var hereDate = new Date(calStartYear,calStartMonth,calCurrentDay);
            var hereDay = hereDate.getDate();
            var aClass = '"stylecal"';

            if (hereDate.getYear() == todayDate.getYear() && hereDate.getMonth() == todayDate.getMonth() && hereDate.getDate() == todayDate.getDate()) {
               tdColor = '"#ff9999"';
            }
            if (hereDate.getMonth() != calDate.getMonth()) {
               tdColor = '@@@MENUBAR@@@';
               var aClass = '"notmonth"';
            }

            html += '<td bgcolor='+tdColor+' align="right"><a class='+aClass+' href="#" onClick="changeFormDate('+hereDate.getFullYear()+','+(hereDate.getMonth()+1)+','+hereDate.getDate()+',\''+formName+'\',\''+validationScript+'\'); hideLayer(\''+id+'\'); return false;">'+hereDay+'</a></td>\n';
            calCurrentDay++;
         }
      }
      html += '</tr>\n';
   }
   html += '<tr>\n';
   html += '<td align="center" colspan="7"><a class="stylecal" href="#" onClick="updateCal(\''+id+'\','+todayDate.getFullYear()+','+(todayDate.getMonth()+1)+','+todayDate.getDate()+',\''+formName+'\',\''+validationScript+'\'); return false;">@@@TODAY@@@</a></td>\n';
   html += '</tr>\n';
   html += '</table>\n';
   html += '</td>\n';
   html += '</tr>\n';
   html += '</table>\n';
   html += '</td>\n';
   html += '</tr>\n';
   html += '</table>\n';

   return html;
}

function updateCal(id, calYear, calMonth, calDay, formName, validationScript) {
   calHtml = makeCalHtml(id,calYear,calMonth,calDay,formName,validationScript);
   writeLayer(id,calHtml);
}

function writeLayer(id, html) {
   var layer = new pathToLayer(id);
   if (nn4) {
      layer.obj.document.open();
      layer.obj.document.write(html);
      layer.obj.document.close();
   } else {
      layer.obj.innerHTML = '';
      layer.obj.innerHTML = html;
   }
}

function setLayerPos(obj, id, xOffset, yOffset) {
   var newX = 0;
   var newY = 0;
   if (obj.offsetParent) {
      // if called from href="setLayerPos(this,'example')" then obj will
      // have no offsetParent properties. Use onClick= instead.
      while (obj.offsetParent) {
         newX += obj.offsetLeft;
         newY += obj.offsetTop;
         obj = obj.offsetParent;
      }
   } else if (obj.x) {
      // nn4 - only works with "a" tags
      newX += obj.x;
      newY += obj.y;
   }

   // apply the offsets
   newX += xOffset;
   newY += yOffset;

   // apply the new positions to our layer
   var layer = new pathToLayer(id);
   if (nn4) {
      layer.style.left = newX;
      layer.style.top  = newY;
   } else {
      // the px avoids errors with doctype strict modes
      layer.style.left = newX + 'px';
      layer.style.top  = newY + 'px';
   }
}

function hideLayersNotClicked(e) {
   if (!e) var e = window.event;
   e.cancelBubble = true;
   if (e.stopPropagation) e.stopPropagation();
   if (e.target) {
      var clicked = e.target;
   } else if (e.srcElement) {
      var clicked = e.srcElement;
   }

   // go through each popup window,
   // checking if it has been clicked
   for (var i=0; i < popups.length; i++) {
      if (nn4) {
         if ((popups[i].style.left < e.pageX) &&
             (popups[i].style.left+popups[i].style.clip.width > e.pageX) &&
             (popups[i].style.top < e.pageY) &&
             (popups[i].style.top+popups[i].style.clip.height > e.pageY)) {
            return true;
         } else {
            hideLayer(popups[i].obj.id);
            return true;
         }
      } else if (ie) {
         while (clicked.parentElement != null) {
            if (popups[i].obj.id == clicked.id) {
               return true;
            }
            clicked = clicked.parentElement;
         }
         hideLayer(popups[i].obj.id);
         return true;
      } else if (dom) {
         while (clicked.parentNode != null) {
            if (popups[i].obj.id == clicked.id) {
               return true;
            }
            clicked = clicked.parentNode;
         }
         hideLayer(popups[i].obj.id);
         return true;
      }
      return true;
   }
   return true;
}

function pathToLayer(id) {
   if (nn4) {
      this.obj = document.layers[id];
      this.style = document.layers[id];
   } else if (ie) {
      this.obj = document.all[id];
      this.style = document.all[id].style;
   } else {
      this.obj = document.getElementById(id);
      this.style = document.getElementById(id).style;
   }
}

function showLayer(id) {
   var layer = new pathToLayer(id)
   layer.style.visibility = "visible";
}

function hideLayer(id) {
   var layer = new pathToLayer(id);
   layer.style.visibility = "hidden";
}

function changeFormDate(changeYear,changeMonth,changeDay,formName,validationScript) {
   document.forms[formName].elements['year'].selectedIndex = changeYear-1970;
   document.forms[formName].elements['month'].selectedIndex = changeMonth-1;
   document.forms[formName].elements['day'].selectedIndex = changeDay-1;
   if (validationScript) {
      eval(validationScript+"('"+formName+"')"); // to update the other selection boxes in the form
   }
}
// -->
</script>

