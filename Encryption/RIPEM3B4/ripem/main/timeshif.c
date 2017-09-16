/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#ifdef MACTC

#include <script.h>
#include <traps.h>

#define TrapMask 0x0800

/* infile prototypes */

#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

int NumToolboxTraps P((void ));
TrapType GetTrapType P((int theTrap));
Boolean TrapAvailable P((int theTrap));
long GMTTimeshift P((void));

#undef P

static int NumToolboxTraps(void)
{ if (NGetTrapAddress(_InitGraf,ToolTrap)==NGetTrapAddress(0xaa6e,ToolTrap))
    return(0x200);
  else return(0x400);
  }
  
static TrapType GetTrapType(int theTrap)
{ if ((theTrap & TrapMask)>0)
    return(ToolTrap);
  else
    return(OSTrap);
}

static Boolean TrapAvailable(int theTrap)
{ TrapType tType;
  tType=GetTrapType(theTrap);
  if (tType==ToolTrap){
     theTrap= theTrap&0x7ff;
     if (theTrap>=NumToolboxTraps())
      theTrap=_Unimplemented;
   }
  return(NGetTrapAddress(theTrap,tType)!=NGetTrapAddress(_Unimplemented,ToolTrap));
 } 
 
/* due to Frederic Miserey */
/* 921109 rwo : if we can do this automagically, set timeshift directly.
 *		Otherwise just return the magic constant that adjusts
 *		the Mac epoch to the UNIX epoch.
 *	NOTE : this routine returns a NEGATIVE number.
 */
long GMTTimeshift(void) {
	long timeshift, gmtDelta;
    MachineLocation loc;
	
	gmtDelta = 0L;
	timeshift = -2082844800L;   
    if (TrapAvailable(_ReadXPRam)){
		ReadLocation(&loc);           
		gmtDelta = loc.gmtFlags.gmtDelta & 0x00FFFFFF;
		if ((gmtDelta & 0x00800000)!=0) /* negative */
			gmtDelta = gmtDelta | 0xFF000000;
		timeshift -= gmtDelta;
		}
	return(timeshift);
	}
	
#endif
