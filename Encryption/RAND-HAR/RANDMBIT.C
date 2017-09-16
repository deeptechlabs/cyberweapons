From bjh@northshore.ecosoft.com Wed Dec  8 08:03:04 CST 1993
Article: 17770 of sci.crypt
Newsgroups: sci.crypt
Path: chinet!pagesat!olivea!spool.mu.edu!howland.reston.ans.net!europa.eng.gtefsd.com!uunet!noc.near.net!northshore!bjh
From: bjh@northshore.ecosoft.com (Brian J. Harvey)
Subject: Hardware based RNG for DOS machines
Message-ID: <CHHM60.19x@northshore.ecosoft.com>
Keywords: random cryptography DOS PGP 
Organization: North Shore Access, a service of Eco Software, Inc.
Date: Sat, 4 Dec 1993 01:44:24 GMT
Lines: 181

/****************************************************************************/
/*                                                                          */
/*          "Almost Truly Random Bits" - a proposed standard for            */
/*                                                                          */
/*              generating crypto-grade random seeds and keys               */
/*                                                                          */
/*                 using AT compatible hardware and MS-DOS                  */
/*                                                                          */
/*                                   by                                     */
/*                                                                          */
/*               Brian J. Harvey <bjh@northshore.ecosoft.com>               */
/*                                                                          */
/*                  Copyright (C) 1993, Tea Party Software                  */
/*                                                                          */
/*                                   ----                                   */
/*                                                                          */
/*       MD5 Message-Digest Copyright (C) 1991, RSA Data Security, Inc.     */
/*                                                                          */
/****************************************************************************/

/*
    ATRB is inspired by the as-yet-unimplemented hardware strategy that
    appears in PGP v2.3a. ATRB does not suggest a standard usage (API),
    but rather demonstrates a hardware-specific method for capturing
    keyboard latency intervals.

    This method requires an AT (all) or XT (some) BIOS that supports
    interrupt 15h, func 4Fh, keyboard intercept.  Note that this
    implementation traps key _releases_, not presses. This avoids
    needless problems and complexity.

    MS-DOS extentions are not standardized amongst C compilers, however,
    it should be relativly easy to adapt this Turbo C implementation for
    other compilers.

    Finally, a note concerning the MD5 Message-Digest...

    Ron Rivest, in Request for Comments 1321, says:

    "The MD5 algorithm has been carefully scrutinized for weaknesses. It
    is, however, a relatively new algorithm and further security analysis
    is of course justified, as is the case with any new proposal of this
    sort."

    With respect to this statement, I am concerned about the non-standard
    usage of the MD5 in PGP's randstir() function. (I'm not an expert, nor
    do I pretend to be.)

    Please direct questions, comments and job offers to the above address.

    "Yet is was for me - not you - I came to write this song."
                                                  
                                                 - Neil Peart
*/

#include <stdio.h>
#include <conio.h>
#include <dos.h>
#include <time.h>

#define PROTOTYPES 1
#include "global.h"
#include "md5.h"

#pragma options -r- -N-

/* Defines */

#define MES_VEC  0x15        /* Misc. Extended Services */
#define MES_FUNC  0x4F00     /* Keyboard Intercept (XT,AT only) */
#define SP_UP 0xB9           /* Spacebar release (scan code) */
#define ESC 27               /* Escape (ascii) */
#define MAX_RAW 20           /* Actual number of raw bytes to get */

#define TIMER0 0x40          /* Timer constants */
#define TIMERCTRL 0x43
#define LATCHTIMER 0


/* Prototypes */

void reset_kbd_trap(void);             /* Auto-cleanup */
#pragma exit reset_kbd_trap

void near futz(void);                  /* Wait for Timer ports to settle */
void interrupt new_kbd_trap(void);     /* This will latch the timer */


/* Globals */

void interrupt (*old_kbd_trap)(void);  /* Save the original vector */

MD5_CTX MD5context;                    /* defined in MD5.h */

time_t time_seed;                      /* record the time */

unsigned char raw_buffer[MAX_RAW];     /* collect the latency values */
unsigned char MD5digest[16];           /* Hash output */

int raw_index,MD5_index;               /* bookkeeping */


/* Functions */

void reset_kbd_trap(void){             /* Auto-cleanup */
  setvect(MES_VEC,*old_kbd_trap);
}

void near futz(void){}                 /* Wait for Timer ports to settle */

void interrupt new_kbd_trap(void){     /* This will latch the timer */
  unsigned int local_ax = _AX;         /* Better safe 'n sorry... */

  if(local_ax == MES_FUNC + SP_UP && raw_index < MAX_RAW){

    /* Latch and accumulate */

    outportb(TIMERCTRL,LATCHTIMER);
    futz();
    raw_buffer[raw_index++] = inportb(TIMER0) ^ inportb(TIMER0);

    cprintf("\b1 ");                   /* Advance the pinwheel */
  }

  (*old_kbd_trap)();                   /* Give others a chance... */
}
             

void main(){
  unsigned int pindex = 0;

  char pinwheel[5] = "/-\\|";

  /* Set the "trap" */

  old_kbd_trap = *(void interrupt (* far *)(void))MK_FP(0,MES_VEC * 4);
  setvect(MES_VEC,new_kbd_trap);

  MD5_index = raw_index = 0;

  time(&time_seed);                     /* Start message digest w/time */
  MD5Init(&MD5context);
  MD5Update(&MD5context,(unsigned char *)&time_seed,sizeof(time_t));

  cprintf("\nATRB - \"Almost Truly Random Bits\"\r\n");
  cprintf("Copyright (C) 1993, Tea Party Software\r\n");

  cprintf("\nPlease press the SPACEBAR %d times (ESC aborts...)\r\n",MAX_RAW);
  cprintf("%.*s\r",MAX_RAW,"0000000000000000000000000000000000000000");

  while(MD5_index < MAX_RAW && (!kbhit() || getch() != ESC)){

    if(MD5_index < raw_index)
      MD5Update(&MD5context,raw_buffer + MD5_index++,1);

    if(raw_index < MAX_RAW){
      cprintf("\b%c",pinwheel[pindex++ % 4]);
      delay(50);
    }
  }

  while(kbhit())                       /* flush keyboard */
    getch();

  if(MD5_index == MAX_RAW){
    cprintf("\r%-*s\r\n\n",MAX_RAW,"Okay, thanks...");                     
    MD5Final(MD5digest,&MD5context);
    cputs("Timeseed, Raw bytes:\r\n");
    cprintf("%08lX  ",time_seed);
    for(pindex=0;pindex<MAX_RAW;pindex++)
      cprintf("%02X ",raw_buffer[pindex]);

    cputs("\r\n\nMessage Digest:\r\n");
    for(pindex=0;pindex<16;pindex++)
      cprintf("%02X ",MD5digest[pindex]);
    cputs("\r\n");
  }
  else
    cprintf("\r%-*s\r\nAborted!\r\n",MAX_RAW," ");
}



