;; Full Keying 128 bit Twofish in ECB Mode
;;
;; Author: Fritz Schneider   (fritz.schneider@iname.com)
;; 
;; This code was written as part of a project in one of my classes 
;; (Microprocessor Lab) at Columbia University.  It is placed in the public
;; domain.
;;
;; Notes:  * The implementation leaves a lot to be desired.  This is the first
;;           large piece of assembly code that I've written so it was more 
;;	     than anything a learning experience.  Its not optimized and needs
;;	     to be streamlined; but it works and thats what was important for 
;;	     the project.  I would have liked to start over and do it 'right' 
;;	     knowing what I know now, but due to my coursework, the demands of
;;           other aspects of the project, and an advanced case of senioritis
;;	     I didn't get around to it :)  In particular, the MDS functionality
;;	     definitely needs to be compacted and generalized.
;;
;;	* There is no good macro assembler for the Z80 that runs on *nix.  So
;;	  this code is a world of kludge:  NASM's preprocessor is used to 
;;	  expand the macros (nasm -e) and then a small perl script I wrote:
;;
;;		#!/usr/bin/perl
;;		while (<>) {
;;			s/^[%].*$/\n/;
;;			s/^[[]org (.*)[]].*$/\tORG $1\n/;
;;			print;
;;			}
;;
;;	  reformats it to undo NASM-isms before actual assembly.
;;
;;	* Careful when fooling with some of the code.  I often use the fact 
;;	  that data doesn't cross 256 byte boundaries to do operations.  Eg,
;;	  xor4HL.  This allows me to increment L and E without worrying about
;;	  H and D.  To fix, just replace the inc l and inc e with inc hl and
;;	  inc de, etc.
;;
;;	* Total size is 7548 bytes:  2428 code & 5120 tables
;;
;;	* Encrypts at about 10.9 ms/block @ 4Mhz after key setup
;;
;;	* Code size can be SIGNIFICANTLY decreased by turning macro calls such
;;	  as Finish?MDS and so forth into subroutines.  The performance hit is
;;	  only a couple thousand cycles per block but would save perhaps 400 
;;	  bytes or more in size.
;;
;;
;; The Project:  In case you're interested, this code formed the core of a 
;; project that we undertook for a class.  We built a floppy disk encryption
;; device that encrypted/decrypted 1.44 meg floppies according to a key 
;; entered on a hex keypad.  As the actual clock speed was 3.57Mhz, we ended up
;; going with a reduced round variant to make it practical.  To a z80 'trainer'
;; we added some extra RAM (and chip select logic), a DMA controller, and a 
;; floppy controller generously donated by SMC.  My partners (nam15 and smk37 
;; @columbia.edu) wrote most of the floppy drivers and such.  Note that we're
;; graduating seniors so my partners' email addresses will only be valid 
;; through about 9/1999.  PS I chose ECB instead of CBC to allow random access
;; to sectors.  Reveals form of plaintext but this was just for fun :P



;;; =========================================================================
;;;	Storage space, constants, and tables
;;; =========================================================================


ORG 1800H	; The user memory on our 'trainer' starts at 1800H

;;; These arrays hold full precomputations including MDS mult.  Si_ROWj[k]
;;;  is the output of sbox i multiplied by the appropriate MDS value for row j
;;;  on input k.   Note that these arrays MUST be aligned on 256 byte frames. 
;;;  In other words, their low order address bytes MUST be 00H.

S0_ROW1:	DEFS 256	
S0_ROW2:	DEFS 256
S0_ROW3:	DEFS 256
S0_ROW4:	DEFS 256

S1_ROW1:	DEFS 256
S1_ROW2:	DEFS 256
S1_ROW3:	DEFS 256
S1_ROW4:	DEFS 256

S2_ROW1:	DEFS 256
S2_ROW2:	DEFS 256
S2_ROW3:	DEFS 256
S2_ROW4:	DEFS 256

S3_ROW1:	DEFS 256
S3_ROW2:	DEFS 256
S3_ROW3:	DEFS 256
S3_ROW4:	DEFS 256

S0_ADD	equ	S0_ROW1/256	; the high order address bytes of the arrays
S1_ADD	equ	S1_ROW1/256
S2_ADD	equ	S2_ROW1/256
S3_ADD	equ	S3_ROW1/256

BLK_SIZE	equ	16	; hardcoded for 128 bits

; Ciphertext and plaintext are stored here in MyText
; Note that MyText is at location 2800H

MyText:		DEFS   16

		;remove defs and put yer test vectors here
	 	;DEFB 01BH, 01BH, 018H, 06DH, 0FEH, 04FH, 01FH, 0C4H
		;DEFB 038H, 05BH, 0C7H, 06FH, 0F3H, 0CAH, 040H, 027H

KEY:		DEFS	 16

		;remove defs and put test vector key here if you like
		;DEFB 084H, 043H, 087H, 031H, 008H, 05DH, 033H, 0F6H
		;DEFB 08EH, 0E4H, 02BH, 040H, 0D9H, 022H, 083H, 07DH
	
Me:	DEFS BLK_SIZE/2		; Even keywords
Mo:	DEFS BLK_SIZE/2		; Odd keywords
S:	DEFS BLK_SIZE/2		; S, the XOR material for the Sboxes
K:	DEFS 160		; Rounds subkeys
ASbKey:	DEFS 4			; Used in computation of round subkeys
BSbKey:	DEFS 4			; ditto

RESULT1:	DEFS 4		; output of one g function
RESULT2:	DEFS 4		; output of the other
	
TEMP32_1:	DEFS 4		; temporary storage used by MDS, eg
	

; the fixed permutation p0 lookup table

p0:	DEFB 0A9h, 067h, 0B3h, 0E8h, 004h, 0FDh, 0A3h, 076h
	DEFB 09Ah, 092h, 080h, 078h, 0E4h, 0DDh, 0D1h, 038h
	DEFB 00Dh, 0C6h, 035h, 098h, 018h, 0F7h, 0ECh, 06Ch
	DEFB 043h, 075h, 037h, 026h, 0FAh, 013h, 094h, 048h
	DEFB 0F2h, 0D0h, 08Bh, 030h, 084h, 054h, 0DFh, 023h
	DEFB 019h, 05Bh, 03Dh, 059h, 0F3h, 0AEh, 0A2h, 082h
	DEFB 063h, 001h, 083h, 02Eh, 0D9h, 051h, 09Bh, 07Ch
	DEFB 0A6h, 0EBh, 0A5h, 0BEh, 016h, 00Ch, 0E3h, 061h
	DEFB 0C0h, 08Ch, 03Ah, 0F5h, 073h, 02Ch, 025h, 00Bh
	DEFB 0BBh, 04Eh, 089h, 06Bh, 053h, 06Ah, 0B4h, 0F1h
	DEFB 0E1h, 0E6h, 0BDh, 045h, 0E2h, 0F4h, 0B6h, 066h
	DEFB 0CCh, 095h, 003h, 056h, 0D4h, 01Ch, 01Eh, 0D7h
	DEFB 0FBh, 0C3h, 08Eh, 0B5h, 0E9h, 0CFh, 0BFh, 0BAh
	DEFB 0EAh, 077h, 039h, 0AFh, 033h, 0C9h, 062h, 071h
	DEFB 081h, 079h, 009h, 0ADh, 024h, 0CDh, 0F9h, 0D8h
	DEFB 0E5h, 0C5h, 0B9h, 04Dh, 044h, 008h, 086h, 0E7h
	DEFB 0A1h, 01Dh, 0AAh, 0EDh, 006h, 070h, 0B2h, 0D2h
	DEFB 041h, 07Bh, 0A0h, 011h, 031h, 0C2h, 027h, 090h
	DEFB 020h, 0F6h, 060h, 0FFh, 096h, 05Ch, 0B1h, 0ABh
	DEFB 09Eh, 09Ch, 052h, 01Bh, 05Fh, 093h, 00Ah, 0EFh
	DEFB 091h, 085h, 049h, 0EEh, 02Dh, 04Fh, 08Fh, 03Bh
	DEFB 047h, 087h, 06Dh, 046h, 0D6h, 03Eh, 069h, 064h
	DEFB 02Ah, 0CEh, 0CBh, 02Fh, 0FCh, 097h, 005h, 07Ah
	DEFB 0ACh, 07Fh, 0D5h, 01Ah, 04Bh, 00Eh, 0A7h, 05Ah
	DEFB 028h, 014h, 03Fh, 029h, 088h, 03Ch, 04Ch, 002h
	DEFB 0B8h, 0DAh, 0B0h, 017h, 055h, 01Fh, 08Ah, 07Dh
	DEFB 057h, 0C7h, 08Dh, 074h, 0B7h, 0C4h, 09Fh, 072h
	DEFB 07Eh, 015h, 022h, 012h, 058h, 007h, 099h, 034h
	DEFB 06Eh, 050h, 0DEh, 068h, 065h, 0BCh, 0DBh, 0F8h
	DEFB 0C8h, 0A8h, 02Bh, 040h, 0DCh, 0FEh, 032h, 0A4h
	DEFB 0CAh, 010h, 021h, 0F0h, 0D3h, 05Dh, 00Fh, 000h
	DEFB 06Fh, 09Dh, 036h, 042h, 04Ah, 05Eh, 0C1h, 0E0h

; the fixed permutation p1 lookup table

p1:	DEFB 075h, 0F3h, 0C6h, 0F4h, 0DBh, 07Bh, 0FBh, 0C8h
	DEFB 04Ah, 0D3h, 0E6h, 06Bh, 045h, 07Dh, 0E8h, 04Bh
	DEFB 0D6h, 032h, 0D8h, 0FDh, 037h, 071h, 0F1h, 0E1h
	DEFB 030h, 00Fh, 0F8h, 01Bh, 087h, 0FAh, 006h, 03Fh
	DEFB 05Eh, 0BAh, 0AEh, 05Bh, 08Ah, 000h, 0BCh, 09Dh
	DEFB 06Dh, 0C1h, 0B1h, 00Eh, 080h, 05Dh, 0D2h, 0D5h
	DEFB 0A0h, 084h, 007h, 014h, 0B5h, 090h, 02Ch, 0A3h
	DEFB 0B2h, 073h, 04Ch, 054h, 092h, 074h, 036h, 051h
	DEFB 038h, 0B0h, 0BDh, 05Ah, 0FCh, 060h, 062h, 096h
	DEFB 06Ch, 042h, 0F7h, 010h, 07Ch, 028h, 027h, 08Ch
	DEFB 013h, 095h, 09Ch, 0C7h, 024h, 046h, 03Bh, 070h
	DEFB 0CAh, 0E3h, 085h, 0CBh, 011h, 0D0h, 093h, 0B8h
	DEFB 0A6h, 083h, 020h, 0FFh, 09Fh, 077h, 0C3h, 0CCh
	DEFB 003h, 06Fh, 008h, 0BFh, 040h, 0E7h, 02Bh, 0E2h
	DEFB 079h, 00Ch, 0AAh, 082h, 041h, 03Ah, 0EAh, 0B9h
	DEFB 0E4h, 09Ah, 0A4h, 097h, 07Eh, 0DAh, 07Ah, 017h
	DEFB 066h, 094h, 0A1h, 01Dh, 03Dh, 0F0h, 0DEh, 0B3h
	DEFB 00Bh, 072h, 0A7h, 01Ch, 0EFh, 0D1h, 053h, 03Eh
	DEFB 08Fh, 033h, 026h, 05Fh, 0ECh, 076h, 02Ah, 049h
	DEFB 081h, 088h, 0EEh, 021h, 0C4h, 01Ah, 0EBh, 0D9h
	DEFB 0C5h, 039h, 099h, 0CDh, 0ADh, 031h, 08Bh, 001h
	DEFB 018h, 023h, 0DDh, 01Fh, 04Eh, 02Dh, 0F9h, 048h
	DEFB 04Fh, 0F2h, 065h, 08Eh, 078h, 05Ch, 058h, 019h
	DEFB 08Dh, 0E5h, 098h, 057h, 067h, 07Fh, 005h, 064h
	DEFB 0AFh, 063h, 0B6h, 0FEh, 0F5h, 0B7h, 03Ch, 0A5h
	DEFB 0CEh, 0E9h, 068h, 044h, 0E0h, 04Dh, 043h, 069h
	DEFB 029h, 02Eh, 0ACh, 015h, 059h, 0A8h, 00Ah, 09Eh
	DEFB 06Eh, 047h, 0DFh, 034h, 035h, 06Ah, 0CFh, 0DCh
	DEFB 022h, 0C9h, 0C0h, 09Bh, 089h, 0D4h, 0EDh, 0ABh
	DEFB 012h, 0A2h, 00Dh, 052h, 0BBh, 002h, 02Fh, 0A9h
	DEFB 0D7h, 061h, 01Eh, 0B4h, 050h, 004h, 0F6h, 0C2h
	DEFB 016h, 025h, 086h, 056h, 055h, 009h, 0BEh, 091h

; lookup table for MDS multiply.  tab5B[i] contains result of i * 5B

tab5B: 
	DEFB 000h, 05Bh, 0B6h, 0EDh, 005h, 05Eh, 0B3h, 0E8h
	DEFB 00Ah, 051h, 0BCh, 0E7h, 00Fh, 054h, 0B9h, 0E2h
	DEFB 014h, 04Fh, 0A2h, 0F9h, 011h, 04Ah, 0A7h, 0FCh
	DEFB 01Eh, 045h, 0A8h, 0F3h, 01Bh, 040h, 0ADh, 0F6h
	DEFB 028h, 073h, 09Eh, 0C5h, 02Dh, 076h, 09Bh, 0C0h
	DEFB 022h, 079h, 094h, 0CFh, 027h, 07Ch, 091h, 0CAh
	DEFB 03Ch, 067h, 08Ah, 0D1h, 039h, 062h, 08Fh, 0D4h
	DEFB 036h, 06Dh, 080h, 0DBh, 033h, 068h, 085h, 0DEh
	DEFB 050h, 00Bh, 0E6h, 0BDh, 055h, 00Eh, 0E3h, 0B8h
	DEFB 05Ah, 001h, 0ECh, 0B7h, 05Fh, 004h, 0E9h, 0B2h
	DEFB 044h, 01Fh, 0F2h, 0A9h, 041h, 01Ah, 0F7h, 0ACh
	DEFB 04Eh, 015h, 0F8h, 0A3h, 04Bh, 010h, 0FDh, 0A6h
	DEFB 078h, 023h, 0CEh, 095h, 07Dh, 026h, 0CBh, 090h
	DEFB 072h, 029h, 0C4h, 09Fh, 077h, 02Ch, 0C1h, 09Ah
	DEFB 06Ch, 037h, 0DAh, 081h, 069h, 032h, 0DFh, 084h
	DEFB 066h, 03Dh, 0D0h, 08Bh, 063h, 038h, 0D5h, 08Eh
	DEFB 0A0h, 0FBh, 016h, 04Dh, 0A5h, 0FEh, 013h, 048h
	DEFB 0AAh, 0F1h, 01Ch, 047h, 0AFh, 0F4h, 019h, 042h
	DEFB 0B4h, 0EFh, 002h, 059h, 0B1h, 0EAh, 007h, 05Ch
	DEFB 0BEh, 0E5h, 008h, 053h, 0BBh, 0E0h, 00Dh, 056h
	DEFB 088h, 0D3h, 03Eh, 065h, 08Dh, 0D6h, 03Bh, 060h
	DEFB 082h, 0D9h, 034h, 06Fh, 087h, 0DCh, 031h, 06Ah
	DEFB 09Ch, 0C7h, 02Ah, 071h, 099h, 0C2h, 02Fh, 074h
	DEFB 096h, 0CDh, 020h, 07Bh, 093h, 0C8h, 025h, 07Eh
	DEFB 0F0h, 0ABh, 046h, 01Dh, 0F5h, 0AEh, 043h, 018h
	DEFB 0FAh, 0A1h, 04Ch, 017h, 0FFh, 0A4h, 049h, 012h
	DEFB 0E4h, 0BFh, 052h, 009h, 0E1h, 0BAh, 057h, 00Ch
	DEFB 0EEh, 0B5h, 058h, 003h, 0EBh, 0B0h, 05Dh, 006h
	DEFB 0D8h, 083h, 06Eh, 035h, 0DDh, 086h, 06Bh, 030h
	DEFB 0D2h, 089h, 064h, 03Fh, 0D7h, 08Ch, 061h, 03Ah
	DEFB 0CCh, 097h, 07Ah, 021h, 0C9h, 092h, 07Fh, 024h
	DEFB 0C6h, 09Dh, 070h, 02Bh, 0C3h, 098h, 075h, 02Eh

; lookup table for MDS multiply.  tabEF[i] contains result of i * EF

tabEF: 
	DEFB 000h, 0EFh, 0B7h, 058h, 007h, 0E8h, 0B0h, 05Fh
	DEFB 00Eh, 0E1h, 0B9h, 056h, 009h, 0E6h, 0BEh, 051h
	DEFB 01Ch, 0F3h, 0ABh, 044h, 01Bh, 0F4h, 0ACh, 043h
	DEFB 012h, 0FDh, 0A5h, 04Ah, 015h, 0FAh, 0A2h, 04Dh
	DEFB 038h, 0D7h, 08Fh, 060h, 03Fh, 0D0h, 088h, 067h
	DEFB 036h, 0D9h, 081h, 06Eh, 031h, 0DEh, 086h, 069h
	DEFB 024h, 0CBh, 093h, 07Ch, 023h, 0CCh, 094h, 07Bh
	DEFB 02Ah, 0C5h, 09Dh, 072h, 02Dh, 0C2h, 09Ah, 075h
	DEFB 070h, 09Fh, 0C7h, 028h, 077h, 098h, 0C0h, 02Fh
	DEFB 07Eh, 091h, 0C9h, 026h, 079h, 096h, 0CEh, 021h
	DEFB 06Ch, 083h, 0DBh, 034h, 06Bh, 084h, 0DCh, 033h
	DEFB 062h, 08Dh, 0D5h, 03Ah, 065h, 08Ah, 0D2h, 03Dh
	DEFB 048h, 0A7h, 0FFh, 010h, 04Fh, 0A0h, 0F8h, 017h
	DEFB 046h, 0A9h, 0F1h, 01Eh, 041h, 0AEh, 0F6h, 019h
	DEFB 054h, 0BBh, 0E3h, 00Ch, 053h, 0BCh, 0E4h, 00Bh
	DEFB 05Ah, 0B5h, 0EDh, 002h, 05Dh, 0B2h, 0EAh, 005h
	DEFB 0E0h, 00Fh, 057h, 0B8h, 0E7h, 008h, 050h, 0BFh
	DEFB 0EEh, 001h, 059h, 0B6h, 0E9h, 006h, 05Eh, 0B1h
	DEFB 0FCh, 013h, 04Bh, 0A4h, 0FBh, 014h, 04Ch, 0A3h
	DEFB 0F2h, 01Dh, 045h, 0AAh, 0F5h, 01Ah, 042h, 0ADh
	DEFB 0D8h, 037h, 06Fh, 080h, 0DFh, 030h, 068h, 087h
	DEFB 0D6h, 039h, 061h, 08Eh, 0D1h, 03Eh, 066h, 089h
	DEFB 0C4h, 02Bh, 073h, 09Ch, 0C3h, 02Ch, 074h, 09Bh
	DEFB 0CAh, 025h, 07Dh, 092h, 0CDh, 022h, 07Ah, 095h
	DEFB 090h, 07Fh, 027h, 0C8h, 097h, 078h, 020h, 0CFh
	DEFB 09Eh, 071h, 029h, 0C6h, 099h, 076h, 02Eh, 0C1h
	DEFB 08Ch, 063h, 03Bh, 0D4h, 08Bh, 064h, 03Ch, 0D3h
	DEFB 082h, 06Dh, 035h, 0DAh, 085h, 06Ah, 032h, 0DDh
	DEFB 0A8h, 047h, 01Fh, 0F0h, 0AFh, 040h, 018h, 0F7h
	DEFB 0A6h, 049h, 011h, 0FEh, 0A1h, 04Eh, 016h, 0F9h
	DEFB 0B4h, 05Bh, 003h, 0ECh, 0B3h, 05Ch, 004h, 0EBh
	DEFB 0BAh, 055h, 00Dh, 0E2h, 0BDh, 052h, 00Ah, 0E5h



;;; =========================================================================
;;;	Macros
;;; =========================================================================

;;; =========================================================================
;;;	copy4 -- copies four bytes to a location in memory
;;;	Args: 2, the first IXY is the destination, the second IXY the source  
;;;	Result:  four bytes starting at %2 copied into mem starting at %1
;;;	Clobbers:  HL
;;; =========================================================================
			
%macro		copy4	2
		ld	hl,(%2)
		ld	(%1),hl
		ld	hl,(%2+2)
		ld	(%1+2),hl
%endmacro


;;; =========================================================================
;;;	dup4 -- writes four bytes of the accumulator content to memory
;;;	Args: 1, IXY points to destination 
;;;	Result:  copies value in A into four bytes starting at %1
;;;	Clobbers:  
;;; =========================================================================

%macro		dup4	1	
		ld	(%1+0),a
		ld	(%1+1),a
		ld	(%1+2),a
		ld	(%1+3),a
%endmacro


;;; =========================================================================
;;;	add4MEM -- 32 bit add where both operands are in memory
;;;	Args: 2, memory locations; the result of the add placed in first arg
;;;	Result:  32 bit add.  Does (%1) = (%1) + (%2)
;;;	Clobbers:  DEHL
;;; =========================================================================

%macro		add4MEM	2	
		ld	de, (%1)	; grab first two bytes
		ld	hl,(%2)
		add	hl,de		; add first two bytes
		ld	(%1),hl		; store result
	
		ld	de, (%1+2)	; upper half
		ld	hl,(%2+2)
		adc	hl,de		; add with carry
		ld	(%1+2),hl	; store result
%endmacro
	

;;; =========================================================================
;;;	add4HL -- 32 bit add, one operand ptd to by HL, steps past operands
;;;	Args: 1, mem location of first word operand
;;;	      HL should point to beginning of second operand
;;;	Result:  32 bit add.  adds 32 bits pointed to by %1 with those pointed
;;;	           to by HL and stores results in %1.  HL is incremented by 4.
;;;	Clobbers:  ADE, and HL is incremented by four, DE points to %1 + 4
;;; =========================================================================

%macro		add4HL	1	
		ld	de,%1		; load location of first operand

		ld	a, (de)		; bring in first byte
		add	a,(hl)		; add
		ld	(de), a		; and store

		inc	hl		; step to next byte
		inc	de
	
		ld	a, (de) 
		adc	a,(hl)		; add again, this time with carry
		ld	(de), a

		inc	hl
		inc	de
	
		ld	a, (de)
		adc	a,(hl)
		ld	(de), a

		inc	hl
		inc	de
	
		ld	a, (de)
		adc	a,(hl)
		ld	(de), a

		inc	hl		; final increment.  doing it this way
		inc	de		;    speeds up main loop a bit


%endmacro

	
;;; =========================================================================
;;;	xor16 -- XORs 16 bytes in memory
;;;	Args:  2, memory locations:  the start of bytes to XOR
;;;	Result:  XORs 16 bytes starting at %1 and %2.  Result into %1
;;;	Clobbers:  ABDEHL
;;; =========================================================================

%macro		xor16	2	
		ld	hl,%2		; point HL and DE to memory
		ld	de,%1
		ld	b,10H		; going to do 16 = 10H bytes
%%xlp:		ld	a,(de)		; load one byte
		xor	(hl)		; xor it
		ld	(de),a		; store
		inc	hl		; step up pointers
		inc	de
		djnz	%%xlp		; loop
%endmacro


;;; =========================================================================
;;;	xor4HL -- XOR 4 bytes in memory using DE & HL, steps past operands
;;;	Args:  None.  HL and DE should point to bytes to be XORed
;;;	Result:  XORs four bytes starting at (DE) with (HL).  Result into (DE)
;;;	Clobbers:  DE and HL are incremented by four
;;; =========================================================================

%macro		xor4HL		0	
		ld	a,(de)		; step through bytes, XORing
		xor	(hl)
		ld	(de),a		; store result
		inc	l	     ; assumes doesnt cross 256 byte boundaries
		inc	e
		ld	a,(de)
		xor	(hl)
		ld	(de),a
		inc	l
		inc	e
		ld	a,(de)
		xor	(hl)
		ld	(de),a
		inc	l
		inc	e
		ld	a,(de)
		xor	(hl)
		ld	(de),a
		inc	l
		inc	e
%endmacro


;;; =========================================================================
;;;	xor4 -- XOR four bytes in memory using IXY registers
;;;	Args: 2, first IXY is first operand, second IXY is the second operand
;;;	Result:  XORs four bytes starting at (%1) with (%2).  Result in (%1)
;;;	Clobbers:  A
;;; =========================================================================		
%macro		xor4	2	; XOR 4 bytes together, result in first arg
 		ld a,(%1 + 0)
 		xor (%2 + 0)
 		ld (%1 + 0),a
 		ld a,(%1 + 1)
 		xor (%2 + 1)
 		ld (%1 + 1),a
 		ld a,(%1 + 2)
 		xor (%2 + 2)
		ld (%1 + 2),a
 		ld a,(%1 + 3)
 		xor (%2 + 3)
 		ld (%1 + 3),a
%endmacro


;;; =========================================================================
;;;	clear32 -- Writes four 0 bytes to memory
;;;	Args: 1, the memory location to clear
;;;	Result:  writes four bytes of zeros to memory starting at %1
;;;	Clobbers:  HL
;;; =========================================================================

%macro		clear32	1		
		ld	hl,0000H	; word to write
		ld	(%1),hl		; write it once
		ld	(%1 + 2),hl	; write it again
%endmacro


;;; =========================================================================
;;;	sl32 -- 32 bit rotate left in memory
;;;	Args:  2, first IXY is location of data, second is # bits to rotate by
;;;	Result:  32-bit left shift.  32 bit word at (%1) rotate left by %2 bits
;;;	Clobbers:  
;;; =========================================================================

%macro		sl32	2	
		push	bc		; save b
		ld	b,%2		; load number of rotations
%%lp:		jp	nc,%%nocry	; assumes frst arg IXY pts to low byte
		ccf			; if carry flag is set, reset it
%%nocry:	rl	(%1+0)		; rotate first byte
		rl	(%1+1)		; second
		rl	(%1+2)		; third
		rl	(%1+3)		; final
%%bot:		djnz	%%lp		; if not finished, loop again
		pop	bc
%endmacro


;;; =========================================================================
;;;	copy4HL	-- copies four bytes from (IXY) into (HL) and increments HL
;;;	Args: 1, IXY the source of the bytes
;;;	Result:  copies four bytes from (%1) into (HL) and increments
;;;	Clobbers:  none, HL is incremented by four
;;; =========================================================================

%macro	copy4HL	1		; copies four bytes into (HL) and increments
	push	af
	ld	a, (%1+0)
	ld	(hl),a
	inc	hl
	ld	a, (%1+1)
	ld	(hl),a
	inc	hl
	ld	a, (%1+2)
	ld	(hl),a
	inc	hl
	ld	a, (%1+3)
	ld	(hl),a
	inc	hl
	pop	af
%endmacro
	

;;; =========================================================================
;;;	DoSBoxes -- run four bytes through the SBoxes
;;;	Args: 3, first is location in memory to store results
;;;	         second IXY points to the input to the SBOXs
;;		 third IXY points to the 8 bytes of intermediate XOR material
;;;	Result:  stored in %3.  Sbox zero output is in %3+0, sbox 1 in %3+1 etc
;;;	Clobbers:  ABCDEHL
;;; =========================================================================
	
%macro	DoSBoxes	3	
	ld	d,00H		; zero out d 

				; setup sbox zero
	ld	e,(%2+0)	; load first input byte
	ld	b,(%3+4)	; load B with first XOR material
	ld	c,(%3+0)	; load C with second XOR material
	call	FeedS0		; feed through the sbox, result into A
	ld	(%1+0),a	; store result

	ld	e,(%2+1)	; do same for sbox 1
	ld	b,(%3+5)
	ld	c,(%3+1)
	call	FeedS1
	ld	(%1+1),a

	ld	e,(%2+2)	; and sbox 2
	ld	b,(%3+6)
	ld	c,(%3+2)
	call	FeedS2
	ld	(%1+2),a

	ld	e,(%2+3)	; and sbox 3
	ld	b,(%3+7)
	ld	c,(%3+3)
	call	FeedS3
	ld	(%1+3),a

%endmacro
	

;;; =========================================================================
;;;	SwapText -- swap 8 contiguous bytes in memory 
;;;	Args: 2, both are IXY and point to start of bytes to swap
;;;	Result:  8 bytes formerly starting at %2 are now at %1, and vice versa
;;;	Clobbers:  DEHL
;;; =========================================================================

%macro	SwapText	2

	ld	hl, (%1)	; swap two bytes at a time
	ld	de, (%2)	; read both in
	ld	(%2),hl		; write both out
	ld	(%1),de

	ld	hl, (%1+2)
	ld	de, (%2+2)
	ld	(%2+2),hl
	ld	(%1+2),de

	ld	hl, (%1+4)
	ld	de, (%2+4)
	ld	(%2+4),hl
	ld	(%1+4),de

	ld	hl, (%1+6)
	ld	de, (%2+6)
	ld	(%2+6),hl
	ld	(%1+6),de
%endmacro


;;; =========================================================================
;;;	Finish0MDS -- Looks up output of first g function and finishes out
;;;		      MDS multiply by XORing (adding) the bytes.
;;;	Args: 3, %1 is starting location in memory of input word
;;;	         %2 is a constant, the row that we're in.  Used as an offset
;;;		    from Si to make lookups faster.  See below.
;;;		 %3 is the location in memory to put result
;;;	Result:  feeds input word (4 bytes) to sboxes and completes MDS 
;;;		 multiply, writing result to memory starting at %3
;;;	Clobbers:  AA'DEHL
;;; =========================================================================
;;; This feeds the g function the input word without rotating left by 8 bits.
;;; Because the sbox lookup arrays are aligned on 256 bytes frames, we can 
;;; just load the high order bytes of their addresses.  Saves some time and
;;; allows me to increment e instead of de.

%macro	Finish0MDS	3	
	ld	h,S0_ADD + %2		; start with sbox zero
	ld	de,%1			; point de to input
	ld	a,(de)			; load first input byte
	inc	e			; step to next byte
	ld	l,a			; put input byte into l as offset
	ld	a,(hl)			; load result
	ld	h,S1_ADD + %2		; now for sbox 1
	ex	af,af'			; save the result of sbox 0
	ld	a,(de)			; load input to sbox 1
	ld	l,a			; use input as offset into table
	ex	af,af'			; get sbox 0 output back
	inc	e			; step to next byte
	xor	(hl)			; xor result of sbox 1 with sbox 0
	ld	h,S2_ADD + %2		; now we're on sbox 2
	ex	af,af'			; save current value
	ld	a,(de)			; load input byte
	ld	l,a			; use input byte as offset
	ex	af,af'			; get current value back
	inc	e			; step to next byte
	xor	(hl)			; xor the output of sbox 2 with value
	ld	h,S3_ADD + %2		; now we're on the last sbox
	ex	af,af'			; save current value
	ld	a,(de)			; load input byte
	ld	l,a			; use input byte as table offset
	ex	af,af'			; get current value
	xor	(hl)			; final xor of value and sbox3's output
	ld	(%3),a			; store result
%endmacro


;;; =========================================================================
;;;	Finish1MDS -- Looks up output of second g function and finishes out
;;;		      MDS multiply by XORing (adding) the bytes.
;;;	Args: 3, %1 is starting location in memory of input word
;;;	         %2 is a constant, the row that we're in.  Used as an offset
;;;		    from Si to make lookups faster.  See below.
;;;		 %3 is the location in memory to put result
;;;	Result:  feeds input word (4 bytes) to sboxes in rotated order and 
;;;		 completes MDS multiply, writing result to mem starting at %3
;;;	Clobbers:  AA'DEHL
;;; =========================================================================
;;; This feeds the g function the input word simulating a left rotate by 8 bits
;;; before hand.   This is achieved by just changing the order that we feed
;;; the input to the sboxes from 0,1,2,3 to 1,2,3,0.   Other than that its
;;; identical to Finish0MDS.  Should have combined these two into one big
;;; macro but oh well.

%macro	Finish1MDS	3		; Same exact operation as above, just
	ld	h,S1_ADD + %2		;  feeding sboxes in a different order.
	ld	de,%1
	ld	a,(de)
	ld	l,a
	inc	e
	ld	a,(hl)
	ld	h,S2_ADD + %2
	ex	af,af'
	ld	a,(de)
	ld	l,a
	ex	af,af'
	inc	e
	xor	(hl)
	ld	h,S3_ADD + %2
	ex	af,af'
	ld	a,(de)
	ld	l,a
	ex	af,af'
	inc	e
	xor	(hl)
	ld	h,S0_ADD + %2
	ex	af,af'
	ld	a,(de)
	ld	l,a
	ex	af,af'
	xor	(hl)
	ld	(%3),a
%endmacro


;;; =========================================================================
;;;	RoundFunc -- performs a whole F function minus the output rotations
;;;		     and keyword addition
;;;	Args:  
;;;	Result:  RESULT1 contains output of first g function
;;;		 RESULT2 contains output of second g function
;;;	Clobbers:  AA'DEHL
;;; =========================================================================
		
%macro	RoundFunc	0

	; Feed the first input word to g function, storing result in RESULT1

 	Finish0MDS	MyText,0,RESULT1	   ; with row 1 of MDS matrix
	Finish0MDS	MyText,01H,RESULT1+1	   ; with row 2 of MDS matrix
 	Finish0MDS	MyText,02H,RESULT1+2	   ; with row 3 of MDS matrix
 	Finish0MDS	MyText,03H,RESULT1+3	   ; with row 4 of MDS matrix

	; Feed the second input word to g function, storing result in RESULT2

 	Finish1MDS	MyText+4,0,RESULT2	 ; with row 1 of MDS matrix
	Finish1MDS	MyText+4,01H,RESULT2+1   ; with row 2 of MDS matrix
 	Finish1MDS	MyText+4,02H,RESULT2+2   ; with row 3 of MDS matrix
 	Finish1MDS	MyText+4,03H,RESULT2+3   ; with row 4 of MDS matrix

	add4MEM	RESULT1,RESULT2		; do the pseudo-hadamard transform
	add4MEM	RESULT2,RESULT1
%endmacro
	


;;; =========================================================================
;;;	Subroutines
;;; =========================================================================
		
;;; =========================================================================
;;;	KeySetup -- sets up round subkeys, etc.  MUST BE CALLED BEFORE ENCRYPT
;;;	Args:  KEY contains the 128 bit key
;;;	Result:  K0 to K39 are in K, Subkeys S0 and S1 are in S, 
;;;	Clobbers:  All registers, K, S, Me, Mo, ASbKey, BSbKey, TEMP32_1
;;; =========================================================================
;;;	This can definitely be optimized.  Eg, check to see if ldir is any
;;;     faster than just copying, etc., Make Ke0 Ke1 etc index into KEY, etc
	
KeySetup:	
	copy4	Me,KEY
	copy4	Me+4,KEY+8
	copy4	Mo,KEY+4
	copy4	Mo+4,KEY+12

	;; Me and Mo are valid at this point

	;; Now calculate subkeys S0 and S1

	ld	IY, Me		; point IX towards first even 32bit word
	ld	IX, Mo		; point IY towards first odd 32bit word	

	call	RS_MDS_Encode	; do the RS thang

	ld	de, S+4		; we're going to put the first word here
	ld	bc, 0004H	; going to copy four bytes...
	ldir			; copy into S

	ld	IY, Me+4	; point IX towards second even 32bit word
	ld	IX, Mo+4	; point IY towards second odd 32bit word
	call	RS_MDS_Encode	; do the RS thang
	ld	de, S		; we're going to put the second word here
	ld	bc, 0004H	; going to copy four bytes...
	ldir			; copy into S

	;; at this point Me, Mo, and S are valid

	ld	hl, K		; get ready to compute expanded keywords
	ld	a, 00H		; start count at zero
	
SubKeyLoop:	
	push	hl		; save location of extended keywords
	push	af		; save count
	ld	IX,ASbKey	; load location of A
	dup4	IX		; duplicate accumulator into A
	
	ld	IY,Me		; load even keyword
	call	f32		; run the permutation

	pop	af		; pop off the count
	inc	a		; increment the count 
	push	af		; save count again
	ld	IX,BsbKey	; load location of B
	dup4	IX		; duplicate accum into B 
	ld	IY,Mo		; load odd keyword (KEY[4]to[7])
	call	f32		; do the permutation

	ld	b,08H
	call	rol32		; rotate B around 8 bits left

	ld	IY,ASbKey	; load A's address
	
	add4MEM	ASbKey,BSbKey	; Do PHT
	add4MEM	BSbKey,ASbKey
		
	ld	b,9
	call	rol32		; rotate B around 9 bits left

	pop	af		; grab the count again
	pop	hl		; grab location of key again (was clobbered)
	copy4HL	IY		; copy into expanded keywords (increments HL)
	copy4HL	IX		; copy second word
	
	inc	a		; increment our count

	cp	40		; are we done yet? (Note: too far to use djnz)
	jp	nz,SubKeyLoop	; loop if we're not
	
	ret			; and we're done


;;; =========================================================================
;;;	MakeTable -- precomputes lookup table for full keying
;;;	Args:  Assumes KeySetup has already been called
;;;	Result:  Si_ROWj[k] contains the output of sbox i multiplied by the 
;;;		 appropriate MDS value for row j on input k.  The final MDS 
;;;		 addition (4 byte-wise XORs) is computed in the round function.
;;;	Clobbers:  All registers, Si_ROWj for 0<=i<=3, 1<=j<=4
;;; =========================================================================
;;;	Note that sboxes are numbered from 0 to 3 and rows from 1 to 4.  Also
;;;	this full keying version relies on the fact that each Si's ROW
;;;	arrays are aligned on 256 byte frames.

MakeTable:	
				
	ld	de,0000H	; clear out DE, we use e as the count and
				;  input value for the sboxes
TblLp:	
	;; This loop runs 256 times and each iteration fills in SBOX arrays
	;;   with the appropriate output given the count as input.  Only the
	;;   code for filling SBOX0's arrays is commented.  The code to fill
	;;   the other SBOXs' arrays is run in parallel and differs only in the
	;;   value of multiplication and desintaion of output.  Looking back, I
	;;   should have made this a macro...

	ld	hl,S+4         ; Setup XOR material
	ld	b,(hl)	       ; put first byte to XOR in B
	ld	hl,S
	ld	c,(hl)	       ; and the second XOR byte into C
	push	de	       ; save our current count and input
	call	FeedS0	       ; feed value through the sbox
	pop	de	       ; get out count and input back

	ld	hl,S0_ROW1     ; location to stick output
	add	hl,de	       ; find offset into array
	ld	(hl),a	       ; store result into array (multiply by 01)

	push	de	       ; save count/input
	ld	hl,tab5B       ; get ready to do multiplication by 5B
	ld	e,a	       ; move output of sbox into e to use de as offset
	add	hl,de	       ; find offset into table
	ex	af,af'	       ; save a (the output of sbox 0)
	ld	a,(hl)	       ; load result of multiply
	pop	de	       ; get our count/input back
	push	de	       ; save it again
	ld	hl,S0_ROW2     ; laod loction of output
	add	hl,de	       ; find offset into array
	ld	(hl),a	       ; store result of sbox and multiply by 5B

	ex	af,af'	       ; retreive the sbox output
	ld	hl,tabEF       ; get ready to multiply by EF
	ld	e,a	       ; put sbox output into e to offset into tabEF
	add	hl,de	       ; calculate the offset
	ld	a,(hl)	       ; grab result of the multiply
	ld	hl,S0_ROW3     ; both ROW3 and ROW4 are multiplied by EF so...
	pop	de	       ; get back input value
	push	de	       ; save it again
	add	hl,de	       ; offset into ROW3
	ld	(hl),a	       ; store value
	ld	hl,S0_ROW4     ; ROW4 is also multiplied by EF so...
	add	hl,de	       ; find offset
	ld	(hl),a	       ; and store value
		
	;; Done with sbox zero	

	ld	hl,S+5		; Setup sbox 1 and continue...
	ld	b,(hl)
	ld	hl,S+1
	ld	c,(hl)
	call	FeedS1
	pop	de

	ld	hl,S1_ROW4	
	add	hl,de
	ld	(hl),a

	push	de
	ld	hl,tab5B
	ld	e,a
	add	hl,de
	ex	af,af'
	ld	a,(hl)
	pop	de
	push	de
	ld	hl,S1_ROW3
	add	hl,de
	ld	(hl),a

	ex	af,af'
	ld	hl,tabEF
	ld	e,a
	add	hl,de
	ld	a,(hl)
	ld	hl,S1_ROW1
	pop	de
	push	de
	add	hl,de
	ld	(hl),a
	ld	hl,S1_ROW2
	add	hl,de
	ld	(hl),a		

	;; Done with sbox one

	ld	hl,S+6		; Setup sbox 2 and continue...
	ld	b,(hl)
	ld	hl,S+2
	ld	c,(hl)
	call	FeedS2
	pop	de

	ld	hl,S2_ROW3	
	add	hl,de
	ld	(hl),a

	push	de
	ld	hl,tab5B
	ld	e,a
	add	hl,de
	ex	af,af'
	ld	a,(hl)
	pop	de
	push	de
	ld	hl,S2_ROW1
	add	hl,de
	ld	(hl),a

	ex	af,af'
	ld	hl,tabEF
	ld	e,a
	add	hl,de
	ld	a,(hl)
	ld	hl,S2_ROW2
	pop	de
	push	de
	add	hl,de
	ld	(hl),a
	ld	hl,S2_ROW4
	add	hl,de
	ld	(hl),a		

	;; Done with sbox 2	

	ld	hl,S+7		; Setup sbox 3 and do it...
	ld	b,(hl)
	ld	hl,S+3
	ld	c,(hl)
	call	FeedS3
	pop	de

	ld	hl,S3_ROW2	
	add	hl,de
	ld	(hl),a

	push	de
	ld	hl,tabEF
	ld	e,a
	add	hl,de
	ex	af,af'
	ld	a,(hl)
	pop	de
	push	de
	ld	hl,S3_ROW3
	add	hl,de
	ld	(hl),a

	ex	af,af'
	ld	hl,tab5B
	ld	e,a
	add	hl,de
	ld	a,(hl)
	ld	hl,S3_ROW1
	pop	de
	add	hl,de
	ld	(hl),a
	ld	hl,S3_ROW4
	add	hl,de
	ld	(hl),a		

	;; Done with sbox 3

	;; Finished filling in values for all SBOXs and ROWS for input e

	inc	e		      ; Increment out count...
	jp	nz,TblLp	      ; if not done, loop again
	
	ret
	
;;; ==========================================================================
;;;	EncryptBlock		(FULL KEYING, ECB VERSION)
;;;	Args:  None
;;;	Result:	 128 bit block of text at MyText is encrypted
;;;	Clobbers:  Everything
;;; ==========================================================================

EncryptBlock:	

	xor16	MyText,K	; input whitening

	ld	b,16		; number of rounds
	exx			; swap them out for later use (only 4 Tstates)

	ld	hl, K+32	; load location of keywords K8 to K39
	push	hl		; push it on the stack
	
Encrypt:			; actual encryption loop

	RoundFunc		; do a round
	 
	pop	hl		; pop our location in the keywords
	add4HL	RESULT1		; add keyword to RESULT1	
	add4HL	RESULT2		; add keyword to RESULT2
	push	hl		; push our location in the keywords

	ld	de,MyText+8	; get ready XOR first output word
	ld	hl,RESULT1	; where it is
	xor4HL			; xor RESULT1 with 1st word in right half

	; now go to spare registers so we can use HL again after rotations
	; just experimenting :)

	exx			
				; looking at word as little-endian
	ld	hl,MyText+11	; start with last byte in word
	rr	(hl)		; rotate it right, xor unsets CF so no worries
	dec	l		; rotate other bytes around...
	rr	(hl)
	dec	l
	rr	(hl)
	dec	l
	rr	(hl)
	jp	nc,NoCry1	; did we rotate out a 1? If so...
	ld	hl,MyText+11	; we need to rotate it back in
	set	7,(hl)
	ccf
NoCry1:	
	ld	hl,MyText+12	; now to rotate the second word left
	rl	(hl)		
	inc	l
	rl	(hl)
	inc	l
	rl	(hl)
	inc	l
	rl	(hl)
	jp	nc,NoCry2	; again, check carry flag 
	ld	hl,MyText+12	; and set the bit if necessary
	set	0,(hl)
NoCry2:	exx			; go back to our other registers

	xor4HL			; XOR result2 into 2nd word 

	SwapText	MyText,MyText+8	; do the swap

	exx			; get round info back
	dec	b		; decrement b
	exx			; swap back out (no flags affected)

	jp	nz,Encrypt	; are we done?  if not, loop again

	SwapText	MyText,MyText+8	; undo the last swap

	xor16	MyText,K+16	; output whitening

	pop	hl		; pop hl to keep stack aligned
	ret


;;; ==========================================================================
;;;	DecryptBlock
;;;	Args:  None
;;;	Result:	 128 bit block of text at MyText is decrypted
;;;	Clobbers:  Everything
;;; ==========================================================================

DecryptBlock:	
	xor16	MyText,K+16	; input whitening
	
	ld	b, 16		; number of rounds
	exx			; swap out for later use (only 4 Tstates)

	ld	hl, K+152	; load location of keywords K8 to K39
	push	hl		; push it on the stack
	
Decrypt:			; actual encryption loop

	RoundFunc		; do a round
	
	pop	hl		; pop off our location in keywords
	add4HL	RESULT1		; add keywords, remember HL is incremented
	add4HL	RESULT2
	ld	de, 65520	; simulate subtraction by 16
	add	hl,de
	push	hl		; push on location of next keywords to use

	jp	nc, Nocry3	; ensure carry flag is unset.  This was a 
	ccf			;   gotcha because its set in the add above
NoCry3:	ld	hl,MyText+8	; rotate byte around 1 bit left
	rl	(hl)
	inc	l
	rl	(hl)
	inc	l
	rl	(hl)
	inc	l
	rl	(hl)
	jp	nc,NoCry4	; again, make sure everythings OK with carry
	ld	hl,MyText+8
	set	0,(hl)
NoCry4:

	ld	hl, RESULT1	; get ready to XOR output into text
	ld	de, MyText+8
	xor4HL			; do both XORs right away
	xor4HL

	ld	hl,MyText+15	; now rotate the other word around 1 bit right
	rr	(hl)
	dec	l
	rr	(hl)
	dec	l
	rr	(hl)
	dec	l
	rr	(hl)
	jp	nc,NoCry5
	ld	hl,MyText+15
	set	7,(hl)
NoCry5:	

	SwapText	MyText,MyText+8	; do the swap

	exx			; get round info back
	dec	b		; decrement b
	exx			; swap back out (no flags affected)

	jp	nz,Decrypt	; are we done?  if not, loop again

	SwapText	MyText,MyText+8	; undo the last swap

	xor16	MyText,K	; output whitening

	pop	hl		; pop hl to keep stack aligned
	ret

	
;;; ==========================================================================
;;;	RS_MDS_Encode
;;;	Args:  IX points to first 32 bit keyword, IY to the second
;;;	Result:	 HL points to resulting byte (stored in TEMP32_1)
;;;	Clobbers:  TEMP32_1, AFBCDEHL
;;; ==========================================================================
;;;	Note everything is sepecific to 128 bits 

RS_MDS_Encode:
	ld	de, TEMP32_1	; 32 bits to play with
	clear32	TEMP32_1
	push	ix
	push	ix
	pop	hl		; get ready to copy
	ld	bc, 0004H	; four bytes to move
	ldir			; do it
	ld	ix, TEMP32_1	; point ix towards memory
	ld	b, 04H		; get ready to do Reed-Solomon
RSlp1:	push	bc
	call	RS_Rem		; do it
	pop	bc
	djnz	RSlp1		; loop until done with that block
	xor4	ix,iy		; xor second keyword into result of first
	ld	b, 04H		; get ready to do it again
RSlp2:	push	bc
	call	RS_rem		; do it
	pop	bc
	djnz	RSlp2		; loop until done with final block
	ld	hl, TEMP32_1	; put address of result in HL
	pop	ix		; restore ix's value
	ret
	
;;; ==========================================================================
;;; 	RS_Rem
;;;	Args:  IX points to low byte of 32 bit word
;;;	Result:	  RS remainder data into mem IX points to
;;;     Clobbers:  AFBCD
;;; ==========================================================================
	
RS_Rem:	
	ld	a, (ix + 3)	; load high byte into accumulator
	sla	a		; shift one bit left
	jp	nc, RSisz	; if (A & 80H), do XOR
	xor	4DH		; xor with the generator
RSisz:	ld	b,a		; store value in b
	ld	a, (ix + 3)	; reload high byte
	srl	a		; shift right one bit
	and	7FH		; mask it
	bit	0, (ix + 3)	; was its lowest bit set?
	jp	z,RSisz2	; skip xor if it is
	xor	0A6H		; xor the generator right shifted one
RSisz2:	xor	b		; xor with previous result
	ld	c,a		; store result in c
	ld	d, (ix + 3)	; grab hi byte again hold onto it for a sec
	sl32	IX,8		; shift IX left eight
	ld	a, (ix+3)	; grab new hi byte
	xor	c		; xor g3 into it
	ld	(ix+3),a	; store back
	ld	a, (ix+2)	; grab second highest byte
	xor	b		; xor g2 into it
	ld	(ix+2),a	; store byte back
	ld	a, (ix+1)	; grab next byte
	xor	c		; g3 again
	ld	(ix+1), a	; store back
	ld	(ix+0),d	; store d back
	ret		

		
;;; ==========================================================================
;;;	f32  -- the full 32 bit permutation, include MDS (but not PHT)
;;;	Args:  IX points to input 32 bit word, IY to L
;;;	Result:  result of operation overwrites mem IX points to
;;;	Clobbers:  ADEHL, TEMP32_1
;;; ==========================================================================
;;; This is one of those places this implementation is redundant.  I should
;;; really only have ONE set of MDS multiply routines and use it everywhere.
;;; This is the code used by key setup. 

f32:
	DoSBoxes	TEMP32_1,IX,IY    ; the result goes into TEMP32_1
	push	IY			  ; be nice and save IY for keysetup
	ld	iy, TEMP32_1
	call	Full_MDS_Mult		  ; multiply by MDS matrix
	pop	IY
	ret


;;; ==========================================================================
;;;	Full_MDS_mult -- full MDS matrix multiplication... SLOW
;;;	Args: IY = input, IX = output
;;;	Clobbers: ADEHL
;;; ==========================================================================
;;;	There should be a macro for rowwise multiply!  This is about the 
;;;	slowest and most lengthy way to do it.  But its straightforward and
;;;	easy to see what I'm doing.  
	
Full_MDS_Mult:			; IY=input, IX=output
	ld	a, (IY+0)	; get first byte
	ld	hl,tabEF	; get EF table
	ld	d, 00H		; clear out d
	ld	e, (IY+1)	; grab second byte
	add	hl, de		; offset into EF table
	xor	(hl)		; xor result of multiply
	ld	hl, tab5B	; address of 5B table
	ld	e, (IY+2)	; third byte
	add	hl, de		; offset into table
	xor	(hl)		; xor result into a
	sbc	hl, de		; remove offset
	ld	e, (iY + 3)	; final byte
	add	hl, de		; calc offset
	xor	(hl)		; final xor
	ld	(IX+0),a	; store result

	ld	a, (iY+3)	; get the byte multiplied by 01
	ld	hl, tabEF	; do EF mults first
	ld	e, (iY+2)	; get byte
	add	hl, de		; calc offset
	xor	(hl)		; xor with table value
	sbc	hl, de		; remove offset
	ld	e, (iy+1)	; next value
	add	hl, de		; calc offset
	xor	(hl)		; do xor
	ld	hl, tab5B	; the 5b table
	ld	e, (IY+0)	; final (first) byte
	add	hl, de		; calc offset
	xor	(hl)		; final xor
	ld	(ix+1),a	; store second result

	ld	a, (iy+2)	; the 01 element
	sbc	hl, de		; get tab5b again
	ld	e, (iy+1)	; get 5b element
	add	hl, de		; calc offset
	xor	(hl)		; do xor
	ld	hl, tabEF	; now for the EF mults
	ld	e, (iy+0)	; first one
	add	hl, de		; offset
	xor	(hl)		; do xor
	sbc	hl, de		; undo offsetting
	ld	e, (iy+3)	; last one
	add	hl, de		; calc offset
	xor	(hl)		; final xor
	ld	(ix+2), a	; store result

	ld	a, (iy+1)	; 01 element
	sbc	hl, de		; undo last offset
	ld	e, (iy+0)	; first EF multiply
	add	hl, de		; get offset
	xor	(hl)		; do xor
	sbc	hl, de		; undo offset
	ld	e, (iy+2)	; second EF multiplyu
	add	hl, de		; calc offset
	xor	(hl)		; do xor
	ld	hl, tab5B	; other table
	ld	e, (iy+3)	; byte to multiply
	add	hl, de		; offset
	xor	(hl)		; do it
	ld	(ix+3),a	; store final value

	ret


;;; ==========================================================================
;;;	rol32 -- rotate 32 bit quantity left
;;;	Args:  called with IX pointing to data to be rotated and 
;;;	       with B containing the number of bits to rotate
;;;	Result:	 data pointed to by IX rotated B bits left
;;;	Clobbers:  none
;;; ==========================================================================

rol32:			
rllp:		jp	nc,rlnocry	; assumes IX pts to low byte
		ccf			; if carry flag is set, reset it
rlnocry:	rl	(IX+0)		; rotate first byte
		rl	(IX+1)		; second
		rl	(IX+2)		; third
		rl	(IX+3)		; final
		jp	nc,rlbot	; done if we just rotated out a zero
		set	0,(IX+0)	; if a 1, stick it in low byte
rlbot:		djnz	rllp		; if not finished, loop again
		ret


;;; ==========================================================================
;;;	FeedSn -- run a byte through an Sbox
;;;	Args:  input byte in E
;;;	       first XOR material in B
;;;	       second XOR material in C
;;;	Result:	 result of operation in A
;;;	Clobbers:  ADHL
;;; ==========================================================================

FeedS0:
	ld	d,00H		; zero out d to be sure
	ld	hl,p0		; offset of table 0
	push	hl		
	add	hl,de		; get offset
	ld	a,(hl)		; load byte from first permutation table
	xor	b		; xor by first byte
	ld	e,a		; get ready to load from second
	pop	hl		; pop address of second
	add	hl,de		; find offset
	ld	a,(hl)		; load second permutation
	xor	c		; second XOR
	ld	e,a		; put result in e
	ld	hl,p1
	add	hl,de		; offset into table
	ld	a,(hl)		; final result
	ret

FeedS1:
	ld	hl,p0
	push	hl
	push	hl
	ld	hl,p1
	add	hl,de		; get offset
	ld	a,(hl)		; load byte from first permutation table
	xor	b		; xor by first byte
	ld	e,a		; get ready to load from second
	pop	hl		; pop address of second
	add	hl,de		; find offset
	ld	a,(hl)		; load second permutation
	xor	c		; second XOR
	ld	e,a		; put result in e
	pop	hl
	add	hl,de		; offset into table
	ld	a,(hl)		; final result
	ret

FeedS2:
	ld	hl,p1
	push	hl
	push	hl
	ld	hl,p0
	add	hl,de		; get offset
	ld	a,(hl)		; load byte from first permutation table
	xor	b		; xor by first byte
	ld	e,a		; get ready to load from second
	pop	hl		; pop address of second
	add	hl,de		; find offset
	ld	a,(hl)		; load second permutation
	xor	c		; second XOR
	ld	e,a		; put result in e
	pop	hl
	add	hl,de		; offset into table
	ld	a,(hl)		; final result
	ret

FeedS3:
	ld	hl,p1
	push	hl
	add	hl,de		; get offset
	ld	a,(hl)		; load byte from first permutation table
	xor	b		; xor by first byte
	ld	e,a		; get ready to load from second
	pop	hl		; pop address of second
	add	hl,de		; find offset
	ld	a,(hl)		; load second permutation
	xor	c		; second XOR
	ld	e,a		; put result in e
	ld	hl,p0
	add	hl,de		; offset into table
	ld	a,(hl)		; final result
	ret	



;;; =========================================================================
;;;	User code
;;; =========================================================================

ORG 3600H		

	;; for example:

	call	KeySetup
	call	MakeTable
	call	EncryptBlock
 	call	DecryptBlock	
	halt


	




		
