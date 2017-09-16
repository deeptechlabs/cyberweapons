; Twofish vector #1
    ;Key Size:
	.byte	080h
    ;Key:
	.byte	000h,000h,000h,000h,000h,000h,000h,000h
	.byte	000h,000h,000h,000h,000h,000h,000h,000h
    ;Plaintext:
	.byte	000h,000h,000h,000h,000h,000h,000h,000h
	.byte	000h,000h,000h,000h,000h,000h,000h,000h
    ;Ciphertext:
	.byte	09Fh,058h,09Fh,05Ch,0F6h,012h,02Ch,032h
	.byte	0B6h,0BFh,0ECh,02Fh,02Ah,0E8h,0C3h,05Ah
;-------------------------------------------------------
; Twofish vector #2
    ;Key Size:
	.byte	080h
    ;Key:
	.byte	09Fh,058h,09Fh,05Ch,0F6h,012h,02Ch,032h
	.byte	0B6h,0BFh,0ECh,02Fh,02Ah,0E8h,0C3h,05Ah
    ;Plaintext:
	.byte	09Fh,058h,09Fh,05Ch,0F6h,012h,02Ch,032h
	.byte	0B6h,0BFh,0ECh,02Fh,02Ah,0E8h,0C3h,05Ah
    ;Ciphertext:
	.byte	01Bh,01Bh,018h,06Dh,0FEh,04Fh,01Fh,0C4h
	.byte	038h,05Bh,0C7h,06Fh,0F3h,0CAh,040h,027h
;-------------------------------------------------------
; Twofish vector #3
    ;Key Size:
	.byte	080h
    ;Key:
	.byte	084h,043h,087h,031h,008h,05Dh,033h,0F6h
	.byte	08Eh,0E4h,02Bh,040h,0D9h,022h,083h,07Dh
    ;Plaintext:
	.byte	01Bh,01Bh,018h,06Dh,0FEh,04Fh,01Fh,0C4h
	.byte	038h,05Bh,0C7h,06Fh,0F3h,0CAh,040h,027h
    ;Ciphertext:
	.byte	080h,01Dh,0AAh,023h,037h,0D8h,0DBh,039h
	.byte	05Bh,0ECh,0C2h,0A7h,055h,0C5h,0D0h,085h
;-------------------------------------------------------
; Twofish vector #4
    ;Key Size:
	.byte	080h
    ;Key:
	.byte	09Bh,006h,0B2h,04Eh,0C9h,097h,0C4h,0FDh
	.byte	063h,0B7h,005h,0C8h,0A6h,00Fh,090h,0A2h
    ;Plaintext:
	.byte	080h,01Dh,0AAh,023h,037h,0D8h,0DBh,039h
	.byte	05Bh,0ECh,0C2h,0A7h,055h,0C5h,0D0h,085h
    ;Ciphertext:
	.byte	05Bh,00Ah,052h,093h,001h,060h,055h,0D6h
	.byte	014h,04Ch,0E8h,038h,0A9h,0EFh,05Ah,0EBh
;-------------------------------------------------------

	.byte 0	;end of list
