; args: buf, longs

	section code

	xdef	_byteReverse
_byteReverse:
	move.l	4(sp),a0
	move.w	10(sp),d0
	subq.w	#1,d0
revloop:
	move.l	(a0),d1
	ror.w	#8,d1
	swap	d1
	ror.w	#8,d1
	move.l	d1,(a0)+

	dbra	d0,revloop
	
	rts

	end
