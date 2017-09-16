      program detran
      implicit logical(a-z)

c   Program to decipher using columnar transposition.
c   Input is on IN.TXT.  Maximum line length 80 characters.
c      Blanks are stripped from the input, but no other modifications
c      are made.
c   Output is on OUT.TXT.  No more than 80 total characters per line.
c   The key is on the file TORDKEY.TXT.  It is a series of numbers in
c      nI4 format.  The first number is the column number of the first
c      column to extract for the ciphertext, the second number specifies
c      the second column, etc.	Note that this is an "inverted" form
c      of the usual manner in which transposition keys are specified
c      for manual methods.
c
c   Written by Mark Riordan	1 October 1986

      integer nplain,nplamx,nlnmax,j,nkymax,lstrow
      parameter(nplamx=8000,nlnmax=80,nkymax=60)
      integer nchars,nkey,irow,ikey,icol,nrow,iline,curpos
      integer key(nkymax)
      logical qendky,goodch

      character*1 line(nlnmax),chars(nplamx)

c   Read in the keys.

      do 30 j = 1, nkymax
	key(j) = 0
30    continue
      open(11,file='tordkey.txt',status='old')
      read(11,8100,end=66,err=66) (key(j),j=1,nkymax)
8100  format(60i4)
      qendky = .false.
      nkey = 0
40    if(qendky) go to 80
	if(nkey .ge. nkymax) then
	  qendky = .true.
	else if(key(nkey+1) .ne. 0) then
	  nkey = nkey + 1
	else
	  qendky = .true.
	endif
      go to 40

c   Come here if there are problems with reading the key.

66    continue
      write(*,*) 'Problems with reading the key on TORDKEY.TXT.'
      stop

80    continue
      close(11)


c   Read in all of the ciphertext, to count the number of characters.

      open(11,file='in.txt',status='old')
      nchars = 0
100   continue
	read(11,8000,end=333) line
8000	format(80a)
	do 120 j = 1, nlnmax
	  if(line(j) .ne. ' ') then
	    nchars = nchars + 1
	  endif
120	continue
      go to 100

c   NCHARS is the number of characters in the ciphertext.
c   Read in the ciphertext into the array, immediately placing
c   each ciphertext character into successive positions down a
c   column.  Thus when we are done, the plaintext will simply be
c   the contents of the array CHARS.

333   continue
      rewind 11

      iline = 9999
      lstrow = nchars - (nchars/nkey)*nkey
      do 840 ikey = 1, nkey
	icol = key(ikey)
	curpos = icol

c   Compute NROW as the number of rows in this column.	This would
c   be a simple division of the total number of ciphertext characters
c   by the number of columns (= the number of numbers in the key)
c   if the transposition matrix were an exact rectangle.  However,
c   often the last row is not completely filled up.  So, the number
c   of characters in each column will be one of two different values,
c   which differ from each other by 1.
c   LSTROW is the number of characters in the last row.

	nrow = nchars/nkey
	if(icol .le. lstrow) nrow = nrow + 1
	do 820 irow = 1, nrow
	  iline = iline + 1
	  goodch = .false.

c   REPEAT - UNTIL loop which results in line(iline) being the
c   next non-blank character on input.	Reads a new line if necessary.

810	  continue
	    if(iline.gt.nlnmax) then
	      read(11,8000,end=666) line
	      iline = 1
	    endif
	    if(line(iline).eq.' ') then
	      iline = iline + 1
	    else
	      goodch = .true.
	    endif
	  if(.not. goodch) go to 810

c   Place this ciphertext character into the net spot in the
c   transposition matrix (the next row down in this column).

	  chars(curpos) = line(iline)
	  curpos = curpos + nkey
820	continue
840   continue
      go to 900

c   Premature EOF on input, second pass.

666   continue
      write(*,*) 'Internal error in DETRAN:'
      write(*,*) 'Premature EOF on input, second pass.'
      stop

c   The plain text now resides in LINE.  There are NLINE characters.

900   continue
      close(11)
      open(12,file='out.txt',status='unknown')
      rewind 12
      write(12,9400) (chars(j),j=1,nchars)
9400  format((1x,60a1))
      close(12)
      end
      end
