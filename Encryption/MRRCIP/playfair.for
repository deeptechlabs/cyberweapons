      program playf
      implicit logical (a-z)

c   Program to implement the classic "Playfair" cipher.
c   The key, which is to be read into the square sequentially
c   into each row from left to right, contains 26 letters.
c   Throughout the cipher, all occurrences of J are changed
c   to I.
c
c   Plaintext on standard input;
c   Ciphertext on standard output.
c   Keyphrase prompted for on the console.
c
c   Written by Mark Riordan   24 October 1987


      integer alfsiz,gdchsz,linsiz,outsiz
      parameter(alfsiz=26,gdchsz=52,linsiz=80,outsiz=60)
      integer boxsiz,modp1
      parameter(boxsiz=25)
      character alf*(alfsiz)
      character keyphr*80,cipalf*(alfsiz)
      character*60 infl,outfl
      character*1 outc(outsiz)
      character boxstr*(boxsiz),boxary(5,5)
      equivalence(boxstr,boxary)

      character*1 ch,newch,pch1,pch2,doubch,cch1,cch2
      integer r1,r2,c1,c2
      integer newr1,newr2,newc1,newc2
      integer iadd,j,iout,jbox,i
      logical qeof,double,doit,encip

c   Query the user for key, encipher vs. decipher, and
c   input/output files.

cc    open(10,file='CON',status='UNKNOWN')
      write(*,9000)
9000  format(' Input the keyphrase:')
      read(*,8000) keyphr
8000  format(a)
80    continue
      write(*,9020)
9020  format(' Encipher (E) or Decipher (D) ?')
      read(*,8000) ch
      write(*,9030)
9030  format(' Input file (blank==terminal)?')
      read(*,8000) infl
      if(infl .eq. ' ') infl = 'con'
      write(*,9040)
9040  format(' Output file (blank==terminal)?')
      read(*,8000) outfl
      if(outfl .eq. ' ') outfl = 'con'

      open(1,file=infl,status='UNKNOWN')
      open(2,file=outfl,status='UNKNOWN')

      if(ch.eq.'e' .or. ch.eq.'E') then
	iadd = 1
	encip = .true.
      else if(ch.eq.'d' .or. ch.eq.'D') then
	iadd = -1
	encip = .false.
      else
	go to 80
      endif

c   Make the cipher alphabet from the key phrase, and read it
c   into the box.  Eliminate the character "J".

      call mksmpl(keyphr,cipalf)
      jbox = 0
      do 120 j = 1, alfsiz
	if(cipalf(j:j) .ne. 'J') then
	  jbox = jbox + 1
	  boxstr(jbox:jbox) = cipalf(j:j)
	endif
120   continue
      write(*,9080) ((boxary(i,j),i=1,5),j=1,5)
9080  format(' box = ',5a1,4(/7x,5a1))

      qeof = .false.
      double = .false.
      doit = .true.
      iout = 0

c   Do this loop once for each pair of plaintext letters.

200   continue

c   If we were processing a doubled letter last time, then
c   now return the second of these doubled letters as the
c   first input character of the current pair.

	if(double) then
	  pch1 = doubch
	  double = .false.
	else
	  call getch(pch1,qeof)
	endif

c   If we reached a end of file on the first character,
c   then we have to decide whether we have any characters left
c   to process at all.	We do have one only if the last pair was
c   was a double letter, in which case the second letter this
c   time is a Q.

	if(qeof) then
	  if(double) then
	    pch2 = 'Q'
	  else
	    doit = .false.
	  endif
	else

c   Normal situation--no EOF, so get next character as second
c   plaintext character.
c   If EOF, set second plaintext to Q.
c   If first==second, then set second plaintext to Q, but
c   save the second letter for next time around.

	  call getch(pch2,qeof)
	  if(qeof) then
	    pch2 = 'Q'
	  else if(pch1 .eq. pch2) then
	    doubch = pch2
	    pch2 = 'Q'
	    double = .true.
	  endif
	endif

c   We now have pch1==first plaintext character and
c   pch2==second plaintext character.  Go ahead and do
c   the enciphering unless there was no input (doit==.false.)

	if(doit) then

c   Find the row and column of each of the two plaintext letters.

	  c1 = mod(index(boxstr,pch1)-1,5)+1
	  r1 = ((index(boxstr,pch1)-1)/5)+1
	  c2 = mod(index(boxstr,pch2)-1,5)+1
	  r2 = ((index(boxstr,pch2)-1)/5)+1

c   Now decide which of the three classic Playfair situations holds:
c   1.	Different row and column.
c   2.	Same row, different column.
c   3.	Same column, different row.

	  cch1 = boxary(c2,r1)
	  cch2 = boxary(c1,r2)
	  if(r1 .eq. r2) then
	    newc1 = modp1(c1+iadd,5)
	    cch1 = boxary(newc1,r1)
	    newc2 = modp1(c2+iadd,5)
	    cch2 = boxary(newc2,r2)
	  else if(c1 .eq. c2) then
	    newr1 = modp1(r1+iadd,5)
	    cch1 = boxary(c1,newr1)
	    newr2 = modp1(r2+iadd,5)
	    cch2 = boxary(c2,newr2)
	  endif

c   Ciphertext letters in cch1 and cch2.  Pack them into
c   the line "outc" and write the line if we fill it.

	  outc(iout+1) = cch1
	  outc(iout+2) = cch2
	  iout = iout + 2
	  if(iout .ge. outsiz) then
	    if(encip) then
	      write(2,9200) (outc(j),j=1,iout)
9200	      format(12(1x,5a1))
	    else
	      write(2,9210) (outc(j),j=1,iout)
9210	      format(1x,60a1)
	    endif
	    iout = 0
	  endif
cc	  write(*,*) pch1,pch2,' yields ',cch1,cch2,
cc   +	  '; r1,c1,r2,c2=',r1,c1,r2,c2
	endif

c   Loop until end-of-file.

      if(.not. qeof) go to 200

c   Flush the output line "outc" if there's anything in it.

	if(iout .gt. 0) then
	  if(encip) then
	    write(2,9200) (outc(j),j=1,iout)
	  else
	    write(2,9210) (outc(j),j=1,iout)
	  endif
	  iout = 0
	endif
      end
      subroutine getch(ch,qeof)

c   Return one character from the standard input.

      character ch*1
      logical qeof

      integer gdchsz
      parameter(gdchsz=52)
      integer linsiz
      parameter (linsiz=80)
      logical qdig
      integer wchdig,idgch

      character gdinch*(gdchsz)
      character gdtrn*(gdchsz)
      character line*(linsiz),tch*1
      character nums*10
      character*6 alfdig(10)

      data gdinch/
     +	'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'/
      data gdtrn/
     +	'ABCDEFGHIIKLMNOPQRSTUVWXYZABCDEFGHIIKLMNOPQRSTUVWXYZ'/
      data nums/'0123456789'/
      data alfdig/'ZERO','ONE','TWO','THREE','FOUR','FIVE','SIX',
     + 'SEVEN','EIGHT','NINE'/
      data iptr/999/

100   continue

c   If we are processing a previously-entered digit, return
c   the next letter of the spelled-out word version of the digit.
c   But if this character is a blank, we're at the end of the
c   word, so signal the end of this digit and go on to processing
c   the next character of input.

	if(qdig) then
	  idgch = idgch + 1
	  ch = alfdig(wchdig)(idgch:idgch)
	  if(ch .eq. ' ') then
	    qdig = .false.
	  else
	    go to 999
	  endif
	endif

c   Get the next character in the line.

	iptr = iptr + 1
	if(iptr .gt. linsiz) then
	  read(1,8000,end=666) line
8000	  format(a)
	  iptr = 1
	endif
	tch = line(iptr:iptr)

c   Check to make sure it's a legal input character.  If so,
c   translate it and return it.

	idx = index(gdinch,tch)
	if(idx .ne. 0) then
	  ch = gdtrn(idx:idx)
	else

c   Not an alphabetic character.  Is it a digit?
c   If so, set up flags and then return the first letter of
c   the spelled-out version of the digit.

	  wchdig = index(nums,tch)
	  if(wchdig .ne. 0) then
	    qdig = .true.
	    idgch = 1
	    ch = alfdig(wchdig)(idgch:idgch)
	  else
	    go to 100
	  endif
	endif
      go to 999

666   continue
      qeof = .true.
999   continue
cc    write(*,*) 'getch returns ',ch,' qeof=',qeof
      return
      end
      subroutine mksmpl(line,outalf)

c   MKSMKY -- Make a simple-style (substitution) cipher alphabet.
c
c     entry   line    is an input keyphrase
c
c     exit    outalf  is the output key--the 26 letters
c		      of the alphabet in the order prescribed
c		      by the key.
c		      This is simply the input keyphrase, with
c		      duplicates removed, followed by the rest
c		      of the alphabet.

      character line*(*),outalf*(*)

      integer alfsiz,gdchsz,linsiz
      parameter(alfsiz=26,gdchsz=52,linsiz=80)
      character gdinch*(gdchsz)
      character ch*1,newch*1
      character gdtrn*(gdchsz),alf*(alfsiz)

      gdinch = 'abcdefghijklmnopqrstuvwxyz'//
     +	       'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
      gdtrn  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'//
     +	       'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
      alf    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


      jin = 0
      jout = 0

c   Go through this loop once for each input character.

100   continue
	jin = jin + 1
	ch = line(jin:jin)
	jidx = index(gdinch,ch)

c   This key character is legal.  Check to see if it is already
c   in the output key being generated.

	if(jidx .gt. 0) then
	  newch = gdtrn(jidx:jidx)
	  if(index(outalf,newch).eq.0) then
	    jout = jout + 1
	    outalf(jout:jout) = newch
	  endif
	endif
      if(jin .lt. linsiz) go to 100

c   The input key phrase, minus duplicate characters, has been
c   copied to outalf.  Now copy the rest of the alphabet.

      do 200 jch = 1, alfsiz
	ch = alf(jch:jch)
	if(index(outalf,ch) .eq. 0) then
	  jout = jout + 1
	  outalf(jout:jout) = ch
	endif
200   continue
      end
      integer function modp1(num,modx)
      implicit logical(a-z)

c   MODP1 -- Compute "num" modulus "modx", except return
c   the result in the range 1:modx, rather than 0:(modx-1).
c   Also, negative results are adjusted to be in this range.

      integer num,modx
      integer ires

      ires = num - (num/modx)*modx
100   continue
      if(ires .le. 0) then
	ires = ires + modx
	go to 100
      endif
      modp1 = ires
      end
      end
