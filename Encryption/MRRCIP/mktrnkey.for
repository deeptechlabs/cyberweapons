      program trnkey

c   TRNKEY -- program to make a numerical version of a transpostion
c     key for use (most likely) in a (cryptographic) transposition
c     cipher.  The input is a character string.
c
c   The way this works is as follows:
c     The user inputs a character string containing any ASCII
c     characters.  The characters are mapped to upper-case and
c     any non-alphabetic characters are eliminated.
c     The letters in the resulting string are then numbered
c     alphabetically, with duplicate letters being numbered from
c     left to right.
c   For instance:
c     JOANN  yields the numerical sequence 2-5-1-3-4.
c     For classical cryptographic applications, 2-5-1-3-4 would be
c     the resultant numerical version of the key.
c     For computer applications, an "inverted" form of the key, with
c     the ordinal number of "1" first, the ordinal number of "2"
c     second, etc., might be more useful.
c
c   Written by Mark Riordan   27 September 1986

      integer nkeymx
      parameter(nkeymx=160)
      integer nkey,j,inew,iold,tint
      logical debug,qchng
      character key(nkeymx)*1,tchar
      integer numkey(nkeymx)

      debug = .false.
cc	write(*,9000)
cc9000	format(' Please input the key string:')
      read(*,8000,end=666) (key(j),j=1,nkeymx)
8000  format(160a)

      inew = 0
      do 120 iold = 1, nkeymx
	if(key(iold).ge.'a' .and. key(iold).le.'z') then
	  key(iold) = char(ichar(key(iold))-32)
	endif
	if(key(iold).ge.'A' .and. key(iold).le.'Z') then
	  inew = inew + 1
	  key(inew) = key(iold)
	endif
120   continue
      nkey = inew
      if(nkey .le. 0) then
	write(*,*) 'No legal key characters were input.'
	go to 999
      endif

      if(debug) then
	write(*,9200) (key(j),j=1,inew)
9200	format(' ',160a)
      endif

c   Create an array of ordinal positions.  The sorted version of
c   this array will be the numerical version of the key.
c   Initially, for this algorithm, we start out with 1-2-3-...
c   in this array.

      do 140 j = 1, nkey
	numkey(j) = j
140   continue

c   Sort the key characters, and drag their ordinal numbers along
c   to keep track of things.

160   continue
      qchng = .false.
	do 200 j = 1, nkey-1
	  if(key(j) .gt. key(j+1)) then
	    tchar = key(j)
	    key(j) = key(j+1)
	    key(j+1) = tchar
	    tint = numkey(j)
	    numkey(j) = numkey(j+1)
	    numkey(j+1) = tint
	    qchng = .true.
	  endif
200	continue
      if(qchng) go to 160

c   The key is now sorted.

      if(debug) then
	write(*,9220) (numkey(j), j=1,nkey)
9220	format(' Row #''s in ordinal order:',40i4)
      endif

cc	open(12,file='tordkey.txt')
cc	rewind 12
      write(*,9030) (numkey(j),j=1,nkey)
9030  format(40i4)

      goto 999
666   continue
	write(*,*) 'Premature end-of-file encountered.'
	go to 999

999   continue
      end
      end
