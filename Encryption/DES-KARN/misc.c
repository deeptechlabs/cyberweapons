/* Set block of memory to constant */
memset(blk,val,size)
register char *blk;
register char val;
register unsigned size;
{
	while(size-- != 0)
		*blk++ = val;
}

/* Copy block of memory */
memcpy(dest,src,size)
register char *dest,*src;
register unsigned size;
{
	while(size-- != 0)
		*dest++ = *src++;
}

/* Compare two blocks of memory */
memcmp(a,b,size)
register char *a,*b;
register unsigned size;
{
	while(size-- != 0)
		if(*a++ != *b++)
			return 1;
	return 0;
}

