# AWK program to find the average of a column of numbers.
# The average, excluding unreasonably large numbers, is
# also computed. 
#
# Mark Riordan   12 June 92

BEGIN {
	sum = sumsmall = n = nsmall = 0
	bigsmall = nbig = 0
}
{
	val = $1
	if(val < 1) {
		sumsmall += val
		nsmall++
		if(val > bigsmall) bigsmall = val
	} else {
		nbig++
	}
	sum += val
	n++
}

END {
	printf("Ave = %f  Ave of small = %f  Biggest small = %f  Nbig = %d\n",sum/n, sumsmall/nsmall,bigsmall,nbig)
}	
