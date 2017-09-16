/* by Peter K. Boucher */

============== C CODE FRAGMENT START =====================

/* !!!!!!!!!!!!!!!!!! THESE TWO MUST MATCH !!!!!!!!!!!!!!!!!!! */
#define N     1024 /* THESE TWO MUST MATCH !!!!!!!!!!!!!!!!!!! */
#define SQRTN 32.0 /* THESE TWO MUST MATCH !!!!!!!!!!!!!!!!!!! */
/* !!!!!!!!!!!!!!!!!! THESE TWO MUST MATCH !!!!!!!!!!!!!!!!!!! */

#define NUM_LONGS 4294967296.0
#define F(x) (((double)(x))/NUM_LONGS) /* probability that a
random */
                                       /* unsigned long is less
than*/
                                       /* x.                      
 */

double
long_Kplus_1024(X)
unsigned long *X;
{
    double max = 0.0;
    double tmp;
    long j;

    for (j=0L; j<N; j++) {
        tmp = ((double)(j+1))/((double)(N)) - F(X[j]);
        if (max < tmp) {
            max = tmp;
        }
    }
    return(max * SQRTN);
}

============== C CODE FRAGMENT END =======================

I also calculate K-1024, but with the subtraction parameters
as follows: 

============== C CODE FRAGMENT START =====================

        tmp = F(X[j]) - ((double)(j))/((double)(N));

============== C CODE FRAGMENT END =======================

I repeat these 8K times, so that I've analyzed 32M of output
(8M unsigned longs).  Then I calculate K+8192 and K-8192 for
the saved K+1024's and K-1024's.  As follows:

============== C CODE FRAGMENT START =====================

#define Fk(x) (1.0 - exp(-2.0*(x)*(x)))/* probability that a
random */
                                       /* K+1024 or K-1024 is
less  */
                                       /* than x.                 
 */
double
float_Kplus_8192(X)
double *X;
{
    double max = 0.0;
    double tmp;
    long j;

    for (j=0L; j<NUM_BUFS; j++) {
        tmp = ((double)(j+1))/num_bufs - Fk(X[j]);
        if (max < tmp) {
            max = tmp;
        }
    }
    return(max * sqrt(num_bufs));
}

============== C CODE FRAGMENT END =======================

Finally, I split the K+1024's and K-1024's into 1024 groups
of equally likely probability and did a chi-square, as follows:

============== C CODE FRAGMENT START =====================

int
chi_ks(K)
double *K;
{
/* chi-square table for 1023 degrees of freedom */
#define C99 920.56
#define C95 949.94
#define C75 992.10
#define C50 1022.33
#define C25 1053.17
#define C05 1098.31
#define C01 1131.34

    static double cnt[1024];
    double V = 0.0, divisor = num_bufs/1024.0;
    int i, score = 0;

    for (i=0; i<1024; i++) {
        cnt[i] = 0.0;
    }
    for (i=0; i<NUM_BUFS; i++) {
        cnt[((int)(1023.0*Fk(K[i])))]++;
    }
    for (i=0; i<1024; i++) {
        V += (cnt[i]*cnt[i])/divisor;
    }
    if ((V -= num_bufs) < C75) {
        score--;
        if (V < C95) {
            score--;
            if (V < C99) {
                score--;
            }
        }
    } else if (V > C25) {
        score++;
        if (V > C05) {
            score++;
            if (V > C01) {
                score++;
            }
        }
    }
    return(score); /*  3  means V was way too hi (non-uniform) */
                   /*  2 means V was suspiciously too hi */
                   /*  1 means V was slightly too hi */
                   /*  0 means V was neither too hi nor too low
*/
                   /* -1 means V was slightly too low */
                   /* -2 means V was suspiciously too low */
                   /* -3 means V was way too low (overly uniform)
*/
}
