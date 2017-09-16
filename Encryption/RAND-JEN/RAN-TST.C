/*
----------------------------------------------------------------------
By Bob Jenkins, 1994, a tester of random number generators.
I don't mind if you use it, but it is unsupported.

Run chi-square tests on a random number generator rng_test().
  uni -- are values uniform; do they occur equally often
  gap -- are the gaps between values of the expected lengths
  run -- how long are strictly increasing subsequences
  mau -- for each value, multiply lengths of all the gaps
  occ -- occurance test, in a sample of OSIZE values, how many values
				 occur exactly i times
Run each test on a number of different types of values
  norm - the values produced by the rng
  corr - values constructed from the low-order bit of a group of
	 consecutive normal values
  jump - make up your own values

Expected distributions and results are estimated; see chisquare().
This means you can write and modify tests and values without knowing
the expected distributions or the expected chi^2 results.

Instructions: If "get" is close to "expect", then the tests pass.  
  Reduce ALPHA, OMEGA until the tests blatently fail.  Increase
	MYRUNS until the tests fail.  Why do the tests fail?
  Change the constants, change the RNG, change the values and tests,
	recompile and rerun.  flow_allo() chooses which tests to run.
----------------------------------------------------------------------
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef  unsigned      char u1;   /* u1 is unsigned, 1 byte  */
typedef  unsigned long int  u4;   /* u4 is unsigned, 4 bytes */


/*
----------------------------------------------------------------------
Constants for controlling all the tests
----------------------------------------------------------------------
*/
#define ALPHA 4                           /* arrays of size 2^alpha */
#define OMEGA 24          /* omega bits per value in internal state */
#define OMICRON 3                /* number of bits in values tested */
#define CORRBIT 0x1            /* which bits to use for corr values */
#define SHIFT 2                            /* amount of barrelshift */
#define CHILEN ((u4)16)    /* chisquare ignores counts smaller than */
#define SIZE  ((u4)1<<ALPHA)       /* how many results rng produces */
#define WSIZE ((u4)1<<OMEGA)   /* range of values in internal state */
#define USIZE ((u4)1<<OMICRON)              /* # values in uni test */
#define GSIZE (SIZE<<1)                     /* # values in gap test */
#define RSIZE ((u4)8)             /* maximum run length to look for */
#define OSIZE (SIZE<<1)            /* sample size in occurance test */
#define MASK  (SIZE-1)         /* x&MASK is a valid index into mm[] */
#define WMASK (WSIZE-1)  /* y&WMASK is a valid internal state value */
#define UMASK (USIZE-1)                /* z&UMASK is a valid result */
#define NNN   ((u4)256)   /* Analog to SIZE, but for good generator */
#define MYRUNS (((u4)1)<<16)           /* how long to run the tests */


/*
----------------------------------------------------------------------
Declaration -- Random number generators
The test and control generators are expected to fill rr[]
with SIZE values ranging from 0..UMASK.  The values in mm[] should
range from 0..WMASK.
----------------------------------------------------------------------
*/

struct rng
{
  u4   id;    /* type of rng, offset into rnglist */
  u4  *mm;    /* secret memory */
  u4  *rr;    /* public results */
  u4  *ss;    /* other results */
  u4   a;     /* accumulator */
  u4   b;     /* other state */
  u4   c;     /* yet more state */
  u4   count; /* how many values in rr have been used */
};
typedef  struct rng  rng;

struct rngdef
{
  void  (*pass)(/* rng *r1, rng *r2 */);/* refill rr in r1 */
  u4      alen;                    /* length of array */
  u4      wlen;                    /* number of bits per result */
}; 
typedef  struct rngdef  rngdef;

static void    rng_good(/* rng *r1, rng *r2 */);
static void    rng_test(/* rng *r1, rng *r2 */);
static void    rng_ctrl(/* rng *r1, rng *r2 */);
static rng    *rng_allo(/* u4 id */);
static void    rng_free(/* rng *r */);

rngdef rnglist[] = {
#define RNGGOOD 0  /* RNG which produces results known to be good */
  {rng_good, NNN,  32},
#define RNGTEST 1  /* RNG being tested */
  {rng_test, SIZE, OMICRON},
#define RNGCTRL 2  /* control RNG */
  {rng_ctrl, SIZE, OMICRON},
};


/*
----------------------------------------------------------------------
Declaration -- Different types of values
Values do not have to be uniformly distributed, but there do have to
be SIZE of them, and they have to be in 0..UMASK.
----------------------------------------------------------------------
*/

struct val
{
  u4  id;            /* type of value, offset into vallist */
  u4 *arr;           /* array of SIZE values, allocated at creation */
  u4 *rr;            /* array of SIZE values fed to tests, not allocated */
  u4  vc;            /* count of values currently filled in array */
  u4  bc;            /* bit count, used in constructing current value */
  struct val *next;  /* next values to collect */
  union test *test;  /* list of tests to run on these values */
};
typedef  struct val  val;

struct valdef
{
  char   name[5];                       /* 4-letter value name */
  void (*pass)(/* val *v, rng *r */);   /* use results to build values */
};
typedef  struct valdef  valdef;

static val    *val_init(/* val *v, rng *r */);
static void    val_norm(/* val *v, rng *r, u4 use */);
static void    val_corr(/* val *v, rng *r, u4 use */);
static void    val_jump(/* val *v, rng *r, u4 use */);

valdef vallist[] = {
#define VALNORM 0    /* raw values */
  { "norm", val_norm },
#define VALCORR 1    /* CORRBIT-th bits of sets of OMICRON values */
  { "corr", val_corr },
#define VALJUMP 2    /* every JUMPth value */
  { "jump", val_jump },
#define VALLAST 3    /* number of values */
};


/*
----------------------------------------------------------------------
Declaration -- Tests for measuring randomness

It is common for all groups of SIZE consecutive values to be equally
likely (when the internal state can by any group of SIZE consecutive
values), but groups bigger than that are not equally likely.  In this
case, tests will never fail unless they measure events that depend on
values further apart than SIZE.  This can be done by the tests, or by
constructing values which compress or mix the rng's normal values.
----------------------------------------------------------------------
*/

struct testall
{
  u4           id;        /* type of test, offset into testlist */
  u4          *event;     /* array of counts, to be fed to chi^2 */
  u4           count;     /* every test seems to need a counter */
  double       expect;    /* expected result of chi^2 test */
  u4           display;   /* how to display the results */
  u4           estchi;    /* should we use estimate chi with the good test? */
#define TDNONE  0     /* don't display per-value results */
#define TDNORM  1     /* normalize so expected rsl is 1.0 */
#define TDTEST  2     /* actual counts from the test rng */
#define TDCTRL  3     /* actual counts from the control rng */
  union test  *next;      /* next test to run */
};
typedef  struct testall  testall;

struct testgap   /* count of number of gaps of given length */
{
  testall  all;
  u4       last[USIZE]; /* count when value was last seen */
};
typedef  struct testgap  testgap;

struct testrun   /* lengths of strictly increasing subsequences */
{
  testall  all;
  u4       last;        /* last value seen */
};
typedef  struct testrun  testrun;

struct testmau   /* for each value, product of all gaps */
{
  testall  all;
  double   devent[USIZE]; /* product of all gaps seen so far */
  u4       last[USIZE];   /* count when value was last seen */
};
typedef  struct testmau  testmau;

struct testocc   /* how many values occur n times in an interval */
{
  testall  all;
  u4       vcount[USIZE];   /* how many times each value appears */
  u4       rold[OSIZE];     /* old values from v->rr */
};
typedef  struct testocc  testocc;

union test
{
  testall  all;
  testgap  gap;
  testrun  run;
  testmau  mau;
  testocc  occ;
};
typedef  union test  test;

struct testdef   /* This assumes mm[SIZE] and OMICRON bits per result */
{
  u4       len;                          /* length of event array */
  char     name[4];                      /* 3-character test name */
  void   (*init)(/* test *t */);         /* initialize the test */
  void   (*pass)(/* test *t, val *v */); /* run stats on SIZE results */
  void   (*wrap)(/* test *t */);         /* polish stats if need be */
};
typedef  struct testdef  testdef;

static test *test_allo(/* u4 id */);
static void  test_init(/* test *t */);
static void  test_mini(/* test *t */);
static void  test_gini(/* test *t */);
static void  test_pini(/* test *t */);
static void  test_uni (/* test *t, val *v */);
static void  test_gap (/* test *t, val *v */);
static void  test_run (/* test *t, val *v */);
static void  test_mau (/* test *t, val *v */);
static void  test_occ (/* test *t, val *v */);
static void  test_wrap(/* test *t */);
static void  test_mwra(/* test *t */);
static void  test_free(/* test *t */);

testdef testlist[] = {
#define TESTUNI 0   /* number of occurances of each value */
  { USIZE, "uni", test_init, test_uni, test_wrap},
#define TESTGAP 1   /* number of gaps of each length */
  { GSIZE, "gap", test_gini, test_gap, test_wrap},
#define TESTRUN 2   /* lengths of strictly increasing subsequences */
  { RSIZE, "run", test_init, test_run, test_wrap},
#define TESTMAU 3   /* product of gaps for each value */
  { USIZE, "mau", test_mini, test_mau, test_mwra},
#define TESTOCC 4   /* occurance test, how many values occur n times */
  { OSIZE, "occ", test_init, test_occ, test_wrap},
#define TESTLAST 5  /* number of tests */
};



/* 
---------------------------------------------------------------------
RRR: routines for Random Number Generators
---------------------------------------------------------------------
*/


/* a generator known to produce values with no detectable bias */
static void rng_good(r1,r2)
rng *r1;   /* internal state of the perfect generator */
rng *r2;   /* not used */
{
#define rotate(a)  (((a)<<19)^((a)>>13))
#define fff(x)     ((x)&(NNN-1))                      /* choose any term */
  register u4 *mm,*rr,a,b,i,x,y;

  mm = r1->mm; rr = r1->rr;
  a  = r1->a;  b  = r1->b;
  for (i=0; i<NNN; ++i)
  {
    x = mm[i];  
    a = rotate(a) + mm[fff(i+(NNN/2))];
    mm[i] = y = mm[fff(x)] + a + b;
    rr[i] = b = mm[fff(y>>8)] + x;
  }
  r1->b = b;   r1->a = a;
}

/* produce one random 32-bit value whenever you want one */
#define  prng(i,r) \
  if (1) { \
    if (++(r)->count >= NNN) { rng_good( (r), (rng *)0); (r)->count=0; } \
    (i) = (r)->rr[(r)->count]; \
  }

/* The control generator */
/* Whatever distribution the test generator is supposed to have, the
 * control generator should be changed to produce that distribution too.
 */
static void rng_ctrl(r1, r2)
rng *r1;   /* results for the user */
rng *r2;   /* internal state of the good generator */
{
  register u4 i,z, *rr=r1->rr, *ss=r1->ss, *mm = r1->mm;
  for (i=0; i<SIZE; ++i)
  {
    prng(z,r2);
    *(mm++) = (z&WMASK);
    *(rr++) = (z&UMASK);
    *(ss++) = ((z>>OMICRON)&UMASK);
  }
  /* prevent cycles by putting the full 32 bits in a,b,c */
  prng(r1->a,r2);
  prng(r1->b,r2);
  prng(r1->c,r2);
}

/* rng_test: Experimental RNG -- place your RNG here */
static void rng_test(rtest, rgood)
rng *rtest;  /* internal state of your generator */
rng *rgood;  /* internal state of auxilliary, good generator */
{
  register u4 a,b,i,x,y,z,*mm,*rr,*ss;
#define ind(x) ((x)&MASK)
  
  mm = rtest->mm;  rr = rtest->rr;  ss = rtest->ss;

  /* add-and-carry generator */
  a = rtest->a;
  for (i=0; i<SIZE; ++i)
  {
    b = mm[i] + mm[ind(i+SIZE/2-1)] + a;
    a = (b > WMASK);
    mm[i] = b & WMASK;
    rr[i] = ss[i] = (b>>(OMEGA-OMICRON))&UMASK;
  }
  rtest->a = a;

#ifdef NEVER    /* store deleted code inside the NEVER area */
  /* The good generator, scaled down */
  a = rtest->a;
  b = rtest->b;
  for (i=0; i<SIZE; ++i)
  {
    x = mm[i];
    z = mm[ind(i+(SIZE/2))];
    a = ((a<<SHIFT)^(a>>(OMEGA-SHIFT))) & WMASK;
    a = (a + z) & WMASK;
    mm[i] = y = (mm[ind(x)] + a + b) & WMASK;
    b = (mm[ind(y>>ALPHA)] + x) & WMASK;
    rr[i] = b & UMASK;
    /* ss is part of the secret internal state */
  }
  rtest->b = b;
  rtest->a = a;

  /* RC4 */
  a  = rtest->a;  b  = rtest->b;
  for (i=0; i<SIZE; ++i)
  {
    x=mm[i];
    a=(a+x)&MASK;
    y=mm[a];
    mm[i]=y; mm[a]=x;
    rr[i] = mm[((x+y)&MASK)] & UMASK;
    ss[i] = x & UMASK;
  }
  rtest->b = b;   rtest->a = a;
  prng(x,rgood);
#endif
}

/* allocate the internal state for an rng */
static rng *rng_allo(id)
u4          id;
{
  rng *r= (rng *)malloc(sizeof(rng));
  r->mm = (u4 *)malloc(sizeof(u4)*rnglist[id].alen);
  r->rr = (u4 *)malloc(sizeof(u4)*rnglist[id].alen);
  r->ss = (u4 *)malloc(sizeof(u4)*rnglist[id].alen);
  r->id = id;
  return r;
}

/* free an internal state */
static void rng_free(r)
rng        *r;
{
  free(r->mm);
  free(r->rr);
  free(r->ss);
  free(r);
}



/*
------------------------------------------------------------------
VVV: routines for Values
------------------------------------------------------------------
*/

/* initialize a value counter */
static val  *val_allo( id)
u4           id;
{
  val *v = (val *)malloc(sizeof(val));
  v->rr = v->arr = (u4 *)malloc(sizeof(u4)*SIZE);
  v->id = id;
  v->bc = v->vc = 0;
  v->test = (test *)0;
  v->next = (val  *)0;
  return v;
}

/* Given a new set of values, run all the tests hanging off v */
static void  val_all( v, use)
val         *v;
u4           use;
{
  register test *t;
  if (use) for (t=v->test; t; t=t->all.next)
  {
    (*testlist[t->all.id].pass)( t, v);
  }
  v->vc = v->bc = 0;
}

/* Just use the rng values directly */
static void  val_norm( v, r, use)
val         *v;
rng         *r;
u4           use;
{
  v->rr = r->rr;
  val_all( v, use);
}

/* Construct new values by concatenating the low-order bit of consecutive
 * rng values.
 */
static void  val_corr( v, r, use)
val         *v;
rng         *r;
u4           use;
{  
  register u4 i,j,k, *rr = r->rr;

  for (i=0, j=0, k=0; i<SIZE; ++i)
  {
    k = ((k<<1)|(!!(rr[i]&CORRBIT)))&UMASK;
    ++j;
    if (j>=OMICRON)
    {
      v->rr[v->vc++] = k;
      j = 0;
      k = 0;
      if (v->vc == SIZE) val_all( v, use);
    }
  }
}

/* Construct your own values */
static void  val_jump( v, r, use)
val         *v;
rng         *r;
u4           use;
{
  u4  i;
  v->rr[v->vc++] = r->ss[i];
  if (v->vc == SIZE) val_all( v, use);
}

static void  val_free( v)
val         *v;
{
  test *t;
  free(v->arr);
  while (v->test)
  {
    t = v->test->all.next;
    test_free( v->test);
    v->test = t;
  }
  free(v);
}



/*
------------------------------------------------------------------
TTT: routines for Tests 
------------------------------------------------------------------
*/

/* Knuth's frequency test.  How uniformly distributed are the values */
static void test_uni( t, v )
test       *t;
val        *v;
{
  register u4  i, *rr = v->rr, *d = t->all.event;
  for (i=0; i<SIZE; ++i) ++d[*(rr++)];
}

/* Knuth's gap test.  How big are the gaps between occurances of values */
static void test_gap( t, v)
test       *t;
val        *v;
{
  register u4  i, *rr = v->rr, *d = t->all.event;
  register u4  j, k, count = t->all.count, *last = t->gap.last;
  
  for (i=0; i<SIZE; ++i)
  {
    j = rr[i];
    k = (count+i)-last[j];
    if (k<=GSIZE) ++d[k-1];
    else ++d[GSIZE-1];
    last[j] = i+count;
  }
  t->all.count += SIZE;
}

/* Knuth's run test.  Count runs of strictly increasing sequences */
static void test_run( t, v)
test       *t;      /* test being run */
val        *v;      /* state of RNG */
{
  register u4  i, *rr = v->rr, *d = t->all.event;
  register u4  last = t->run.last, count = t->all.count;
  
  for (i=0; i<SIZE; ++i)
  {
    if (count > 1000) {count=0; last=rr[i];}
    else if (last == rr[i]) ;
    else if (last < rr[i]) {++count; last=rr[i];}
    else 
    {
      if (count > RSIZE-1) count=RSIZE-1;   
      ++d[count]; 
      count=1001;
    }
  }
  t->all.count = count; t->run.last = last;
}

/* Maurer test.  For each value, the product of all gaps */
static void test_mau( t, v)
test       *t;      /* test being run */
val        *v;      /* state of RNG */
{
  register u4  i, *rr = v->rr, *d = t->all.event;
  register u4  j, k, count = t->all.count, *last = t->mau.last;
  register double *devent;
  
  for (i=0; i<SIZE; ++i)
  {
    j = rr[i];
    k = (count+i)-last[j];
    last[j] = i+count;
    devent = &(t->mau.devent[j]);
    if ((*devent *= (double)k) > (double)((u4)1<<30))
    {
      *devent /= (double)((u4)1<<30);
      d[j] += 30;
    }
  }
  t->all.count += SIZE;
}

/* How many values occur n times in groups of OSIZE values */
static void test_occ( t, v)
test       *t;      /* test being run */
val        *v;      /* state of RNG */
{
  register u4   i, j, count = t->all.count;
  for (i=0; i<SIZE; ++i)
  {
    t->occ.rold[count++] = v->rr[i];
    if (count >= OSIZE)
    {
      count = 0;
      for (j=0; j<USIZE; ++j) t->occ.vcount[j] = 0;
      for (j=0; j<OSIZE; ++j) t->occ.vcount[t->occ.rold[j]]++;
      for (j=0; j<USIZE; ++j)
	if (t->occ.vcount[j] < OSIZE)
	  ++t->all.event[t->occ.vcount[j]];
    }
  }
  t->all.count = count;
}


static test *test_allo( id)
u4           id;
{
  test *t = (test *)malloc(sizeof(test));
  t->all.event = (u4 *)malloc(sizeof(u4)*testlist[id].len);
  t->all.id = id;
  t->all.estchi = 1;
  t->all.display = TDNONE;
  t->all.expect = 0;
  return t;
}

static void  test_free( t)
test        *t;
{
  free(t->all.event);
  free(t);
}

static void  test_init( t)
test        *t;
{
  u4         i, *event = t->all.event;
  for (i=testlist[t->all.id].len; i--;) event[i] = 0;
  t->all.count = 0;
}

static void  test_gini( t)
test        *t;
{
  u4      i;
  test_init(t);
  t->all.count = 1;
  for (i=0; i<SIZE; ++i) t->gap.last[i] = 0;
}

static void  test_mini( t)
test        *t;
{
  u4      i;
  double *devent = t->mau.devent;
  test_init(t);
  t->all.count = 1;
  for (i=0; i<USIZE; ++i) t->mau.last[i] = 0;
  for (i=0; i<USIZE; ++i) *(devent++) = 1.0;
}

static void  test_wrap( t)
test        *t;
{
  /* nothing to do */
}

static void  test_mwra( t)
test        *t;
{
  u4      i, *event = t->all.event;
  double *devent = t->mau.devent;
  for (i=0; i<USIZE; ++i, ++event, ++devent)
  {
    while (*devent > 1.0) 
    {
      *devent /= 2.0; 
      *event += 1;
    }
  }
}


/*
------------------------------------------------------------------
Chi-squared test

If data[] is random, the result should be expect +- Ksqrt(expect) 
unless outlen is less than 30.  I think K=3, but I'm not sure.

This isn't the standard chisquare test.  Rather than comparing stats
to the expected probabilities, they are compared to the results of an
RNG which is known to be good when run through the same tests.

The loss from this approach is that tests are slower (two generators
need to be run) and there is an extra source of error (the good RNG).

The gains from this approach are
* You don't have to write routines to compute the exact probabilities.
* If your tests don't collect what you think they do, that's OK.
* You can use tests where you have no clue what the results should be.
* You can model nonuniform things by placing the model in rng_ctrl,
  then the tests will all adapt to the new distributions.
------------------------------------------------------------------
*/
static double chisquare( chilen, data, good, len, outlen, scale)
u4      chilen;  /* how small should we ignore */
u4     *data;    /* data from the questionable RNG */
u4     *good;    /* data from the good RNG */
u4      len;     /* length of data and good; they must be the same length */
u4     *outlen;  /* number of values actually used */
double *scale;   /* amount of data in sample vs good */
{
  register u4     i;
  register double V=0, S=1.0, SD=0, SG=0, Q, R;
  for (*outlen=0, i=0; i<len; ++i) if (good[i] > chilen) ++(*outlen);
  for (i=0; i<len; ++i) if (good[i] > chilen) SG += (double)good[i];
  for (i=0; i<len; ++i) if (good[i] > chilen) SD += (double)data[i];
  if (!SG || !SD || !*outlen) return 0.0;
  *scale = S = SD/SG;

  for (i=0; i<len; ++i) if (good[i] > chilen)
  {
    R = S*(double)good[i];
    Q = ((double)data[i] - R);
    V += (Q*Q)/R;
  }
  return V*SG/(SD+SG);     /* will be average of good and data's variance */
}

/*
------------------------------------------------------------------
CCC: Flow Control
------------------------------------------------------------------
*/

static val *flow_allo(/* void */);
static void flow_free(/* val *v */);
static void cyc_init(/* rng *r, rng *rcyc */);
static u4   cyc_test(/* rng *r, rng *rcyc */);
static void gather(/* val *v, rng *rtest, rng *rgood, u4 runs */);
static void estimate(/* val *vctrl, rng *rctrl, rng *rgood, u4 runs */);
static void report(/* test *t, test *tctrl, val *vctrl */);
static void show_all(/* val *v, val *vctrl */);


/* flow_allo: where you decide which values and tests to use */
/* running time is proportional to the number of tests being run */
static val *flow_allo()
{
  val *v = (val *)0;
  u4   i,j;

  for (i=VALLAST; i--;)
  {
    val *vt;
    if ((i != VALNORM) && (i != VALCORR)) continue;
    vt = val_allo( i);
    for (j=TESTLAST; j--;)
    {
      test *t;
      if ((j != TESTUNI) && (j != TESTGAP)) continue;
      t = test_allo( j);
      t->all.next = vt->test;
      if (i == VALNORM && j == TESTGAP) t->all.display = TDNORM;
      vt->test = t;
    }
    vt->next = v;
    v= vt;
  }
  return v;
}

static void  flow_free( v)
val         *v;
{
  while (v)
  {
    val *vt = v->next;
    val_free( v);
    v = vt;
  }
}

/* remember the current internal state of an rng */
static void cyc_init( r, rcyc)
rng        *r;
rng        *rcyc;
{
  u4    i;
  rcyc->a = r->a;  rcyc->b = r->b; rcyc->c = r->c;
  for (i=0; i<SIZE; ++i) rcyc->mm[i] = r->mm[i];
}

/* This only works if the rng is reversible */
static u4   cyc_test( r, rcyc)
rng        *r;
rng        *rcyc;
{
  u4    i;
  for (i=0; i<SIZE; ++i) if (r->mm[i] != rcyc->mm[i]) return 0;
  return ((r->a == rcyc->a) && (r->b == rcyc->b) && (r->c == rcyc->c));
}

/* Run the rng and gather statistics on all the tests */
static void gather(v, rtest, rgood, runs)
val        *v;      /* list of values and tests */
rng        *rtest;  /* which rng to test, already initialized */
rng        *rgood;  /* internal state of the good rng */
u4          runs;   /* how long to run the rng */
{
  register u4   i;
  register val  *vp;
  register test *tp;
  register void (*myrng)() = rnglist[rtest->id].pass;
  register rng  *rcyc = rng_allo( rtest->id);

  /* Initialize the test counters */
  for (vp=v; vp; vp=vp->next)
    for (tp=vp->test; tp; tp=tp->all.next)
      (*testlist[tp->all.id].init)( tp);

  /* Warm up the generator */
  for (i=0; i<10; ++i)
  {
    (*myrng)( rtest, rgood);
    (*rnglist[rgood->id].pass)( rgood, (rng *)0);
    for (vp=v; vp; vp=vp->next)
      (*vallist[vp->id].pass)( vp, rtest, (u4)0);
  }
  cyc_init( rtest, rcyc);

  /* Run the tests */
  for (i=1; i<=runs; ++i)
  {
    (*myrng)( rtest, rgood);
    for (vp=v; vp; vp=vp->next)
      (*vallist[vp->id].pass)( vp, rtest, (u4)1);
    if (cyc_test( rtest, rcyc))
    {
      printf("cycle found at %ld\n",i);
      break;
    }
  }

  /* Wrap up the tests */
  for (vp=v; vp; vp=vp->next)
  for (tp=vp->test; tp; tp=tp->all.next)
    (*testlist[tp->all.id].wrap)( tp);
  rng_free( rcyc);
}

/*
------------------------------------------------------------------
Estimate the distribution for each test and the chi^2 results

Estimating the distribution is easy; just run the good test for a long
time and gather statistics in the normal way.  The longer control statistics
are gathered, the smaller the expected deviation from the true distribution.

Estimating the chi^2 results is a little trickier.  Rather than gathering
control statistics all at once, we gather them in many little pieces.  Each
piece also has about the expected distribution.  We estimate the chi^2
results by comparing the distributions of all these little pieces.
------------------------------------------------------------------
*/
static void estimate(vctrl, rctrl, rgood, runs)
val        *vctrl;      /* output: results from the good generator */
rng        *rctrl;      /* control generator state */
rng        *rgood;      /* good generator state */
u4          runs;       /* how long stats will be gathered for rtest */
{
  val  *v1 = flow_allo();   /* first set of results */
  val  *vc1,*vcr,*vt;       /* counter */
  test *tc1,*tcr;           /* counter */
  u4    i,j,k, samples=64;
  if (samples > MYRUNS) samples = MYRUNS;

  /* Gather n samples, compare each to the sum of all previous samples */
  for (i=0; i<samples; ++i)
  {
    gather(v1, rctrl, rgood, runs/(samples/2));
    for (vc1=v1, vcr=vctrl;  vc1;   vc1=vc1->next, vcr=vcr->next)
    {
      for (tc1=vc1->test, tcr=vcr->test;  tc1;
	   tc1=tc1->all.next, tcr=tcr->all.next)
      {
	if (i)
	{
	  double  outlen, scale;
	  tcr->all.expect += chisquare((u4)((i*CHILEN)/samples),
				       tc1->all.event, tcr->all.event,
				       testlist[tc1->all.id].len,
				       &outlen, &scale);
	}
	else tcr->all.expect = 0.0;
	for (j=testlist[tc1->all.id].len; j--;)
	  tcr->all.event[j] = ((!i) ? tc1->all.event[j] :
	    tcr->all.event[j]+tc1->all.event[j]);
      }
    }
  }

  /* Figure out what the chi^2 results are expected to be */
  for (vc1=v1, vcr = vctrl;  vc1;  vc1=vc1->next, vcr=vcr->next)
  {
    for (tc1=vc1->test, tcr=vcr->test;  tc1;
	 tc1=tc1->all.next, tcr=tcr->all.next)
    {
      if (!tcr->all.estchi) 
      {
	for (j=0, i=testlist[tc1->all.id].len; i--;)
	if (tcr->all.event[i] > CHILEN) ++j;
	tcr->all.expect = (j ? j-1 : 0);
      }
      else tcr->all.expect /= (samples-1);
    }
  }
  flow_free(v1);
}

/* report a single set of results */
static void report( t, tctrl, vctrl)
test       *t;      /* results from the generator being tested */
test       *tctrl;  /* results from the control generator */
val        *vctrl;  /* values fed to the control generator */
{
  u4     outlen,i;
  double actual, scale;

  actual = chisquare( CHILEN, t->all.event, tctrl->all.event, 
		     testlist[t->all.id].len,
		     &outlen, &scale);
  if (!scale) scale = 1.0;
  printf("%s %s: expect %14.4f    get %14.4f \n", 
	 vallist[vctrl->id].name, 
	 testlist[tctrl->all.id].name,
	 tctrl->all.expect, actual);
  if (tctrl->all.display != TDNONE)
  {
    for (i=0; i<testlist[t->all.id].len; ++i)
    {
      if (0 && tctrl->all.event[i] <= CHILEN) printf("        *");
      else switch (tctrl->all.display)
      {
      case TDNORM: printf(" %8.4f", ((double)t->all.event[i]/
				     ((double)tctrl->all.event[i]*scale)));
	break;
      case TDTEST: printf(" %8.0f",(double)t->all.event[i]);
	break;
      case TDCTRL: printf(" %8.0f",(double)tctrl->all.event[i]);
	break;
      }
      if (!((i+1)&7)) printf("\n");
    } 
    if (i&7) printf("\n");
  }
}

/* show all results */
static void show_all( v, vctrl)
val        *v;      /* values and tests for rng being tested */
val        *vctrl;  /* values and tests from control generator */
{
  test     *t, *tctrl;
  for (; v; v=v->next, vctrl=vctrl->next)
    for (t=v->test, tctrl=vctrl->test; t;
	 t=t->all.next, tctrl=tctrl->all.next)
      report(t, tctrl, vctrl);
}

/* driver() is where you choose which seeds to use */
void driver()
{
  u4       i,j;
  val     *vtest;    /* values and tests for generator being tested */
  val     *vctrl;    /* values and tests for control generator */
  val     *vt;       /* counter */
  rng     *rgood, *rtest, *rctrl;
  test    *t;        /* counter */

  /* Allocate the values, tests, and generators */
  rgood = rng_allo( (u4)RNGGOOD);
  rtest = rng_allo( (u4)RNGTEST);
  rctrl = rng_allo( (u4)RNGCTRL);

  /* Estimate the probability distribution and expected results */
  printf("Setting up probabilities ...\n");
  vctrl = flow_allo();
  for (j=0; j<NNN;  ++j) rgood->mm[j] = j;
  rgood->a = rgood->b = 2;  rgood->count = NNN;
  for (j=0; j<SIZE; ++j) rctrl->mm[j] = (j)&WMASK;
  rctrl->a = rctrl->b = 2;  rctrl->count = SIZE;
  estimate( vctrl, rctrl, rgood, MYRUNS);

  /* For a number of different seeds, test the new generator */
  vtest = flow_allo();
  for (i=10; i<=12; ++i)
  {
    printf("seed %ld\n", i);
    for (j=0; j<SIZE; ++j) rtest->mm[j] = ((j+i)&MASK)&WMASK;
    rtest->a = rtest->b = 2;  rtest->count = SIZE;
    gather( vtest, rtest, rgood, MYRUNS);
    show_all( vtest, vctrl);
  }

	/* Deallocate the values, tests, and generators */
  rng_free( rgood);
  rng_free( rtest);
  rng_free( rctrl);
  flow_free( vtest);
  flow_free( vctrl);
}

int main()
{
  driver();
  return 1;
}


