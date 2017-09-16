/* file crtype.h */
/* Include a few standard C files. */

#include <math.h>
#include <ctype.h>
#include <strings.h>
#include <stdio.h>


/* Some definitions to make the program more readable. */
#define TRUE 1
#define FALSE 0
#define IS ==
#define AND &&
#define OR  ||
#define ONE   '1'
#define ZERO  '0'
#define LOW_BIT_MASK ~(~0 << 1)

/* Define the size of some standard data types. */

#define NUM_ITERATIONS  32    /*  Number of iterations of diffusive encryption        */
#define BLOCK_SIZE       750  /*  Enough to hold biggest encrypted state              */
#define PERM_SIZE       256    /*  Up to permutation on 6-blocks                       */
#define LINK_SIZE   320       /*  the size of a link                                  */
#define LINK_LINK_SIZE  192    /* size of link link */
#define PLAIN_BLOCK_SIZE 384  /*  the block size, normally 384=6x64                   */
#define BLOCK_PERM_FRAME 6   /*   frame size for block permutation                    */
#define BLOCK_NUM_PERMS  64  /*  number of labels on fram                             */
#define LINK_PERM_FRAME 4   /*   frame size for block permutation                    */
#define LINK_NUM_PERMS  16  /*  number of labels on fram                             */
#define LINK_BLOCK_SIZE 128   /* size of block in link                               */


typedef struct pt {

char m[256][1024];

} pat_type, *pat_ptr_type;

pat_type pat1[1],pat2[1];

pat_ptr_type global_pat_ptr;

/* global variables */

/* character global variables */

char  block_current_state[BLOCK_SIZE];  /* the memory locations of
				      an array of processors  hold the current state   */


char  plain_text[PLAIN_BLOCK_SIZE];   /* to be compared */

int balanced_bits[1024];          /* this is the actual block key
					   as seen from the outside */

int link_balanced_bits[64];       /* ditto for link key */

char left_key[2050];                    /* the block key interpreted as a left-toggle rule */
char right_key[2050];                   /* the block key interpreted as a right-toggle rule */
char *key;                              /* key in play */

char link_left_key[129];                    /* the block key interpreted as a left-toggle rule */
char link_right_key[129];                   /* the block key interpreted as a right-toggle rule */

char master_link[LINK_SIZE];

/* integer global variables */

int current_state_size;               /* number of active processors */
int radius;                           /* the radius of the CA rule   */
int radius_times_2;                   /* 2*radius                    */
int neighborhood_size;                /* 2*radius+1                  */
int number_of_partial_neighborhoods;  /* 2^radius_times_2            */
int number_of_neighborhoods;          /* 2^neighborhood_size         */
int list_of_powers_of_2[30];          /* a list of the powers of 2   */
int high_bit_mask;                    /* used in encryption          */
int encrypt_bit_cut_off;                    /* used in encryption          */
int decrypt_bit_cut_off;                    /* used in encryption          */
int neighborhood_mask;                /* used in decryption          */
int printer;                          /* for making pictures */
int which_pat;                        /* which pattern is begin filled */
int pat_row;                          /* which row of pattern being filled */



