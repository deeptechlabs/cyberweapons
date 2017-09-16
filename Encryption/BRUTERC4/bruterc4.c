/* 
 *  get latest copy from: 
 *
 *          ftp://ftp.brute.cl.cam.ac.uk/pub/brute/bruterc4.c
 *
 *  Or if you have WWW see:
 *
 *          http://www.brute.cl.cam.ac.uk/brute/
 *
 **************************************************************************
 *
 *  interactive usage:
 *
 *     rc4brute <config-file> <project-id> <start-key> <segments>
 *
 *  batch usage:
 *
 *     rc4brute -q <config-file> <project-id> <start-key> <segments>
 *
 *  if <config-file> = -, stdin will be used for the config file.
 *
 *     <config-file>   contains the plaintext/ciphertext for this bruting
 *     <project-id>    a checksum on the config-file, doubling as an id
 *     <start-key>     your allocated place to start bruting
 *     <segments>      how man 24-bit segments to search
 *
 *
 *  example:
 *
 *     rc4brute test.cfg 12a3 340e 5
 *
 *  ie start bruting the plaintext/ciphertext pair contained in 'test.cfg'
 *  the project-id is 12a3 hex, the place to start searching is 340e, and
 *  you want to search 5 segments.
 *
 **************************************************************************
 *
 *  rc4brute.c by    Adam Back <aba@dcs.ex.ac.uk>
 * optimisations by  Tatu Ylonen <ylo@cs.hut.fi>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSDOS)
#include <time.h>
#elif defined(__OS2__)
#include <time.h>
#else
#include <sys/time.h>
#endif

#ifdef __OS2__
#define INCL_DOSPROCESS
#include <os2.h>
#endif /* __OS2__ */

#define UCHAR unsigned char
#define USHORT unsigned short
#define ULONG unsigned long

#define KEY_SIZE 5 /* key size in bytes, ie 40 bits */

#define MAX_LINE 1024
#define MAX_TEXT 128   /* don't want more than that much plain text */

#define buf_size 1024

typedef struct rc4_key
{
   UCHAR state[256];
   UCHAR x;
   UCHAR y;
} rc4_key;

#define swap_byte(x,y) t = (x); (x) = (y); (y) = t

#define LF '\n'
#define CR '\r'
#define WHITE_SPACE " \t\r\n"

char* prog;

int verbose = 1, check = 0;

ULONG test_endian = 0x1;
int big_endian;

void inc_key(UCHAR key[])
{
  int i;
  for (i=KEY_SIZE-1; i && key[i] == 255; i--)
  {
    key[i] = 0;
  }
  key[i]++;
}

const UCHAR* print_hex(UCHAR key[],int len)
{
  static UCHAR space[513];
  int i;
  for (i=0; i<len; i++)
  {
    sprintf(space+i*2,"%02x",key[i]);
  }
  space[i*2]=0;
  return space;
}

void strip_comments(UCHAR* line);
void strip_crlf(UCHAR* line);
USHORT checksum(USHORT, UCHAR* line);
void parse_line(UCHAR*, UCHAR**, UCHAR**);
USHORT byte_pack(UCHAR[], UCHAR[], USHORT);
void instructions();

/* excellent optimised prepare key by Tatu Ylonen ylo@cs.hut.fi */

void prepare_key(UCHAR *key_data_ptr, 
		 int key_data_len, 
		 rc4_key *key)
{
  register unsigned int t, u;
  register unsigned int index2;
  register unsigned int counter;
  register unsigned int k0, k1, k2, k3, k4;
  UCHAR *state = key->state;

  if (big_endian)
  {
    t = 0x03020100L;
  }
  else
  {
    t = 0x00010203L;
  }

  for (u=0;u<64;u+=8)
  {
    ((int*)state)[u] = t;
    t+=0x04040404L;
    ((int*)state)[u+1] = t;
    t+=0x04040404L;
    ((int*)state)[u+2] = t;
    t+=0x04040404L;
    ((int*)state)[u+3] = t;
    t+=0x04040404L;
    ((int*)state)[u+4] = t;
    t+=0x04040404L;
    ((int*)state)[u+5] = t;
    t+=0x04040404L;
    ((int*)state)[u+6] = t;
    t+=0x04040404L;
    ((int*)state)[u+7] = t;
    t+=0x04040404L;
  }

  index2 = 0;
  k0 = key_data_ptr[0];
  k1 = key_data_ptr[1];
  k2 = key_data_ptr[2];
  k3 = key_data_ptr[3];
  k4 = key_data_ptr[4];

  for(counter = 0; counter < 255; counter += 5)
  {
    t = state[counter];
    index2 = (index2 + k0 + t) & 0xff;
    u = state[index2];
    state[index2] = t;
    state[counter] = u;

    t = state[counter + 1];
    index2 = (index2 + k1 + t) & 0xff;
    u = state[index2];
    state[index2] = t;
    state[counter + 1] = u;

    t = state[counter + 2];
    index2 = (index2 + k2 + t) & 0xff;
    u = state[index2];
    state[index2] = t;
    state[counter + 2] = u;

    t = state[counter + 3];
    index2 = (index2 + k3 + t) & 0xff;
    u = state[index2];
    state[index2] = t;
    state[counter + 3] = u;

    t = state[counter + 4];
    index2 = (index2 + k4 + t) & 0xff;
    u = state[index2];
    state[index2] = t;
    state[counter + 4] = u;
  }
  t = state[255];
  index2 = (index2 + k0 + t) & 0xff;
  u = state[index2];
  state[index2] = t;
  state[255] = u;
}

int rc4_eq(UCHAR *pre_xored,
	   unsigned int text_len, rc4_key *key)
{
  unsigned int t;
  unsigned int x = 0;
  unsigned int y = 0;
  UCHAR* state = key->state;
  unsigned int xorIndex;
  unsigned int counter;

  for(counter = 0; counter < text_len; counter++)
  {
    x = (x + 1) & 0xFF;
    y = (state[x] + y) & 0xFF;
    swap_byte(state[x], state[y]);
    xorIndex = (state[x] + state[y]) & 0xFF;
    if (pre_xored[counter] != state[xorIndex])
    {
      return 0;
    }
  }
  return 1;
}

void usage()
{

  fprintf(stderr,
"   interactive usage:\n"
"      rc4brute <config-file> <project-id> <start-key> <segments>\n\n"
"   batch usage:\n"
"      rc4brute -q <config-file> <project-id> <start-key> <segments>\n\n"
"   if <config-file> = -, stdin will be used for the config file.\n\n"
"      <config-file>   contains the plaintext/ciphertext for this bruting\n"
"      <project-id>    a checksum on the config-file, doubling as an id\n"
"      <start-key>     your allocated place to start bruting\n"
"      <segments>      how man 24-bit segments to search\n\n"
"   example:\n\n"
"      rc4brute test.cfg 12a3 340e 5\n\n"
"   ie start bruting the plaintext/ciphertext pair contained in 'test.cfg'\n"
"   the project-id is 12a3 hex, the place to start searching is 340e, and\n"
"   you want to search 5 segments.\n\n"
"   see: http://www.brute.cl.cam.ac.uk/brute\n");
}

int main(int argc, char* argv[])
{
  UCHAR seed[256];
  UCHAR line[MAX_LINE+1];
  UCHAR plain_text[MAX_TEXT+1];
  UCHAR cipher_text[MAX_TEXT+1];
  UCHAR comment[MAX_LINE+1];
  UCHAR xored_text[MAX_TEXT+1];
  int i, num;
  ULONG sweep, done = 0, iter;
  rc4_key key;
  FILE *fp;
  char** args = argv;
  int acount = argc;
  double time_taken;

  USHORT plain_text_len, cipher_text_len, text_len;
  USHORT cmd_line_project_id, file_check_sum = 0;
  USHORT completed_check_sum = 0;
  USHORT comment_len = 0;
  USHORT segments, start_segment;
  UCHAR* tag;
  UCHAR* value;

  int done_plain_text = 0;
  int done_cipher_text = 0;

#if !defined(_MSDOS) && !defined(__OS2__)
  struct timeval tv_start,tv_end;
#endif
  double keys_sec, run_time, start_time;
  int first = 1;
#ifdef __OS2__
  APIRET rc;
#endif

  big_endian = ((char*)&test_endian)[0];
  prog = argv[0];

#ifdef __OS2__
  /* set priority class to IDLETIME */
  rc = DosSetPriority(PRTYS_PROCESS, PRTYC_IDLETIME, 0, 0);
  if (rc != 0)
  {
    fprintf(stderr, "%s: unable to set priority, rc = %ld\n", prog, rc);
    exit(1);
  }
#endif /* __OS2__ */

  if (argc < 2)
  {
    usage();
    exit(1);
  }
  if (args[1][0]=='-')
  {
    switch(args[1][1])
    {
    case 'q':
      verbose = 0; break;
    case '\0':  /* stdin = '-' */
      acount++; args--;  /* doesn't count as a flag */
      break;
    default:
      fprintf(stderr,"invalid flag %s\n",args[1]);
      usage();
      exit(1);
    }
    args++; acount--;
  }

  if (acount < 5)
  {
    usage();
    exit(1);
  }

  if (!strcmp(args[1],"-"))
  {
    fp = stdin;
  }
  else
  {
    fp = fopen(args[1],"rb");
    if (!fp) 
    {
      fprintf(stderr,"error cannot open config file %s\n",args[1]);
      exit(2);
    }
  }

  num = sscanf(args[2],"%hx",&cmd_line_project_id);
  if (num < 1)
  {
    fprintf(stderr,"error: project-id should be a hexadecimal number\n\n");
    usage();
    exit(1);
  }

  if (strlen(args[3]) > 4)
  {
    fprintf(stderr,"error: start-key should be a 4 digit hexadecimal number\n\n");
    usage();
    exit(1);
  }
  i = byte_pack(seed, (UCHAR*) args[3], 2);
  if (i != 2)
  {
    fprintf(stderr,"error: start-key should be a 4 digit hexadecimal number\n\n");
    usage();
    exit(1);
  }
  
  seed[2] = seed[3] = seed[4] = 0;
  start_segment = (USHORT)seed[0]*256 + (USHORT)seed[1];

  num = sscanf(args[4],"%hu",&segments);
  if (num < 1)
  {
    fprintf(stderr,"error: segments should be a decimal number\n\n");
    usage();
    exit(1);
  }
  
  sweep = (ULONG)segments << 8;

  while (!feof(fp))
  {
    line[0] = '\0';
    fgets(line, MAX_LINE, fp);
    strip_crlf(line);
    strip_comments(line);
    file_check_sum = checksum(file_check_sum, line);
    parse_line(line,&tag,&value);
    if (!tag || !*tag)
    {
      continue;
    }
    if (!strcasecmp(tag,"PLAIN-TEXT"))
    {
      if (done_plain_text)
      {
	fprintf(stderr,
	  "config file error: should only have one PLAIN-TEXT field\n");
	exit(2);
      }
      if (strlen(value) & 0x1 != 0)
      {
	fprintf(stderr,
"config file error: PLAIN-TEXT field must be an even number of hex digits\n");
	exit(2);
      }
      plain_text_len = byte_pack(plain_text, value, MAX_TEXT);
      if (plain_text_len == 0)
      {
	fprintf(stderr,
	  "config file error: PLAIN-TEXT field must be hex digits\n");
	exit(2);
      }
      done_plain_text = 1;
    }
    else if (!strcasecmp(tag,"CIPHER-TEXT"))
    {
      if (done_cipher_text)
      {
	fprintf(stderr,
	  "config file error: should only have one CIPHER-TEXT field\n");
	exit(2);
      }
      if (strlen(value) & 0x1 != 0)
      {
	fprintf(stderr,
"config file error: CIPHER-TEXT field must be an even number of hex digits\n");
	exit(2);
      }
      cipher_text_len = byte_pack(cipher_text, value, MAX_TEXT);
      if (cipher_text_len == 0)
      {
	fprintf(stderr,
	  "config file error: CIPHER-TEXT field must be hex digits\n");
	exit(2);
      }
      done_cipher_text = 1;
    }
    else if (!strcasecmp(tag,"COMMENT"))
    { 
      char *rest = strtok(0, "\n"); /* ie to the end of string as there */
      if (comment_len != 0)	    /* won't be a \n due to strip_crlf */
      {
	fprintf(stderr,
	  "config file error: should only have one COMMENT field\n");
	exit(2);
      }
      strncpy(comment, value, MAX_LINE);
      if (rest)
      {
	comment_len = strlen(comment);
	strncat(comment," ", MAX_LINE - comment_len);
	comment_len++;
	strncat(comment, rest, MAX_LINE - comment_len);
	comment[MAX_LINE] = '\0';
      }
      comment_len = strlen(comment);
    }
    else
    {
      fprintf(stderr,"config file error: unknown tag: %s\n",tag);
      exit(2);
    }
  }
  if (!done_plain_text)
  {
    fprintf(stderr,"config file error: no PLAIN-TEXT field\n");
    exit(2);
  }
  if (!done_cipher_text)
  {
    fprintf(stderr,"config file error: no CIPHER-TEXT field\n");
    exit(2);
  }

  if (plain_text_len != cipher_text_len)
  {
    fprintf(stderr,"config file warning: PLAIN-TEXT and CIPHER-TEXT are not the same length\n");
  }
  text_len = plain_text_len < cipher_text_len ? 
                                    plain_text_len : cipher_text_len;

  if (cmd_line_project_id != file_check_sum)
  {
    fprintf(stderr,"error: you have the wrong config file for project %04x (%04x)\n",
	    cmd_line_project_id, file_check_sum);
    exit(1);
  }

  completed_check_sum = (( (ULONG)file_check_sum + (ULONG)start_segment + 
                            (ULONG)segments ) & 0xFFFFL);

  if (verbose)
  {
    fprintf(stderr,"PROJECT-ID\t%04x\n",file_check_sum);
    if (comment_len) fprintf(stderr,"COMMENT \t%s\n",comment);
    fprintf(stderr,"START-KEY\t%s\n",print_hex(seed,KEY_SIZE));
    fprintf(stderr,"SEGMENTS\t%u (16M keys/segment)\n",segments);
    fprintf(stderr,"PLAIN-TEXT\t%s\n",print_hex(plain_text,text_len));
    fprintf(stderr,"CIPHER-TEXT\t%s\n",print_hex(cipher_text,text_len));
    fprintf(stderr,"TEXT-SIZE\t%d\n",text_len);

    fprintf(stderr,"256k keys per '.' printed, 1 segment per line, a segment = 16M keys\n");
    fprintf(stderr,"LINES-TO-DO\t%d\n",segments);
  }

/* pre-compute plain_text XOR cipher_text */ 

  for (i=0; i<text_len; i++)
  {
    xored_text[i] = plain_text[i] ^ cipher_text[i];
  }

  for (done=0; done<sweep; done++)
  {
    if (verbose)
    {
      if (first)
      {
#if defined(_MSDOS) || defined(__OS2__)
	start_time = (double) clock()/CLOCKS_PER_SEC;
#else
	gettimeofday(&tv_start,0);
#endif
      }
    }
    for (iter=0; iter < 65536; iter++)
    {
      prepare_key(seed,KEY_SIZE,&key);
      if (rc4_eq(xored_text, text_len, &key))
      {
	if (verbose)
	{
	  fprintf(stderr,"\nFOUND-IT\t%s\n", print_hex(seed,KEY_SIZE));
	  instructions();
	}
	printf("%04x %04x %04x %u %s\n",file_check_sum,completed_check_sum,
	       start_segment,segments,print_hex(seed,KEY_SIZE));
	exit(0);
      }
      inc_key(seed);
    }
    if (verbose) 
    {
      if (first)
      {
#if defined(_MSDOS) || defined(__OS2__)
	time_taken = ((double) clock()/CLOCKS_PER_SEC) - start_time;
#else
	gettimeofday(&tv_end,0);
	time_taken = (double)(tv_end.tv_sec - tv_start.tv_sec);
	time_taken += ((double)(tv_end.tv_usec - tv_start.tv_usec)/1000000.0);
#endif
	keys_sec = 65536.0 / time_taken;
	fprintf(stderr,"KEYS-PER-SEC\t%0.1lf keys/sec\n",keys_sec);
	fprintf(stderr,"EXPECTED-RUNNING-TIME\t");
	run_time = sweep * time_taken;
	if (run_time < 60)
	{
	  fprintf(stderr,"%0.1lf secs\n",run_time);
	}
	else if (run_time < 3600)
	{
	  fprintf(stderr,"%0.1lf mins\n",run_time / 60);
	}
	else 
	{
	  fprintf(stderr,"%0.1lf hours\n",run_time / 3600);
	  if (run_time > 180000)
	  {
	    fprintf(stderr,"in days: %0.1lf days\n",run_time / 86400);
	  }
	}
	first = 0;
      }
      if ((done & 255L) == 0)
      {
	if (done > 0) fprintf(stderr,"]\n");
	fprintf(stderr,"%sxxxxxx:[",print_hex(seed,2));
      }
      if ((done & 3L) == 0)
      {
	fputc('.',stderr);
      }
#ifdef __OS2__
      fflush(stderr);	/* needed to prevent buffering of stderr */
#endif
    }
  }
  if (verbose)
  {
    fprintf(stderr,"]\n");
    instructions();
  }
  printf("%04x %04x %04x %u no\n",file_check_sum,completed_check_sum,
	 start_segment,segments);
  return 0;
}

void parse_line(UCHAR* line, UCHAR** tag, UCHAR** value)
{
  *tag = (UCHAR*) strtok(line, WHITE_SPACE);
  *value = (UCHAR*) strtok(0, WHITE_SPACE);
}

void strip_comments(UCHAR* line)
{
  UCHAR* comment;

  comment = (UCHAR*) strchr(line,'#');
  if (comment)
  {
    *comment = '\0';
  }
}

void strip_crlf(UCHAR* line)
{
  int len = strlen( line );
  if (len && line[len-1] == LF)
  {
    line[len-1] = '\0';
    len--;
  }
  if (len && line[len-1] == CR)
  {
    line[len-1] = '\0';
    len--;
  }
}

USHORT checksum(USHORT sum, UCHAR* line)
{
  ULONG check = sum;
  for (;*line && *line != '#';line++)
  {
    if (!strchr(WHITE_SPACE,*line))
    {
      check += *line;
    }
  }
  return (USHORT) (check & 0xFFFFL);
}

USHORT byte_pack(UCHAR bytes[], UCHAR hex[], USHORT max)
{
  UCHAR str[3];
  USHORT i, val;
  USHORT len = strlen(hex) / 2;
  int num;
  
  str[2] = '\0';

  if (len > max) len = max;

  for (i=0; i<len;i++)
  {
    str[0] = hex[2*i];
    str[1] = hex[2*i+1];
    num = sscanf(str,"%hx",&val);
    if (num < 1)
    {
      return 0;
    }
    bytes[i] = (UCHAR) val;
  }
  return len;
}

void instructions(void)
{
  fprintf(stderr,"----------------------------------------------------------------------\n");
  fprintf(stderr,"Please paste *exactly* what it says below this line into the \n");
  fprintf(stderr,"acknowledgement box on http://www.brute.cl.cam.ac.uk/brute/\n");
  fprintf(stderr,"----------------------------------------------------------------------\n");
}
