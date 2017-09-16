#include <hut-include.h>
#include "amp.h"
#include <stdio.h>
#include <ctype.h>

typedef int	(*funptr)();
typedef amp	*(*ampfunptr)();

char	*(*pr_fun)() = mp_mtoa;

#define OBJ_STR	1
#define OBJ_AMP	2
#define OBJ_FILE	3

typedef struct obj_s {
  struct obj_s	*link;
  int		type;
  int		strlen;
  char		*str;
  amp		*x;
  int		lookahead;
  union {
    FILE	*f;
    char	*s;
  }		stream;
} obj;

extern obj	*amp_to_obj();
extern obj	*do_pop();
extern char	*obj_to_str();
extern obj	*amp_to_obj();
extern int	obj_getc();
extern obj	*new_obj();
extern obj	*str_to_obj();
extern obj	*str_to_obj();
extern obj	*obj_copy();
extern obj	*pop_amp();
extern obj	*print_obj();

obj	*in_stream;

obj	obj_z;

obj	*stack;
obj	*regs[256];
obj	*obj_freelist;

amp *
atom(p)

char	*p;

{
  if (p[0] == '0' && p[1] == 'x') {
    pr_fun = mp_mtoh;
    return mp_htom(p+2);
  } else {
    pr_fun = mp_mtoa;
    return mp_atom(p);
  }
}

obj *
file_to_obj(f)

FILE	*f;

{
  obj	*r;

  r = new_obj();
  r->stream.f = f;
  r->type = OBJ_FILE;
  return r;
}

main(argc,argv,envp)

int argc;
char **argv;
char **envp;

{
  char	*s;
  char	*p0;
  char	*p;
  int	i;
  int	op;
  int	op2;
  hut_linebuf	l = hut_linebuf_z;
  amp	*acc,*x1,*x2;

  in_stream = file_to_obj(stdin);

  do_obj(&in_stream);
  return 0;
}

obj *
parse_num(op)

obj	**op;

{
  char	*p;
  int	neg;
  amp	*x;
  char	*numstart;
  int	c;

  neg = 0;

  c = obj_getc(op);
  if (c == '_') {
    neg = 1;
    c = 0;
  }
  x = mp_itom(0);
  for(;; c = 0) {
    if (!c) c = obj_getc(op);
    if (c == EOF) break;
    if (c < '0' || c > '9') break;
    c -= '0';
    mp_mul_x_to(x,x,(long)10);
    mp_add_x_to(x,(long)c);
  }
  if (c != EOF) obj_ungetc(op,c);
  if (neg)
    x->sign = MP_NEGATIVE;
  return amp_to_obj(x);
}

do_reg_op(op,reg)

int	op,reg;

{
  obj	**rp;

  reg &= 0xff;
  rp = &regs[reg];
  switch(op) {
  case 's':
    while (*rp) obj_free(do_pop(rp));
    /* Fall through... */
  case 'S':
    do_push(rp,do_pop(&stack));
    break;
  case 'l':
    do_push(&stack,obj_copy(*rp));
    break;
  case 'L':
    do_push(&stack,do_pop(rp));
  }
}

obj *
parse_str(op)

obj	**op;

{
  char	*p;
  int	c;
  obj	*r;
  char	s[1024];
  int	level;
  
  level = 1;
  for(p = s; level > 0;) {
    switch (c = obj_getc(op)) {
    default:
      *p++ = c;
      break;
    case EOF:
      level = 0;
      *p = 0;
      break;
    case '[':
      *p++ = c;
      level++;
    case ']':
      level--;
      if (level > 0) {
	*p++ = c;
      } else {
	*p = 0;
      }
      break;
    }
  }
  r = str_to_obj(s);
  return r;
}

pop_n(sp,n)

obj	**sp;
int	n;

{
  while (n-- > 0)
    obj_free(do_pop(sp));
}

do_cmp(op,c)

obj	**op;
int	c;

{
  obj	*x1,*x2;
  int	d;
  int	reg;

  reg = obj_getc(op);
  x1 = pop_amp(&stack);
  x2 = pop_amp(&stack);

  d = mp_cmp(x1->x,x2->x);
  switch (c) {
  case '<':
    d = (d < 0);
    break;
  case '>':
    d = (d > 0);
    break;
  case '=':
    d = (d == 0);
    break;
  }
  if (d) {
    do_push(op,obj_copy(regs[reg]));
  }
}

do_obj(op)

obj	**op;

{
  int	n;
  int	neg;
  int	c;

  while((c = obj_getc(op)) != EOF) {
    if (c == '_' || (c >= '0' && c <= '9')) {
      obj_ungetc(op,c);
      do_push(&stack,parse_num(op));
    } else
      switch (c) {
      case ' ':
      case '\n':
      case '\t':
	break;
      default:
	if (isascii(c) && isprint(c))
	  printf("'%c' is unimplemented\n",c);
	else
	  printf("0%o is unimplemented\n",c);
	break;
      case 'c':
	while (stack)
	  obj_free(do_pop(&stack));
	break;
      case 'x':
	do_push(op,do_pop(&stack));
	break;
      case 'q':
	switch ((*op)->type) {
	case OBJ_STR:
	  pop_n(op,2);
	  break;
	default:
	  pop_n(op,1);
	  break;
	}
	break;
      case '[':
	do_push(&stack,parse_str(op));
	break;
      case '+':
	do_bin(mp_add);
	break;
      case '-':
	do_bin(mp_sub);
	break;
      case '*':
	do_bin(mp_mul);
	break;
      case '/':
	do_bin(mp_rdiv);
	break;
      case '^':
	do_bin(mp_rpow);
	break;
      case 'P':
	obj_free(print_obj(stdout,do_pop(&stack)));
	break;
      case 'p':
	print_obj(stdout,stack);
	putc('\n',stdout);
	break;
      case 'f':
	print_stack(stdout,stack);
	break;
      case 's':
      case 'S':
      case 'l':
      case 'L':
	do_reg_op(c,obj_getc(op));
	break;
      case 'd':
	do_push(&stack,obj_copy(stack));
	break;
      case 'v':
	do_sqrt(&stack);
	break;
      case '<':
      case '>':
      case '=':
	do_cmp(op,c);
	break;
      }
  }
}

obj *
print_obj(f,p)

FILE	*f;
obj	*p;

{
  fputs(obj_to_str(p),f);
  return p;
}

print_stack(f,p)

FILE	*f;
obj	*p;

{
  for(; p; p = p->link) {
    fprintf(f,"%s\n",obj_to_str(p));
  }
}

obj *
new_obj()

{
  obj	*r;

  if (r = do_pop(&obj_freelist)) {
    r->type = 0;
    return r;
  } else {
    r = HUT_NEW_CHECK(obj);
    *r = obj_z;
  }
  r->lookahead = 0;
  r->stream.s = 0;
  return r;
}

obj_free(p)

obj	*p;

{
  do_push(&obj_freelist,p);
}

obj *
str_to_obj(s)

char	*s;

{
  obj	*r;
  int	l;

  r = new_obj();
  l = strlen(s);
  if (!r->str || r->strlen < l)
    r->str = hut_realloc(r->str,l+16);
  r->strlen = l+15;
  strcpy(r->str,s);
  r->type = OBJ_STR;
  r->stream.s = r->str;
  return r;
}

char *
obj_to_str(p)

obj	*p;

{
  switch(p->type) {
  default:
    return "nil";
  case OBJ_STR:
    return p->str;
  case OBJ_AMP:
    return mp_mtoa(p->x);
  }
}

obj *
amp_to_obj(p)

amp	*p;

{
  obj	*r;

  r = new_obj();
  if (r->x)
    mp_free(r->x);
  r->x = p;
  r->type = OBJ_AMP;
  return r;
}

obj *
obj_copy(p)

obj	*p;

{
  switch (p->type) {
  default:
    return new_obj();
  case OBJ_STR:
    return str_to_obj(p->str);
  case OBJ_AMP:
    return amp_to_obj(mp_copy(p->x));
  }
}

obj *
do_pop(stackp)

obj	**stackp;

{
  obj	*r;
  if (r = *stackp) {
    *stackp = r->link;
    r->link = 0;
  } else {
    return 0;
  }
}

obj *
pop_amp(stackp)

obj	**stackp;

{
  obj	*p;

  if (!(p = do_pop(stackp)))
    return 0;
  if (p->type != OBJ_AMP) {
    do_push(stackp,p);
    return 0;
  }
  return p;
}

do_push(stackp,p)

obj	**stackp;
obj	*p;

{
  if (!p)
    return;
  p->link = *stackp;
  *stackp = p;
}

do_bin(f)

ampfunptr	f;

{
  amp	*x1;
  obj	*p1,*p2;

  if ((p2 = pop_amp(&stack)) &&
      (p1 = pop_amp(&stack))) {
    x1 = f(p1->x,p2->x);
    obj_free(p1);
    obj_free(p2);
    do_push(&stack,amp_to_obj(x1));
  }
}

int
obj_getc(op)

obj	**op;

{
  obj	*p;
  FILE	*f;
  int	c;

  if (!op || !(p = *op))
    return EOF;
  if (c = p->lookahead) {
    p->lookahead = 0;
    return c;
  }
  switch (p->type) {
  default:
    fprintf(stderr,"Illegal type %d in exec stack\n",p->type);
    obj_free(do_pop(op));
    return obj_getc(op);
  case OBJ_STR:
    if (!(c = *p->stream.s++)) {
      obj_free(do_pop(op));
      return obj_getc(op);
    }
    return c;
  case OBJ_FILE:
    f = p->stream.f;
    if ((c = getc(f)) == EOF) {
      obj_free(do_pop(op));
      return obj_getc(op);
    }
    return c;
  }
}

int
obj_ungetc(op,c)

obj	**op;
int	c;

{
  obj	*p;

  if (!op || !(p = *op))
    return EOF;
  p->lookahead = c;
  return c;
}

do_sqrt(sp)

obj	**sp;

{
  obj	*x;
  amp	*a;

  x = pop_amp(sp);
  a = mp_sqrt(x->x,(amp*)0);
  if (a) {
    do_push(sp,amp_to_obj(a));
    obj_free(x);
  } else {
    fprintf("Cannot take sqrt\n");
  }
}
