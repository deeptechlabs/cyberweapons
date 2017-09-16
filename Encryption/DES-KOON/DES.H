/*
 * Copyright (c) 1991 David G. Koontz.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the above mentioned individual.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE
 */

/*  des.h -- include file for des.c */

#define TRUE			1
#define FALSE			0
#define SHIFT			1
#define NOSHIFT			0

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#define BIT(x)		    ( 1 << x)
#define TODEC		       16
#define ENCRYPT			1
#define DECRYPT			0
#define NORMAL_OP		1
#define DES_NO_IP		2
#define TESTMODE		3

union LR_block {
    unsigned char string[8];
    unsigned long     LR[2];
};
