/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

#include "header.h"

char * get_key(char * input_key)
{
    char * key;
    char * keyptr;

    keyptr = (char *)malloc(strlen(input_key+1));
    if (keyptr == NULL) {
	memory_error();
    }
    key = keyptr;
    while (*input_key) {
	if (isalpha(*input_key)) {
	    *keyptr = *input_key;
	    keyptr++;
	}
	input_key++;
    }
    *keyptr = '\0';
    return(key);
}
