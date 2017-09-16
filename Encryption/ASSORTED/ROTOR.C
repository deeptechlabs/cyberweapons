/*
 *     Copyright (C) 1993  Eric E. Moore and Thomas W. Strong
 *
 *     All rights reserved.  Any unauthorized distribution of this
 *     program is prohibited.
 */

#include "header.h"

struct rotor {
    char map[ALPHABET_LEN];
    char advance[ALPHABET_LEN];
    char position;
    char id;
};


int advance_rotor_if_necessary(struct rotor * rotor_array[], int i)
{
    int prev_pos;
    int adv_amt;
    
    prev_pos = rotor_array[i]->position;
    if (i == 0) {
	rotor_array[i]->position++;
	rotor_array[i]->position %= ALPHABET_LEN;
	return(rotor_array[i]->advance[prev_pos]);
    }
    adv_amt = advance_rotor_if_necessary(rotor_array, i - 1);
    if (adv_amt != 0) {
	rotor_array[i]->position += adv_amt;
	rotor_array[i]->position %= ALPHABET_LEN;
	return(rotor_array[i]->advance[prev_pos]);
    }
    return(0);
}


int main(int argc,char *argv[])
{
    char c;
    char * key = NULL;
    int i,j,k,key_len;
    int z;
    int decrypt = 0;
    extern int optind, opterr;
    extern char * optarg;
    int num_rotors_read;
    char rotor_order[128];
    char rotorfile[128];
    FILE * rfp;
    char buffer[80];
    char buffer2[80];
    struct rotor * rotor_array[ROTOR_MAX_ROTORS];
    struct rotor * rotors_as_read[ROTOR_MAX_ROTORS];
    
    strcpy(rotorfile, ROTOR_DEF_ROTORFILE);
    rotor_order[0] = '\0';
    
    opterr = 0;
    while ((z = getopt(argc, argv, "dk:r:f:i:o:")) != EOF) {
	switch (z) {
	case 'i':
	    if (freopen(optarg, "r", stdin) == NULL) {
		file_open_error();
	    }
	    break;
	case 'o':
	    if (freopen(optarg, "w", stdout) == NULL) {
		file_open_error();
	    }
	    break;
	case 'd':
	    decrypt = 1;
	    break;
	case 'f':
	    strcpy(rotorfile, optarg);
	    break;
	case 'k':
	    key = get_key(optarg);
	    break;
	case 'r':
	    strcpy(rotor_order, optarg);
	    break;
	case '?':
	    usage(ROTOR_USAGE);
	}
    }
    if (key == NULL) {
	if (argv[optind] == NULL) {
	    usage(ROTOR_USAGE);
	}
	key = get_key(argv[optind]);
    }
    key_len = strlen(key);
    
    
    /* read in the rotor info */
    if ((rfp = fopen(rotorfile,"r")) == NULL) {
        file_open_error();
    }
    
    i = 0;
    while (fscanf(rfp, "%s %s", buffer, buffer2) != EOF) {
	rotors_as_read[i] = (struct rotor *)malloc(sizeof(struct rotor));
	if (rotors_as_read[i] == NULL) {
	    memory_error();
	}
	rotors_as_read[i]->id = buffer[0];
        for (j = 0; j < ALPHABET_LEN; j++) {
	    int tmp;
            rotors_as_read[i]->map[j] = l2n(buffer2[j]);
	    fscanf(rfp, " %d", &tmp);
	    rotors_as_read[i]->advance[j] = tmp;
        }
        i++;
	if (i >= ROTOR_MAX_ROTORS) {
	    die("More rotors defined than the program can handle.", -47);
	}
    }
    num_rotors_read = i;
    if (num_rotors_read < strlen(key)) {
	die("Key too long for rotors", -17);
    }
    
    /* set up rotor order */
    if (rotor_order[0] == '\0') {
	for (i = 0; i < key_len; i++) {
	    rotor_array[i] = rotors_as_read[i];
	}
    } else {
	if (strlen(key) != strlen(rotor_order)) {
	    die("Rotor order must be same length as key", -29);
	}
	for (i = 0; i < key_len; i++) {
	    rotor_array[i] = NULL;
	    for (j = 0; j < num_rotors_read; j++) {
		if (rotor_order[i] == rotors_as_read[j]->id) {
		    rotor_array[i] = rotors_as_read[j];
		}
	    }
	    if (rotor_array[i] == NULL) {
		die("rotor specified but not found in config", -67);
	    }
	}
    }
    
    /* display the rotor selections */
    /*    for (i = 0; i < key_len; i++) {
	  fprintf(stderr, "%c, ", rotor_array[i]->id);
	  for (j = 0; j < 26; j++) {
	  fprintf(stderr, "%c", n2l(rotor_array[i]->map[j]));
	  }
	  fprintf(stderr, "\n");
	  }*/
    
    /* put rotors in initial positions */
    for (i = 0; i < key_len; i++) {
	rotor_array[i]->position = l2n(key[i]);
    }
    
    if (decrypt) {
	/* Invert rotors */
	char tmp[ALPHABET_LEN];
	for (j = 0; j < key_len; j++) {
	    for (i = 0; i < ALPHABET_LEN; i++) {
		tmp[i] = rotor_array[j]->map[i];
	    }
	    for (i = 0; i < ALPHABET_LEN; i++) {
		k = 0;
		while (tmp[k] != i) {
		    k++;
		}
		rotor_array[j]->map[i] = k;
	    }
	}
    }
    
    while ((c = tolower(getchar())) != EOF) {
	if (isalpha(c)) {
	    c = l2n(c);
	    if (! decrypt) {
		/* Encrypt */
		for (i = 0; i < key_len; i++) {
		    c = (c + rotor_array[i]->position) % ALPHABET_LEN;
		    c = (rotor_array[i]->map[(int)c]) % ALPHABET_LEN;
		    c = (c - rotor_array[i]->position + ALPHABET_LEN) %
			ALPHABET_LEN;
		}
	    } else {
		/* Decrypt */
		for (i = key_len - 1; i >= 0; i--) {
		    c = (c + rotor_array[i]->position) % ALPHABET_LEN;
		    c = (rotor_array[i]->map[(int)c]) % ALPHABET_LEN;
		    c = (c - rotor_array[i]->position + ALPHABET_LEN) %
			ALPHABET_LEN;
		}
	    }
	    c = n2l(c);
	    advance_rotor_if_necessary(rotor_array, key_len - 1);
	}
	putchar(c);
    }
    
    printf("\n");
    
    return(0);
}
