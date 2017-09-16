#ifdef ANSI_MODE
void Mother (unsigned long * pSeed);
int save_curve (char * name, CURVE * curv, POINT * point);
int get_curve (char * name, CURVE * curv, POINT * point);
void init_rand (void);
void close_rand (void);
void big_print (char * strng, BIGINT * a);
void print_point (char * title, POINT * p3);
void rand_curv_pnt (POINT * point, CURVE * curve);
void eliptic_hash (INDEX num_words, ELEMENT * data_ptr, BIGINT * result);
void elptic_key_gen (char * string, BIGINT * key);
int get_string (char * buf, int max);
void public_key_gen (BIGINT * skey, PUBKEY * pkey, INDEX full);
int save_pub_key (PUBKEY * pub);
int restore_pub_key (char * name, PUBKEY * pub);
void print_pubkey (PUBKEY * pk);
#endif
#endif
