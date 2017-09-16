#ifdef ANSI_MODE
void elptic_encrypt (BIGINT * session, PUBKEY * pk, PUBKEY * ek);
int elptic_decrypt (BIGINT * session, PUBKEY * pk, PUBKEY * ek);
ELEMENT elptic_cipher (BIGINT * key, ELEMENT length, char * plain,
                       ELEMENT * crypt, INDEX direction);
void main (void);
#endif
#endif
