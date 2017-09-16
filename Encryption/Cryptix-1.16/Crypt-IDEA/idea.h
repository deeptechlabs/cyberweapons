#include <sys/types.h>

#define IDEA_KS_SIZE 104

typedef u_int16_t idea_cblock[4];
typedef u_int16_t idea_user_key[8];
typedef u_int16_t idea_ks[52];

void idea_crypt(idea_cblock in, idea_cblock out, idea_ks key);
void idea_invert_key(idea_ks key, idea_ks inv_key);
void idea_expand_key(idea_user_key userKey, idea_ks key);
