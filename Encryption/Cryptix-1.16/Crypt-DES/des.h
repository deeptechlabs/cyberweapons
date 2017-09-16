#include <sys/types.h>

typedef u_int8_t  des_user_key[8];
typedef u_int8_t des_cblock[8];
typedef u_int32_t des_ks[32];

void des_crypt( des_cblock in, des_cblock out, des_ks key, int encrypt );
void des_expand_key( des_user_key userKey, des_ks key );

