#ifndef __EC_CRYPT_H
#define __EC_CRYPT_H

#include "ec_curve.h"
#include "ec_vlong.h"

typedef struct {
	vlPoint r, s;
} cpPair;


void cpMakePublicKey (vlPoint vlPublicKey, const vlPoint vlPrivateKey);
void cpEncodeSecret (const vlPoint vlPublicKey, vlPoint vlMessage, vlPoint vlSecret);
void cpDecodeSecret (const vlPoint vlPrivateKey, const vlPoint vlMessage, vlPoint d);
void cpSign(const vlPoint vlPrivateKey, const vlPoint secret, const vlPoint mac, cpPair * cpSig);
int  cpVerify(const vlPoint vlPublicKey, const vlPoint vlMac, cpPair * cpSig );

#endif /* __EC_CRYPT_H */
