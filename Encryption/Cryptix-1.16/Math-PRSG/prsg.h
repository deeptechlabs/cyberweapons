#ifndef PRSG_H
#define PRSG_H

typedef struct prsg_info {
    unsigned long reg[5];
} PRSG_INFO;

typedef unsigned char PRSG_SEED[20];

void prsg_seed(PRSG_INFO * context, unsigned char * seed);
void prsg_clock(PRSG_INFO * context);

#endif
