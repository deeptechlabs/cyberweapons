/*
 * testloki97 - simple program to run a test triple on LOKI97
 *
 * written by Lawrie Brown / May 1998
 */

#include "loki97.h"

main()
{
    int st;

    /* Invoke LOKI97 cipher self-test */
    printf("LOKI97 Self_test\n");
    st = self_test();
    printf("LOKI97 self_test returned %s (%d)\n", (st ? "OK" : "BAD"), st);
}
