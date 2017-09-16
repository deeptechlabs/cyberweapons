#include "lucre.h"

/* Allocate a new tally */
EC_W_Tally EC_W_new_tally(void)
{
    EC_W_Tally tally;

    /* Allocate the memory */
    tally = (EC_W_Tally)EC_G_malloc(sizeof(struct EC_W_Tally_s));
    if (!tally) return tally;

    /* Initialize the fields */
    tally->numvers = 0;
    tally->ver = NULL;

    return tally;
}

/* Clear a tally */
void EC_W_clear_tally(EC_W_Tally tally)
{
    int i,j;
    EC_M_Coindata coindata;

    if (!tally) return;

    for(i=0;i<tally->numvers;++i) {
	if (tally->ver[i].ncoins) EC_G_free(tally->ver[i].ncoins);
	if (tally->ver[i].coindata) {
	    /* Free each chain for each denomination */
	    for(j=0;j<tally->ver[i].ndenom;++j) {
		coindata = tally->ver[i].coindata[j];
		while(coindata) {
		    EC_M_Coindata next = coindata->next;
		    EC_M_free_coindata(coindata);
		    coindata = next;
		}
	    }
	    EC_G_free(tally->ver[i].coindata);
	}
    }
    if (tally->ver) EC_G_free(tally->ver);
    tally->ver = NULL;
    tally->numvers = 0;
}

/* Free a tally */
void EC_W_free_tally(EC_W_Tally tally)
{
    if (!tally) return;

    EC_W_clear_tally(tally);
    EC_G_free(tally);
}

/* Wrapper for EC_W_tally_inc_coin */
EC_Errno EC_W_tally_inc(EC_W_Tally tally, UInt32 keyversion, Int32 amt,
    EC_W_Tallyflags flags)
{
    return EC_W_tally_inc_coin(tally, keyversion, amt, flags, NULL);
}

/* Increment an element of a tally */
EC_Errno EC_W_tally_inc_coin(EC_W_Tally tally, UInt32 keyversion, Int32 amt,
    EC_W_Tallyflags flags, EC_M_Coindata coindata)
{
    int i, found;
    UInt32 currversion, denom;
    EC_Errno err = EC_ERR_NONE;

    if (!tally) return EC_ERR_INTERNAL;

    /* Separate the keyversion */
    currversion = keyversion & ~EC_M_KEYVER_VALMASK;
    denom = keyversion & EC_M_KEYVER_VALMASK;

    /* Check the flags */
    if (flags & EC_W_TALLY_MERGECVER) currversion = 0;
    if (flags & EC_W_TALLY_MERGEDENOM) denom = 0;

    found = -1;
    /* See if we have this keyversion already */
    for(i=0;i<tally->numvers;++i) {
	if (currversion == tally->ver[i].keyversion) {
	    found = i;
	    break;
	}
    }
    if (found < 0) {
	/* Add a new keyversion */
	struct EC_W_Tally1_s *newver;
	
	newver = (struct EC_W_Tally1_s *)EC_G_realloc(tally->ver,
	    sizeof(struct EC_W_Tally1_s)*(tally->numvers+1));

	if (!newver) return EC_ERR_INTERNAL;

	newver[tally->numvers].keyversion = currversion;
	newver[tally->numvers].ndenom = 0;
	newver[tally->numvers].ncoins = NULL;
	newver[tally->numvers].coindata = NULL;
	tally->ver = newver;
	found = tally->numvers;
	++tally->numvers;
    }
    /* Make sure the ncoins array is long enough for the denom */
    if (tally->ver[found].ndenom <= denom) {
	UInt32 *newncoins = (UInt32 *)EC_G_realloc(tally->ver[found].ncoins,
	    sizeof(UInt32)*(denom+1));
	EC_M_Coindata *newcoindata =
	    (EC_M_Coindata *)EC_G_realloc(tally->ver[found].coindata,
	    sizeof(EC_M_Coindata)*(denom+1));
	int i;

	if (!newncoins || !newcoindata) return EC_ERR_INTERNAL;

	for(i=tally->ver[found].ndenom;i<=denom;++i) {
	    newncoins[i] = 0;
	    newcoindata[i] = NULL;
	}
	tally->ver[found].ncoins = newncoins;
	tally->ver[found].coindata = newcoindata;
	tally->ver[found].ndenom = denom+1;
    }
    /* Increment it as required */
    tally->ver[found].ncoins[denom] += amt;

    /* See if we need to store the actual coindata */
    if (flags & EC_W_TALLY_VERBOSE) {
	err = EC_W_tally_inscoin(&tally->ver[found].coindata[denom], coindata);
	if (err) return EC_ERR_INTERNAL;
    }

    return EC_ERR_NONE;
}

/* Insert a coindata into a chain of them (in order of keyversion) */
EC_Errno EC_W_tally_inscoin(EC_M_Coindata *head, EC_M_Coindata coindata)
{
    EC_M_Coindata newcoin;
    
    if (!head) return EC_ERR_INTERNAL;
    if (!coindata) return EC_ERR_NONE;

    /* Copy the coin */
    newcoin = EC_M_clone_coindata(coindata);
    if (!newcoin) return EC_ERR_INTERNAL;

    while(*head && (*head)->keyversion < coindata->keyversion) {
	head = &((*head)->next);
    }
    /* Put the new item here */
    newcoin->next = *head;
    *head = newcoin;

    return EC_ERR_NONE;
}

/* Find the value and number of coins in a tally */
UInt32 EC_W_tally_value(EC_W_Tally tally, UInt32 *pncoins)
{
    UInt32 amt = 0;
    UInt32 ncoins = 0;
    int i,j;

    if (!tally) {
	if (pncoins) *pncoins = 0;
	return 0;
    }

    for(i=0;i<tally->numvers;++i) {
	UInt32 value = 1;
        for(j=0;j<tally->ver[i].ndenom;++j,value<<=1) {
            UInt32 k = tally->ver[i].ncoins[j];
            ncoins += k;
            amt += value * k;
        }
    }

    if (pncoins) *pncoins = ncoins;
    return amt;
}
