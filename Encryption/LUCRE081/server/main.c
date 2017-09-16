#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lucre.h"

/* In the event no function is supplied for one or more of the possible
   initializers, the following defaults are used */
static void *EC_GD_malloc(size_t size)
{
    void *retval;
    retval = malloc(size);
    return retval;
}

static void *EC_GD_realloc(void *ptr, size_t size)
{
    void *retval;
    retval = realloc(ptr, size);
    return retval;
}

static void EC_GD_free(void *ptr)
{
    if (ptr) free(ptr);
}

static void EC_GD_yield(int last_yield)
{
    return;
}

static void EC_GD_log(EC_LogLevel level, const char *text_str)
{
    static const char *logstr[5] = {
	"debug message", "info", "notice", "warning", "ERROR"
	};

    if (level < EC_LOGLEVEL_DEBUG || level > EC_LOGLEVEL_ERROR || !text_str)
	return;
    fprintf(stderr, "%s %s: %s\n", EC_LIB_NAME, logstr[level], text_str);
}

/* These functions are set by EC_main_init and used by everyone else */
void* (*EC_G_malloc)(size_t size) = EC_GD_malloc;
void* (*EC_G_realloc)(void *ptr, size_t size) = EC_GD_realloc;
void (*EC_G_free)(void *ptr) = EC_GD_free;
void (*EC_G_yield)(int last_yield) = EC_GD_yield;
void (*EC_G_log)(EC_LogLevel level, const char *text_str) = EC_GD_log;

/* These functions use the global functions */
char *EC_G_strdup(char *str)
{
    char *ret;
    int len;

    /* strdup, and be paranoid */

    if (!str) return NULL;
    len = strlen(str);
    ret = (char *)EC_G_malloc(len+1);
    if (!ret) return NULL;
    strncpy(ret, str, len);
    ret[len] = '\0';

    return ret;
}

EC_Errno EC_main_init(void *mymalloc(size_t size),
    void *myrealloc(void *data_ptr, size_t size),
    void myfree(void *data_ptr),
    void myyield(int this_is_the_last_yield),
    void mylog(EC_LogLevel level, const char *text_str))
{
    EC_G_malloc = mymalloc ? mymalloc : EC_GD_malloc;
    EC_G_realloc = myrealloc ? myrealloc : EC_GD_realloc;
    EC_G_free = myfree ? myfree : EC_GD_free;
    EC_G_yield = myyield ? myyield : EC_GD_yield;
    EC_G_log = mylog ? mylog : EC_GD_log;

    return EC_ERR_NONE;
}

char *EC_main_get_libver()
{
    return EC_LIB_VERSTR;
}

EC_Errno EC_main_cleanup()
{
    return EC_ERR_NONE;
}
