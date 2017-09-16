/* entropysources.h */
/* This files contain the defination of the entropy sources */

#ifndef YARROW_ENTROPY_SOURCES_H
#define YARROW_ENTROPY_SOURCES_H

enum entropy_sources {
	KEYTIMESOURCE = 0,
	MOUSETIMESOURCE,
	MOUSEMOVESOURCE,
	SLOWPOLLSOURCE,
	ENTROPY_SOURCES,	/* Leave as second to last source */
	MSG_CLOSE_PIPE		/* Leave as last source */
};

#endif