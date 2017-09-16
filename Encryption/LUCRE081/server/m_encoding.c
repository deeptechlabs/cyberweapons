#include <sys/types.h>
#include <unistd.h>
#include "lucre.h"

/* Sample I/O functions */
Int32 EC_G_write_out(Byte *data, UInt32 len, void *state)
{
    int fd = state ? *(int *)state : 1;
    return write(fd, data, len);
}

Int32 EC_G_read_in(Byte *data, UInt32 len, void *state)
{
    int fd = state ? *(int *)state : 0;
    return read(fd, data, len);
}

static EC_Errno do_output(
    Int32 (*output_fcn)(Byte *outdata, UInt32 outlen, void *state),
    Byte *outdata, UInt32 outlen, void *state)
{
    if (!output_fcn) return EC_ERR_NONE;

    while(outlen > 0) {
	Int32 amt = output_fcn(outdata, outlen, state);
	if (amt <= 0) return EC_ERR_INTERNAL;
	outdata += amt;
	outlen -= amt;
    }
    return EC_ERR_NONE;
}

static EC_Errno do_input(
    Int32 (*input_fcn)(Byte *outdata, UInt32 outlen, void *state),
    Byte *indata, UInt32 inlen, void *state)
{
    if (!input_fcn) return EC_ERR_NONE;

    while(inlen > 0) {
	Int32 amt = input_fcn(indata, inlen, state);
	if (amt <= 0) return EC_ERR_INTERNAL;
	indata += amt;
	inlen -= amt;
    }
    return EC_ERR_NONE;
}

/* Convert a message to ASCII transfer encoding.  title, if not NULL, is
   the string to use in place of MESSAGE in the start and end tag lines.
   headers, if not NULL, is a pointer to the text of the headers, which
   are in the form "Tag1: Value1\nTag2: Value2\nTag3: Value3\n".  There
   can be 0 or more heaers.  Each header should end with exactly one
   "\n".  output_fcn(outdata, outlen, state) is a callback function
   which will be called (using the supplied state) when this routine has
   something to output. */

EC_Errno EC_M_ATE_encode(EC_M_Msg msg, char *title, char *headers,
    Int32 (*output_fcn)(Byte *outdata, UInt32 outlen, void *state),
    void *state)
{
    static const char armorenc[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    char outbuf[70];
    int outbufsize;
    Byte *data;
    UInt32 datalen;
    EC_Errno err = EC_ERR_NONE;

    if (!msg) return EC_ERR_INTERNAL;

    if (!output_fcn) output_fcn = EC_G_write_out;

    /* Handle chained messages */
    for(;msg;msg=msg->next) {
	data = msg->data + msg->begin;
	datalen = msg->end - msg->begin;

	if (datalen >= 0x1000000) return EC_ERR_INTERNAL;

	/* Output the start tag line and header lines */
	err = do_output(output_fcn, "-----BEGIN ECASH ", 17, state);
	if (err) return err;
	if (title) {
	    err = do_output(output_fcn, title, strlen(title), state);
	    if (err) return err;
	} else {
	    err = do_output(output_fcn, "MESSAGE", 7, state);
	    if (err) return err;
	}
	err = do_output(output_fcn, "-----\n", 6, state);
	if (err) return err;
	if (headers) {
	    err = do_output(output_fcn, headers, strlen(headers), state);
	    if (err) return err;
	}

	/* Output a blank line */
	err = do_output(output_fcn, "\n", 1, state);
	if (err) return err;

	/* Initialize the output buffer */
	outbufsize=0;
	outbuf[64] = '\n';
	outbuf[65] = '\0';

	/* Create the length-of-message header */
	outbuf[outbufsize++] = armorenc[(0xa0 & 0xfc) >> 2];
	outbuf[outbufsize++] = armorenc[((0xa0 & 0x03) << 4) | ((0xb9 & 0xf0) >> 4)];
	outbuf[outbufsize++] = armorenc[((0xb9 & 0x0f) << 2) | ((0x90 & 0xc0) >> 6)];
	outbuf[outbufsize++] = armorenc[(0x90 & 0x3f)];

	outbuf[outbufsize++] = armorenc[(0x83 & 0xfc) >> 2];
	outbuf[outbufsize++] = armorenc[((0x83 & 0x03) << 4) | (((datalen >> 16) & 0xf0) >> 4)];
	outbuf[outbufsize++] = armorenc[(((datalen >> 16) & 0x0f) << 2) | (((datalen >> 8) & 0xc0) >> 6)];
	outbuf[outbufsize++] = armorenc[((datalen >> 8) & 0x3f)];

	outbuf[outbufsize++] = armorenc[(datalen & 0xfc) >> 2];
	outbuf[outbufsize++] = armorenc[((datalen & 0x03) << 4) | ((0xa1 & 0xf0) >> 4)];
	if (datalen >= 1) {
	    outbuf[outbufsize++] = armorenc[((0xa1 & 0x0f) << 2) | ((data[0] & 0xc0) >> 6)];
	    outbuf[outbufsize++] = armorenc[(data[0] & 0x3f)];
	    --datalen;
	    ++data;
	} else {
	    outbuf[outbufsize++] = armorenc[(0xa1 & 0x0f) << 2];
	    outbuf[outbufsize++] = '=';
	}

	/* Continue on for the rest of the message */
	while(datalen >= 3) {
	    /* Translate 3 data bytes to 4 output bytes */
	    outbuf[outbufsize++] = armorenc[(data[0] & 0xfc) >> 2];
	    outbuf[outbufsize++] = armorenc[((data[0] & 0x03) << 4) | ((data[1] & 0xf0) >> 4)];
	    outbuf[outbufsize++] = armorenc[((data[1] & 0x0f) << 2) | ((data[2] & 0xc0) >> 6)];
	    outbuf[outbufsize++] = armorenc[(data[2] & 0x3f)];

	    data += 3;
	    datalen -= 3;

	    /* Possibly output a full buffer */
	    if (outbufsize == 64) {
		err = do_output(output_fcn, outbuf, 65, state);
		if (err) return err;
		outbufsize = 0;
	    }
	}

	/* Deal with bits at the end */
	if (datalen == 1) {
	    outbuf[outbufsize++] = armorenc[(data[0] & 0xfc) >> 2];
	    outbuf[outbufsize++] = armorenc[(data[0] & 0x03) << 4];
	    outbuf[outbufsize++] = '=';
	    outbuf[outbufsize++] = '=';
	} else if (datalen == 2) {
	    outbuf[outbufsize++] = armorenc[(data[0] & 0xfc) >> 2];
	    outbuf[outbufsize++] = armorenc[((data[0] & 0x03) << 4) | ((data[1] & 0xf0) >> 4)];
	    outbuf[outbufsize++] = armorenc[(data[1] & 0x0f) << 2];
	    outbuf[outbufsize++] = '=';
	}

	/* Output the rest of the buffer */
	if (outbufsize > 0) {
	    outbuf[outbufsize++] = '\n';
	    outbuf[outbufsize] = '\0';
	    err = do_output(output_fcn, outbuf, outbufsize, state);
	}

	/* Output the end tag line */
	err = do_output(output_fcn, "-----END ECASH ", 15, state);
	if (err) return err;
	if (title) {
	    err = do_output(output_fcn, title, strlen(title), state);
	    if (err) return err;
	} else {
	    err = do_output(output_fcn, "MESSAGE", 7, state);
	    if (err) return err;
	}
	err = do_output(output_fcn, "-----\n", 6, state);
	if (err) return err;
    }
    return EC_ERR_NONE;
}

/* As above, only for the binary transfer encoding.  There are no titles
   or headers here. */
EC_Errno EC_M_BTE_encode(EC_M_Msg msg,
    Int32 (*output_fcn)(Byte *outdata, UInt32 outlen, void *state),
    void *state)
{
    Byte lombuf[8];
    Byte *data;
    UInt32 datalen;
    EC_Errno err = EC_ERR_NONE;

    /* Determine the location and length of the message */
    if (!msg) return EC_ERR_INTERNAL;

    if (!output_fcn) output_fcn = EC_G_write_out;

    /* Handle chained messages */
    for(;msg;msg=msg->next) {
	data = msg->data + msg->begin;
	datalen = msg->end - msg->begin;

	if (datalen >= 0x1000000) return EC_ERR_INTERNAL;

	/* Create the length-of-message header */
	lombuf[0] = 0xa0;
	lombuf[1] = 0xb9;
	lombuf[2] = 0x90;
	lombuf[3] = 0x83;
	lombuf[4] = (datalen >> 16) & 0xff;
	lombuf[5] = (datalen >> 8) & 0xff;
	lombuf[6] = (datalen) & 0xff;
	lombuf[7] = 0xa1;

	err = do_output(output_fcn, lombuf, 8, state);
	if (err) return err;
	err = do_output(output_fcn, data, datalen, state);
	if (err) return err;
    }

    return EC_ERR_NONE;
}

/* Construct a message from a binary transfer encoding, which will be input
   via calls to the input_fcn callback. */
EC_Errno EC_M_BTE_decode(EC_M_Msg msg,
    Int32 (*input_fcn)(Byte *indata, UInt32 inlen, void *state),
    void *state)
{
    Byte lombuf[8];
    Byte *databuf;
    UInt32 datalen;
    EC_Errno err;

    if (!msg) return EC_ERR_INTERNAL;

    if (!input_fcn) input_fcn = EC_G_read_in;

    /* Read the length-of-message header */
    err = do_input(input_fcn, lombuf, 8, state);
    if (err) return err;

    /* Check its validity */
    if (lombuf[0] != 0xa0 || lombuf[1] != 0xb9 || lombuf[2] != 0x90 ||
	lombuf[3] != 0x83 || lombuf[7] != 0xa1) {
	return EC_ERR_INTERNAL;
    }

    /* It's OK; retrieve the data length */
    datalen = (lombuf[4] << 16) | (lombuf[5] << 8) | lombuf[6];

    /* Create a buffer */
    databuf = (Byte *)EC_G_malloc(datalen);
    if (!databuf) return EC_ERR_INTERNAL;

    /* Read the data */
    err = do_input(input_fcn, databuf, datalen, state);
    if (err) return err;

    /* Append it to the message */
    err = EC_M_append_msg(databuf, datalen, msg);
    if (err) return err;

    /* Free the buffer */
    EC_G_free(databuf);

    return EC_ERR_NONE;
}

/* Construct a message from an ASCII transfer encoding, which will be input
   via calls to the input_fcn callback. */
EC_Errno EC_M_ATE_decode(EC_M_Msg msg,
    Int32 (*input_fcn)(Byte *indata, UInt32 inlen, void *state),
    void *state)
{
    int scanstate;
    int done;
    Byte scanbuf[100];  /* Must be a multiple of 4 */
    const char header[] = { "BEGIN ECASH" }; /* must start with B */
    int i,j;
    int msglen, scanlen, readlen;
    int numnl, numcr;
    EC_Errno err;

    if (!msg) return EC_ERR_INTERNAL;

    if (!input_fcn) input_fcn = EC_G_read_in;

    /* This is going to be fairly inefficient; it should be fixed */

    scanstate = 0;
    done = 0;
    while(!done) {
	switch(scanstate) {
	case 0:
	    /* Still looking for the leading hyphens */
	    err = do_input(input_fcn, scanbuf, 1, state);
	    if (err) return err;

	    if (scanbuf[0] == '-') scanstate = 1;
	    break;

	case 1:
	    /* Seen at least one leading hyphen; looking for B */
	    /* Ignore whitespace and > */
	    err = do_input(input_fcn, scanbuf, 1, state);
	    if (err) return err;

	    switch(scanbuf[0]) {
		case '-': case ' ': case '\t': case '\n': case '\r': case '\f':
		case '>': scanstate = 1; break;

		case 'B': scanstate = 2; break;

		default: scanstate = 0; break;
	    }

	    break;

	case 2:
	    /* Seen leading hyphens and B; look for "EGIN ECASH" */
	    for (i=1;i<strlen(header);++i) {
		err = do_input(input_fcn, scanbuf, 1, state);
		if (err) return err;

		if (scanbuf[0] == header[i]) { continue; }
		if (scanbuf[0] == '-') { scanstate = 1; break; }
		scanstate = 0; break;
	    }
	    if (scanstate == 2) scanstate = 3;
	    break;

	case 3:
	    /* Eat things until hyphens */
	    err = do_input(input_fcn, scanbuf, 1, state);
	    if (err) return err;

	    if (scanbuf[0] == '-') scanstate = 4;
	    break;

	case 4:
	    /* Scan for the end of the headers */
	    numnl = 0; numcr = 0;
	    while(numnl < 2 && numcr < 2) {
		err = do_input(input_fcn, scanbuf, 1, state);
		if (err) return err;

		if (scanbuf[0] == '\n') {
		    numnl++;
		} else if (scanbuf[0] == '\r') {
		    numcr++;
		} else if (scanbuf[0] != ' ' && scanbuf[0] != '>' &&
			    scanbuf[0] != '\t' && scanbuf[0] != '\f') {
		    numnl = 0;
		    numcr = 0;
		}
	    }
	    scanstate = 5;
	    break;

	case 5:
	    /* Find the start of the data */
	    err = do_input(input_fcn, scanbuf, 1, state);
	    if (err) return err;

	    if (scanbuf[0] >= 'A' && scanbuf[0] <= 'Z') {
		scanbuf[0] -= 'A';
		scanstate = 6;
	    } else if (scanbuf[0] >= 'a' && scanbuf[0] <= 'z') {
		scanbuf[0] -= ('a' - 26);
		scanstate = 6;
	    } else if (scanbuf[0] >= '0' && scanbuf[0] <= '9') {
		scanbuf[0] += (52 - '0');
		scanstate = 6;
	    } else if (scanbuf[0] == '+') {
		scanbuf[0] = 62;
		scanstate = 6;
	    } else if (scanbuf[0] == '/') {
		scanbuf[0] = 63;
		scanstate = 6;
	    }
	    break;

	case 6:
	    /* Find the length */
	    scanlen = 1;
	    while (scanlen < 12) {
		err = do_input(input_fcn, scanbuf+scanlen, 12-scanlen, state);
		if (err) return err;
		for(i=scanlen,j=scanlen;i<12;++i) {
		    if (scanbuf[i] >= 'A' && scanbuf[i] <= 'Z') {
			scanbuf[j] = scanbuf[i] - 'A';
			++j;
		    } else if (scanbuf[i] >= 'a' && scanbuf[i] <= 'z') {
			scanbuf[j] = scanbuf[i] - ('a' - 26);
			++j;
		    } else if (scanbuf[i] >= '0' && scanbuf[i] <= '9') {
			scanbuf[j] = scanbuf[i] + (52 - '0');
			++j;
		    } else if (scanbuf[i] == '+') {
			scanbuf[j] = 62;
			++j;
		    } else if (scanbuf[i] == '/') {
			scanbuf[j] = 63;
			++j;
		    }
		}
		scanlen = j;
	    }
	    /* Read the length header */
	    if (scanbuf[0] != 0x28 || scanbuf[1] != 0x0b || scanbuf[2] != 0x26
	     || scanbuf[3] != 0x10 || scanbuf[4] != 0x20) {
		return EC_ERR_INTERNAL;
	    }
	    if (scanbuf[5] < 0x30) return EC_ERR_INTERNAL;
	    if ((scanbuf[9] & 0x0f) != 0x0a) return EC_ERR_INTERNAL;
	    if ((scanbuf[10] & 0x3c) != 0x04) return EC_ERR_INTERNAL;
	    msglen = (scanbuf[5] - 0x30); msglen <<= 6;
	    msglen |= scanbuf[6]; msglen <<= 6;
	    msglen |= scanbuf[7]; msglen <<= 6;
	    msglen |= scanbuf[8]; msglen <<= 2;
	    msglen |= (scanbuf[9] >> 4);
	    if (msglen > 0) {
		scanbuf[0] = (((scanbuf[10] & 0x03) << 6) | scanbuf[11]);
		err = EC_M_append_msg(scanbuf, 1, msg);
		if (err) return err;
		--msglen;
		scanstate = 7;
	    } else {
		scanstate = 8;
	    }
	    break;

	case 7:
	    /* Read the body of the message */

	    /* How much to read? */
	    readlen = (msglen / 3) * 4;
	    if (msglen % 3) {
		readlen += 4;
	    }
	    if (readlen > sizeof(scanbuf)) {
		readlen = sizeof(scanbuf);
	    }

	    /* Gather that many valid characters */
	    scanlen = 0;
	    while(scanlen < readlen) {
		err = do_input(input_fcn, scanbuf+scanlen, readlen-scanlen,
				state);
		if (err) return err;
		for(i=scanlen,j=scanlen;i<readlen;++i) {
		    if (scanbuf[i] >= 'A' && scanbuf[i] <= 'Z') {
			scanbuf[j] = scanbuf[i] - 'A';
			++j;
		    } else if (scanbuf[i] >= 'a' && scanbuf[i] <= 'z') {
			scanbuf[j] = scanbuf[i] - ('a' - 26);
			++j;
		    } else if (scanbuf[i] >= '0' && scanbuf[i] <= '9') {
			scanbuf[j] = scanbuf[i] + (52 - '0');
			++j;
		    } else if (scanbuf[i] == '+') {
			scanbuf[j] = 62;
			++j;
		    } else if (scanbuf[i] == '/') {
			scanbuf[j] = 63;
			++j;
		    } else if (scanbuf[i] == '=') {
			scanbuf[j] = 0;
			++j;
		    } else if (scanbuf[i] == '-') {
			/* The message was too short! */
			return EC_ERR_INTERNAL;
		    }
		}
		scanlen = j;
	    }

	    /* Decode them */
	    for(i=0,j=0;i<readlen;i+=4) {
		scanbuf[j] = ((scanbuf[i] << 2)
				| ((scanbuf[i+1] & 0x30) >> 4));
		scanbuf[j+1] = (((scanbuf[i+1] & 0x0f) << 4)
				| ((scanbuf[i+2] & 0x3c) >> 2));
		scanbuf[j+2] = (((scanbuf[i+2] & 0x03) << 6)
				| (scanbuf[i+3]));
		j += 3;
	    }

	    /* Append them to the msg */
	    if (j > msglen) {
		j = msglen;
	    }
	    err = EC_M_append_msg(scanbuf, j, msg);
	    if (err) return err;

	    /* See if we have to read any more */
	    msglen -= j;
	    if (!msglen) {
		scanstate = 8;
	    }

	    break;

	case 8:
	    /* Find the hyphens before the end */
	    do {
		err = do_input(input_fcn, scanbuf, 1, state);
		if (err) return err;
	    } while (scanbuf[0] != '-');

	    /* Get a string of hyphens or whitespace */
	    do {
		err = do_input(input_fcn, scanbuf, 1, state);
		if (err) return err;
	    } while (scanbuf[0] == '-' || scanbuf[0] == ' '
		    || scanbuf[0] == '\t' || scanbuf[0] == '\n'
		    || scanbuf[0] == '\r' || scanbuf[0] == '\f'
		    || scanbuf[0] == '>');

	    /* Get a string of non-hyphens */
	    do {
		err = do_input(input_fcn, scanbuf, 1, state);
		if (err) return err;
	    } while (scanbuf[0] != '-');

	    /* Get up to four more hyphens */
	    i = 1;
	    while(i<5) {
		err = do_input(input_fcn, scanbuf, 1, state);
		if (err) return err;

		if (scanbuf[0] == '-') {
		    ++i;
		} else if (scanbuf[0] != ' ' && scanbuf[0] != '>'
			&& scanbuf[0] != '\t' && scanbuf[0] != '\n'
			&& scanbuf[0] != '\r' && scanbuf[0] != '\f') {
		    break;
		}
	    }

	    /* Successful scanning */
	    done = 1;

	    break;
	}
    }

    return EC_ERR_NONE;
}
