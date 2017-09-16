#include <string.h>
#include "lucre.h"

EC_M_Msg EC_M_new_msg()
{
    EC_M_Msg msg = (EC_M_Msg)EC_G_malloc(sizeof(struct EC_M_Msg_s));

    if (!msg) return NULL;

    msg->data = NULL;
    msg->alloc = 0;
    msg->begin = 0;
    msg->end = 0;
    msg->next = NULL;

    return msg;
}

EC_M_Msg EC_M_clone_msg(EC_M_Msg oldmsg)
{
    EC_M_Msg msg;

    if (!oldmsg) return NULL;

    msg = (EC_M_Msg)EC_G_malloc(sizeof(struct EC_M_Msg_s));
    if (!msg) return NULL;

    /* We copy _all_ of the old message so that we can seek on the copy */
    msg->next = EC_M_clone_msg(oldmsg->next);
    if (oldmsg->next && !msg->next) {
	EC_G_free(msg);
	return NULL;
    }
    msg->alloc = oldmsg->alloc;
    msg->begin = oldmsg->begin;
    msg->end = oldmsg->end;
    if (msg->alloc > 0) {
	msg->data = (Byte *)EC_G_malloc(msg->alloc);
	if (!msg->data) {
	    EC_M_free_msg(msg->next);
	    EC_G_free(msg);
	    return NULL;
	}
	memmove(msg->data, oldmsg->data, msg->alloc);
    } else {
	msg->data = NULL;
    }

    return msg;
}

UInt32 EC_M_cmp_msg(EC_M_Msg msg1, EC_M_Msg msg2)
{
    if (!msg1 && !msg2) return 0;
    if (!msg1 || !msg2) return 1;

    if (msg1->end - msg1->begin != msg2->end - msg2->begin
     || (msg1->end - msg1->begin > 0 && memcmp(msg1->data + msg1->begin,
		 msg2->data + msg2->begin, msg1->end - msg1->begin))
     || EC_M_cmp_msg(msg1->next, msg2->next))
	return 1;

    return 0;
}

void EC_M_free_msg(EC_M_Msg msg)
{
    if (msg) {
	if (msg->data) EC_G_free(msg->data);
	EC_M_free_msg(msg->next);
	EC_G_free(msg);
    }
}

void EC_M_clear_msg(EC_M_Msg msg)
{
    if (msg) {
	if (msg->data) EC_G_free(msg->data);
	msg->data = NULL;
	msg->alloc = 0;
	msg->begin = 0;
	msg->end = 0;
	EC_M_free_msg(msg->next);
	msg->next = NULL;
    }
}

EC_Errno EC_M_append_msg(Byte *data, UInt32 len, EC_M_Msg msg)
{
    if (!msg) return EC_ERR_INTERNAL;
    if (len == 0) return EC_ERR_NONE;
    if (!data) return EC_ERR_INTERNAL;
    if (msg->end + len > msg->alloc) {
	/* Must allocate more memory */
	int newalloc = msg->end + len;

	/* How much?  At least 200 bytes at a time. */
	if (newalloc < msg->alloc + 200) {
	    newalloc = msg->alloc + 200;
	}
	msg->data = EC_G_realloc(msg->data, newalloc);
	if (!msg->data) return EC_ERR_INTERNAL;
	msg->alloc = newalloc;
    }

    /* Append the data */
    memmove(msg->data+msg->end, data, len);
    msg->end += len;
    return EC_ERR_NONE;
}

EC_M_Msgpos EC_M_tell_msg(EC_M_Msg msg)
{
    EC_M_Msgpos pos = {0,0} ;
    if (!msg) return pos;

    pos.begin = msg->begin;
    pos.end = msg->end;

    return pos;
}

EC_Errno EC_M_seek_msg(EC_M_Msgpos pos, EC_M_Msg msg)
{
    if (msg && pos.begin <= pos.end && pos.end <= msg->end) {
	msg->begin = pos.begin;
	msg->end = pos.end;
	return EC_ERR_NONE;
    }
    return EC_ERR_INTERNAL;
}

EC_Errno EC_M_rewind_msg(EC_M_Msg msg)
{
    EC_M_Msgpos pos = EC_M_tell_msg(msg);
    pos.begin = 0;
    return EC_M_seek_msg(pos, msg);
}

BIGNUM *EC_M_clone_MPI(BIGNUM *mpi)
{
    if (!mpi) return NULL;
    return BN_dup(mpi);
}

UInt32 EC_M_cmp_MPI(BIGNUM *mpi1, BIGNUM *mpi2)
{
    if (!mpi1 || !mpi2) return 1;

    if (BN_cmp(mpi1, mpi2))
	return 1;

    return 0;
}

void EC_M_free_MPI(BIGNUM *mpi)
{
    if (mpi) BN_free(mpi);
}

Byte *EC_M_clone_data(Byte *data, UInt32 len)
{
    Byte *retval;

    if (!data) return NULL;
    retval = (Byte *)EC_G_malloc(len);
    if (!retval) return NULL;
    memmove(retval, data, len);

    return retval;
}

UInt32 EC_M_cmp_data(Byte *data1, Byte *data2, UInt32 len)
{
    if (len == 0) return 0;

    if (!data1 || !data2) return 1;

    if (memcmp(data1, data2, len))
	return 1;

    return 0;
}

void EC_M_free_data(Byte *data)
{
    if (data) EC_G_free(data);
}

/* Message constructors */
static EC_Errno EC_M_compile_int_or_time(Byte tag, UInt32 val, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    Byte buffer[6];
    int len = 0;

    buffer[0] = tag;
    buffer[2] = (val >> 24) & 0xff;
    buffer[3] = (val >> 16) & 0xff;
    buffer[4] = (val >> 8) & 0xff;
    buffer[5] = (val) & 0xff;
    /* How long is the data? */
    if (tag == 0x91) {
	/* time is always 4 bytes */
	len = 4;
    } else {
	/* Check how long it is (at least 1 byte, at most 4) */
	for(len = 4; len >= 2 && buffer[6-len] == 0; --len) {}
    }
    buffer[1] = 0x80 + len;

    if (!err) err = EC_M_append_msg(buffer, 2, msg);
    if (!err) err = EC_M_append_msg(buffer+6-len, len, msg);
    return err;
}

EC_Errno EC_M_compile_int(UInt32 val, EC_M_Msg msg)
{
    return EC_M_compile_int_or_time(0x90, val, msg);
}

EC_Errno EC_M_compile_time(time_t val, EC_M_Msg msg)
{
    return EC_M_compile_int_or_time(0x91, (UInt32)val, msg);
}

static EC_Errno EC_M_compile_string_or_data(Byte tag, Byte *val, UInt32 len,
    EC_M_Msg msg)
{
    Byte buffer[6];
    EC_Errno err = EC_ERR_NONE;

    buffer[0] = tag;
    if (len < 127) {
	buffer[1] = 0x80 + len;
	err = EC_M_append_msg(buffer, 2, msg);
    } else if (len < 0x4000) {
	buffer[1] = 0x40 + (len >> 8);
	buffer[2] = len & 0xff;
	err = EC_M_append_msg(buffer, 3, msg);
    } else {
	buffer[1] = 0xff;
	buffer[2] = (len >> 24) & 0xff;
	buffer[3] = (len >> 16) & 0xff;
	buffer[4] = (len >> 8) & 0xff;
	buffer[5] = (len) & 0xff;
	err = EC_M_append_msg(buffer, 6, msg);
    }

    if (!err && tag != 0xa0) {
	if (len && !val) return EC_ERR_INTERNAL;
	err = EC_M_append_msg(val, len, msg);
    }
    return err;
}

EC_Errno EC_M_compile_string(char *val, EC_M_Msg msg)
{
    if (!val) return EC_M_compile_string_or_data(0x92, NULL, 0, msg);
    return EC_M_compile_string_or_data(0x92, (Byte *)val, strlen(val), msg);
}

EC_Errno EC_M_compile_MPI(BIGNUM *val, EC_M_Msg msg)
{
    Byte *valbin;
    UInt32 vallen;
    EC_Errno err = EC_ERR_NONE;

    if (!val) return EC_ERR_INTERNAL;
    vallen = BN_num_bytes(val);
    valbin = (Byte *)EC_G_malloc(vallen);
    if (!valbin) return EC_ERR_INTERNAL;
    BN_bn2bin(val, valbin);
    err = EC_M_compile_string_or_data(0x93, valbin, vallen, msg);
    EC_G_free(valbin);
    return err;
}

EC_Errno EC_M_compile_data(Byte *val, UInt32 len, EC_M_Msg msg)
{
    if (len && !val) return EC_ERR_INTERNAL;
    return EC_M_compile_string_or_data(0x94, val, len, msg);
}

EC_Errno EC_M_compile_sor(UInt32 type, EC_M_Msg msg)
{
    return EC_M_compile_string_or_data(0xa0, NULL, type, msg);
}

/* Note: if you change this, make the appropriate changes to
   m_payment_hdr.c as well! */
EC_Errno EC_M_compile_eor(EC_M_Msg msg)
{
    Byte buffer[1] = { 0xa1 };

    return EC_M_append_msg(buffer, 1, msg);
}

/* Message readers */
static EC_Errno EC_M_get_field_from_msg(EC_M_Fieldtype *fieldtype,
    EC_M_Fieldval *fieldval, EC_M_Msg msg, int eat)
{
    EC_M_Fieldtype type;
    UInt32 nextval;
    UInt32 bytesseen;
    int i;

    if (!msg || !msg->alloc || msg->begin >= msg->end) {
	if (fieldtype) *fieldtype = EC_M_FIELD_NONE;
	return EC_ERR_NONE;
    }

    switch(msg->data[msg->begin]) {
	case 0x90: type = EC_M_FIELD_INT; break;
	case 0x91: type = EC_M_FIELD_TIME; break;
	case 0x92: type = EC_M_FIELD_STRING; break;
	case 0x93: type = EC_M_FIELD_MPI; break;
	case 0x94: type = EC_M_FIELD_DATA; break;
	case 0xa0: type = EC_M_FIELD_SOR; break;
	case 0xa1: type = EC_M_FIELD_EOR; break;
	default: return EC_ERR_INTERNAL;
    }

    if (type != EC_M_FIELD_EOR) {
	if (msg->begin+1 < msg->end && msg->data[msg->begin+1] >= 0x80
	   && msg->data[msg->begin+1] < 0xff) {
	   nextval = msg->data[msg->begin+1] - 0x80;
	   bytesseen = 2;
	} else if (msg->begin+2 < msg->end
	   && msg->data[msg->begin+1] < 0xff) {
	   nextval =
		 ((msg->data[msg->begin+1] - 0x40)<<8)
	       | (msg->data[msg->begin+2]);
	   bytesseen = 3;
	} else if (msg->begin+5 < msg->end) {
	   nextval =
		 ((msg->data[msg->begin+2]) << 24)
	       | ((msg->data[msg->begin+3]) << 16)
	       | ((msg->data[msg->begin+4]) << 8)
	       | (msg->data[msg->begin+5]);
	   bytesseen = 6;
	} else {
	   return EC_ERR_INTERNAL;
	}

	if (fieldtype) *fieldtype = type;
	if (type == EC_M_FIELD_SOR) {
	    if (fieldval) fieldval->rectype = (EC_M_Rectype) nextval;
	    if (eat) msg->begin += bytesseen;
	} else if (msg->begin + bytesseen + nextval > msg->end) {
	    /* We don't have enough data to finish the field! */
	    return EC_ERR_INTERNAL;
	} else if (eat) {
	    /* Read the actual data, and mark it as such */
	    msg->begin += bytesseen;
	    if (fieldval) {
		switch(type) {
		case EC_M_FIELD_INT:
		    fieldval->intval = 0;
		    for(i=0;i<nextval;++i) {
			fieldval->intval <<= 8;
			fieldval->intval |= msg->data[msg->begin+i];
		    }
		    break;
		case EC_M_FIELD_TIME:
		    fieldval->timeval = 0;
		    for(i=0;i<nextval;++i) {
			fieldval->timeval <<= 8;
			fieldval->timeval |= msg->data[msg->begin+i];
		    }
		    break;
		case EC_M_FIELD_STRING:
		    fieldval->stringval = (char *)EC_G_malloc(nextval+1);
		    if (!fieldval->stringval) return EC_ERR_INTERNAL;
		    memmove(fieldval->stringval, msg->data+msg->begin,
			nextval);
		    fieldval->stringval[nextval] = '\0';
		    break;
		case EC_M_FIELD_MPI:
		    fieldval->MPIval = BN_bin2bn(msg->data+msg->begin,
			nextval, NULL);
		    if (!fieldval->MPIval) return EC_ERR_INTERNAL;
		    break;
		case EC_M_FIELD_DATA:
		    fieldval->dataval.data = (Byte *)EC_G_malloc(nextval);
		    if (!fieldval->dataval.data) return EC_ERR_INTERNAL;
		    memmove(fieldval->dataval.data, msg->data+msg->begin,
			nextval);
		    fieldval->dataval.len = nextval;
		    break;
		default:
		    return EC_ERR_INTERNAL;
		}
	    }
	    msg->begin += nextval;
	}
    } else {
	if (fieldtype) *fieldtype = type;
	if (eat) msg->begin += 1;
    }
    return EC_ERR_NONE;
}

void EC_M_free_fieldval(EC_M_Fieldtype fieldtype, EC_M_Fieldval fieldval)
{
    switch(fieldtype) {
    case EC_M_FIELD_STRING:
	if (fieldval.stringval) EC_G_free(fieldval.stringval);
	break;
    case EC_M_FIELD_MPI:
	EC_M_free_MPI(fieldval.MPIval);
	break;
    case EC_M_FIELD_DATA:
	if (fieldval.dataval.data) EC_G_free(fieldval.dataval.data);
	break;
    default:
	break;
    }
}

EC_Errno EC_M_examine_msg(EC_M_Fieldtype *fieldtype, EC_M_Rectype *rectype,
    EC_M_Msg msg)
{
    EC_M_Fieldtype ftype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&ftype, &fieldval, msg, 0);
    if (!err && fieldtype)
	*fieldtype = ftype;
    if (!err && ftype == EC_M_FIELD_SOR && rectype)
	*rectype = fieldval.rectype;
    return err;
}

EC_Errno EC_M_decompile_int(UInt32 *val, EC_M_Msg msg)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
    if (err) return err;
    if (fieldtype == EC_M_FIELD_INT) {
	if (val) *val = fieldval.intval;
    } else {
	EC_M_free_fieldval(fieldtype, fieldval);
	err = EC_ERR_INTERNAL;
    }
    return err;
}

/* Sometimes, people send an int when they mean a time.  Handle that. */
EC_Errno EC_M_decompile_time(time_t *val, EC_M_Msg msg)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
    if (err) return err;
    if (fieldtype == EC_M_FIELD_TIME) {
	if (val) *val = fieldval.timeval;
    } else if (fieldtype == EC_M_FIELD_INT) {
	if (val) *val = fieldval.intval;
    } else {
	EC_M_free_fieldval(fieldtype, fieldval);
	err = EC_ERR_INTERNAL;
    }
    return err;
}

EC_Errno EC_M_decompile_string(char **val, EC_M_Msg msg)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
    if (err) return err;
    if (fieldtype == EC_M_FIELD_STRING) {
	if (val) *val = fieldval.stringval;
    } else {
	EC_M_free_fieldval(fieldtype, fieldval);
	err = EC_ERR_INTERNAL;
    }
    return err;
}

EC_Errno EC_M_decompile_MPI(BIGNUM **val, EC_M_Msg msg)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
    if (err) return err;
    if (fieldtype == EC_M_FIELD_MPI) {
	if (val) *val = fieldval.MPIval;
    } else {
	EC_M_free_fieldval(fieldtype, fieldval);
	err = EC_ERR_INTERNAL;
    }
    return err;
}

EC_Errno EC_M_decompile_data(Byte **val, UInt32 *len, EC_M_Msg msg)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
    if (err) return err;
    if (fieldtype == EC_M_FIELD_DATA) {
	if (val) *val = fieldval.dataval.data;
	if (len) *len = fieldval.dataval.len;
    } else {
	EC_M_free_fieldval(fieldtype, fieldval);
	err = EC_ERR_INTERNAL;
    }
    return err;
}

EC_Errno EC_M_decompile_sor(UInt32 type, EC_M_Msg msg)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
    if (err) return err;
    if (fieldtype == EC_M_FIELD_SOR && fieldval.rectype == type) {
	/* Nothing */
    } else {
	EC_M_free_fieldval(fieldtype, fieldval);
	err = EC_ERR_INTERNAL;
    }
    return err;
}

EC_Errno EC_M_decompile_eor(EC_M_Msg msg)
{
    /* This one is special; eat everything until we see an EOR at the
       right nesting level */
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;
    UInt nestlevel = 0;

    while(1) {
	err = EC_M_get_field_from_msg(&fieldtype, &fieldval, msg, 1);
	if (err) return err;
	if (fieldtype == EC_M_FIELD_NONE) return EC_ERR_INTERNAL;
	EC_M_free_fieldval(fieldtype, fieldval);
	if (fieldtype == EC_M_FIELD_SOR) ++nestlevel;
	if (fieldtype == EC_M_FIELD_EOR && nestlevel == 0) return err;
	if (fieldtype == EC_M_FIELD_EOR) --nestlevel;
    }
}

/* Transfer a field from one message to another (to may be NULL, in which
   case the field turns into heat) */
EC_Errno EC_M_transfer_field(EC_M_Msg from, EC_M_Msg to)
{
    EC_M_Fieldtype fieldtype;
    EC_M_Fieldval fieldval;
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos1 = EC_M_tell_msg(from);

    if (!from) return EC_ERR_INTERNAL;

    err = EC_M_get_field_from_msg(&fieldtype, &fieldval, from, 1);
    if (err) {
	EC_M_seek_msg(msgpos1, from);
	return err;
    }
    if (fieldtype == EC_M_FIELD_NONE) {
	EC_M_seek_msg(msgpos1, from);
	return EC_ERR_INTERNAL;
    }
    if (fieldtype == EC_M_FIELD_SOR) {
	/* Eat to the end of the record */
	err = EC_M_decompile_eor(from);
	if (err) {
	    EC_M_seek_msg(msgpos1, from);
	    return err;
	}
    }

    /* Copy the data we just skipped into the other msg */
    if (!to) return EC_ERR_NONE;

    err = EC_M_append_msg(from->data+msgpos1.begin, from->begin-msgpos1.begin,
			    to);
    if (err) {
	EC_M_seek_msg(msgpos1, from);
	return err;
    }

    return EC_ERR_NONE;
}
