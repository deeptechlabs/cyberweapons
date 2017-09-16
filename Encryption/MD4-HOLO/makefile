#
# Makefile for md4, for Microsoft C (4.0)
#
CC = msc
CFLAGS = /AS /Ox /DLINT_ARGS

md4.exe: md4.obj md4drive.obj md4block.obj
	link md4+md4drive+md4block;

md4.obj:	md4.c md4.h
	$(CC) $(CFLAGS) md4;

md4drive.obj:	md4.h md4drive.c
	$(CC) $(CFLAGS) md4drive;

md4block.obj:	md4block.asm
	masm md4block;
