/*
	testapp.c

	Test routines for the Counterpane PRNG (Yarrow) user commands
*/

#include <windows.h>
#include "yarrow.h"
#include "usersources.h"

HANDLE ghInst;
HWND ghWndMain;

int PASCAL WinMain (HANDLE hInstance, HANDLE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
/* Needs much better error  checking */
{
	BYTE* buf;
	BYTE str[30];

	buf = (BYTE*)malloc(4096);
	memset(buf,0x11,4096);
	prngInput(buf,4096,USERSOURCE1,1);
	memset(buf,0x22,4096);
	prngInput(buf,4096,USERSOURCE1,1);
	memset(buf,0x33,4096);
	prngInput(buf,4096,USERSOURCE1,1);
	free(buf);
	buf = (BYTE*)malloc(8192);
	memset(buf,0x44,8192);
	prngInput(buf,8192,USERSOURCE1,1);
	free(buf);
	buf = (BYTE*)malloc(20000);
	memset(buf,0x55,20000);
	prngInput(buf,20000,USERSOURCE1,1);

	prngAllowReseed(100);
	prngOutput(buf,13);
	prngOutput(buf,13);
	prngOutput(buf,13);
	prngOutput(buf,13);
	prngStretch(buf,13,str,30);
	prngInput(buf,13,USERSOURCE1,5);
	prngAllowReseed(100);
	prngOutput(buf,13);
	free(buf);
	return prngOutput(str,30);
}   
