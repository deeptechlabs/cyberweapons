/*
	FrontEnd.h

	Header file for the front end of the Counterpane PRNG entropy collection rountines.
*/

#ifndef YARROW_FRONT_END_H
#define YARROW_FRONT_END_H

/* menu defines */
#define IDM_ABOUT 100
#define IDM_RESEED 101
#define IDM_CLOSE 102
#define TRAY_CALLBACK WM_USER

/* Forward declerations for frontend.c */
int PASCAL WinMain(HANDLE, HANDLE, LPSTR, int);
LRESULT CALLBACK MainWndProc(HWND, unsigned, WORD, LONG);
BOOL WINAPI About(HWND, unsigned, WORD, LONG);
BOOL WINAPI ReseedDlg(HWND, unsigned, WORD, LONG);
HANDLE SetupLocalMMFile(LPVOID comm);
DWORD WINAPI ListenToMMFile(LPVOID param);
DWORD WINAPI PassData(LPVOID param);
DWORD WINAPI ReseedThread(LPVOID param);

#endif
