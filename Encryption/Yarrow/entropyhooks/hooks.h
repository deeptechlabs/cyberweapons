/*
	hooks.h

	Header file for the Counterpane PRNG entropy collection rountines DLL.
*/

#ifndef YARROW_HOOKS_H
#define YARROW_HOOKS_H

/* Declare HOOKSAPI as __declspec(dllexport) before
   including this file in the actual DLL */
#ifndef HOOKSAPI 
#define HOOKSAPI __declspec(dllimport)
#endif

/* Error numbers */
typedef enum hooks_error_status {
	HOOKS_SUCCESS = 0,
	HOOKS_ERR_NULL_POINTER,
	HOOKS_ERR_LOW_MEMORY,
	HOOKS_ERR_WRONG_CALLER,
	HOOKS_ERR_REINIT,
	HOOKS_ERR_SETUP,
	HOOKS_ERR_HANDLE
} hooks_error_status;

/* Exports */
HOOKSAPI hooks_error_status	WINAPI SetHooks(void);
HOOKSAPI hooks_error_status	WINAPI SetupMMComm(LPVOID*, HANDLE*, HANDLE*);
HOOKSAPI hooks_error_status	WINAPI CloseMMComm(void);
HOOKSAPI hooks_error_status	WINAPI RemoveHooks(void);
HOOKSAPI LRESULT CALLBACK KeyboardHook(int, WORD, LONG);
HOOKSAPI LRESULT CALLBACK MouseHook(int, WORD, LONG);

#endif