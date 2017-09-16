/*
	FrontEnd.c

	Front end routines for the Counterpane PRNG (Yarrow)
*/

#include <windows.h>
#include <stdio.h>
#include "resource.h"
#include "frontend.h"
#include "hooks.h"
#include "yarrow.h"
#include "prng.h"
#include "entropysources.h"

static HANDLE ghInst;
static HWND ghWndMain;

/* Write-out thread control events */
static HANDLE dataReady;
static HANDLE writeAllowed;

/* Context menu for notification area icon */
static HMENU hPop;

/* Reseed thread controls */
static HANDLE reseed;
static DWORD interval = -1;
static DWORD length = 100;
static BOOL threadActive = FALSE;
static CRITICAL_SECTION suspendable;


int PASCAL WinMain (HANDLE hInstance, HANDLE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	WNDCLASS wc;   
	LPVOID commloc;
	MSG msg;
	HANDLE endNow;
	DWORD threadId;
	NOTIFYICONDATA nid;

	/* Initialize this app */
	wc.style = 0;
	wc.lpfnWndProc = MainWndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(hInstance,MAKEINTRESOURCE(IDI_WASTE));
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = GetStockObject(WHITE_BRUSH);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = "frontendWClass";
	if(RegisterClass(&wc)==FALSE) {return FALSE;}

	/* Setup the window for this app but do not display it */
	ghWndMain = CreateWindow("frontendWClass", "Entropy Collection",
                            WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT,
                            CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance,
                            NULL);
	if(ghWndMain==NULL) {return FALSE;}
	ghInst = hInstance;

	/* Setup Core */
	if(prngInitialize()!=PRNG_SUCCESS) {return FALSE;}
	if(SetHooks()!=HOOKS_SUCCESS) {return FALSE;}
	if(SetupMMComm(&commloc,&dataReady,&writeAllowed)!=HOOKS_SUCCESS) {return FALSE;}
	if(SetupLocalMMFile(commloc)==NULL) {return FALSE;}

	/* Create Reseed thread */
	InitializeCriticalSection(&suspendable);
	endNow = CreateEvent(NULL,TRUE,FALSE,NULL);
	reseed = CreateThread(NULL,0,ReseedThread,endNow,CREATE_SUSPENDED,&threadId);
	
	/* Setup notification area icon */
	hPop = CreatePopupMenu();
	AppendMenu(hPop, MF_STRING, IDM_RESEED, "&Reseed Period...");
	AppendMenu(hPop, MF_STRING, IDM_CLOSE, "&Close");
	AppendMenu(hPop, MF_SEPARATOR, 0, NULL);
	AppendMenu(hPop, MF_STRING, IDM_ABOUT, "&About Entropy Collection...");
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.hWnd = ghWndMain;
	nid.uID = (UINT)IDI_WASTE;
	nid.uFlags = NIF_TIP|NIF_ICON|NIF_MESSAGE;
	nid.hIcon = (HICON)LoadImage(hInstance,MAKEINTRESOURCE(IDI_WASTE),IMAGE_ICON,16,16,0);
	nid.uCallbackMessage = TRAY_CALLBACK;
	strcpy(nid.szTip,"Counterpane's Yarrow");
	Shell_NotifyIcon(NIM_ADD,&nid);

	/* Message pump */
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	
	/* Remove notification area icon */
	Shell_NotifyIcon(NIM_DELETE,&nid);

	/* Destroy reseed thread */
	SetEvent(endNow);
	if(threadActive==FALSE) {ResumeThread(reseed);}
	WaitForSingleObject(reseed,INFINITE);
	DeleteCriticalSection(&suspendable);

	/* Dismantle Core */
	CloseMMComm();
	RemoveHooks();
	prngDestroy();

	return msg.wParam;
}                  


/* Window callback functions */
LRESULT CALLBACK MainWndProc(HWND hWnd, unsigned message, WORD wParam, LONG lParam)
{
	POINT pnt;

	switch (message)
	{
	case TRAY_CALLBACK:
		switch(lParam)
		{
		case WM_RBUTTONDOWN:
			SetForegroundWindow(hWnd);
			GetCursorPos(&pnt);
			TrackPopupMenu(hPop,TPM_RIGHTBUTTON,pnt.x,pnt.y,0,hWnd,NULL);
			PostMessage(hWnd, WM_NULL, 0, 0); /* See Knowledge base Q135788 */
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
	case WM_COMMAND: 
		switch (wParam)
		{
		case IDM_ABOUT:
			DialogBox(ghInst, "AboutBox", hWnd, About);
			break;
		case IDM_RESEED:
			DialogBox(ghInst, "ReseedBox", hWnd, ReseedDlg);
			break;
		case IDM_CLOSE:
			PostMessage(hWnd, WM_CLOSE, 0, 0);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;

      case WM_QUERYOPEN:
         break;    /* Keep the window iconic. */

      case WM_SIZE:/* don't allow window to be resized */
         break;

      case WM_DESTROY:               
         PostQuitMessage(0);
         break;

      default:
         return DefWindowProc(hWnd, message, wParam, lParam);
   }              

   return 0;
}            


BOOL CALLBACK ReseedDlg(HWND hDlg, unsigned msg, WORD wParam, LONG lParam)
{
	char out[50];
	int temp;

   switch (msg)
   {
	  case WM_INITDIALOG:
		if(interval==-1)
		{
			SetDlgItemText(hDlg,IDC_INTERVAL,"off");
		}
		else
		{
			SetDlgItemText(hDlg,IDC_INTERVAL,itoa(interval,out,10));
		}
		SetDlgItemText(hDlg,IDC_LENGTH,itoa(length,out,10));
		return (TRUE);

      case WM_COMMAND:
         if (wParam == IDCANCEL)
         {
            EndDialog(hDlg, TRUE);
            return (TRUE);
         }
		 if (wParam == IDOK)
		 {
			GetDlgItemText(hDlg,IDC_INTERVAL,out,49);
			if(strncmp(out,"off",3)==0)
			{
				temp = -1;
			}
			else
			{
				temp = atoi(out);	/* If this fails, the return value is 0 */
				if(temp<=0)
				{
					MessageBox(NULL,"Invalid reseed interval.","Error",MB_OK);
					if(interval==-1)
					{
						SetDlgItemText(hDlg,IDC_INTERVAL,"off");
					}
					else
					{
						SetDlgItemText(hDlg,IDC_INTERVAL,itoa(interval,out,10));
					}
					return TRUE;
				}
			}
			interval = temp;

			GetDlgItemText(hDlg,IDC_LENGTH,out,49);
			temp = atoi(out);	/* If this fails, the return value is 0 */
			if(temp<=0)
			{
				MessageBox(NULL,"Invalid reseed length.","Error",MB_OK);
				SetDlgItemText(hDlg,IDC_LENGTH,itoa(length,out,10));
				return TRUE;
			}
			length = temp;

			if((interval == -1) && (threadActive==TRUE)) /* Deactivate thread */
			{
				EnterCriticalSection(&suspendable);
				SuspendThread(reseed);
				threadActive=FALSE;
				LeaveCriticalSection(&suspendable);
			}
			if((interval != -1) && (threadActive==FALSE)) /* Resume thread */
			{
				ResumeThread(reseed);
				threadActive=TRUE;
			}

            EndDialog(hDlg, TRUE);
            return (TRUE);
		 }
		 break;
   }
   return (FALSE); /* Didn't process the message    */
}            

BOOL CALLBACK About(HWND hDlg, unsigned msg, WORD wParam, LONG lParam)
{
   switch (msg)
   {
      case WM_INITDIALOG:
         return (TRUE);

      case WM_COMMAND:
         if (wParam == IDOK || wParam == IDCANCEL)
         {
            EndDialog(hDlg, TRUE);
            return (TRUE);
         }
         break;
   }
   return (FALSE); /* Didn't process the message    */
}  


/* Misc Functions */
HANDLE SetupLocalMMFile(LPVOID commloc)
{
	int threadId;

	return CreateThread(NULL,0,ListenToMMFile,commloc,0,&threadId);
}


/* Thread functions */
DWORD WINAPI ListenToMMFile(LPVOID param)
{
	int poolnum;
	int size;
	BYTE* buf;
	int threadId;
	BYTE* tempbuf = NULL;
	HANDLE worker = NULL;

	buf = (BYTE*)param;

	while(1)
	{
		WaitForSingleObject(dataReady,INFINITE);

		poolnum = *((int*)buf);
		if(poolnum == MSG_CLOSE_PIPE) {break;}
		if((poolnum<0)||(poolnum>=ENTROPY_SOURCES)) {continue;}
		size = *( ((int*)buf) + 1 );

		if( (worker == NULL) || (WaitForSingleObject(worker,0)==WAIT_OBJECT_0) )
		{
			if(tempbuf != NULL) {free(tempbuf);}
			if(worker != NULL) {CloseHandle(worker);}
			tempbuf = (BYTE*)malloc(size+2*sizeof(int));
			memcpy(tempbuf,buf,size+2*sizeof(int));
			worker = CreateThread(NULL,0,PassData,tempbuf,0,&threadId);
		}

		SetEvent(writeAllowed);
	}

	SetEvent(writeAllowed); /* Unblock any other processes */

	return 0;
}

DWORD WINAPI PassData(LPVOID param)
{
	int poolnum,size;
	BYTE* buf;

	buf = (BYTE*)param;
	
	poolnum = *((int*)buf);
	size = *( ((int*)buf) + 1 );
	prngInputEntropy(buf+2*sizeof(int),size,poolnum);

	return 0;
}



DWORD WINAPI ReseedThread(LPVOID param)
{
	DWORD waitval;
	HANDLE endNow;

	endNow = (HANDLE)param;

	while(1)
	{
		waitval = WaitForSingleObject(endNow,interval*1000*60); /* Wait interval minutes */
		if(waitval == WAIT_OBJECT_0) {return 0;}
		EnterCriticalSection(&suspendable);
		prngAllowReseed(length);
		LeaveCriticalSection(&suspendable);
	}
}