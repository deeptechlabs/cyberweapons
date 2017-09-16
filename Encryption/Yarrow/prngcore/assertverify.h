#ifndef ASSERT_VERIFY_H
#define ASSERT_VERIFY_H

/******************************************************************************
Written by: Jeffrey Richter
Notices: Copyright (c) 1995-1997 Jeffrey Richter
Purpose: Common header file containing handy macros and definitions used
         throughout all the applications in the book.
******************************************************************************/

/* These header functions were copied from the cmnhdr.h file that accompanies 
   Advanced Windows 3rd Edition by Jeffrey Richter */

//////////////////////////// Assert/Verify Macros /////////////////////////////


#define chFAIL(szMSG) {                                                   \
      MessageBox(GetActiveWindow(), szMSG,                                \
         __TEXT("Assertion Failed"), MB_OK | MB_ICONERROR);               \
      DebugBreak();                                                       \
   }

/* Put up an assertion failure message box. */
#define chASSERTFAIL(file,line,expr) {                                    \
      TCHAR sz[128];                                                      \
      wsprintf(sz, __TEXT("File %hs, line %d : %hs"), file, line, expr);  \
      chFAIL(sz);                                                         \
   }

/* Put up a message box if an assertion fails in a debug build. */
#ifdef _DEBUG
#define chASSERT(x) if (!(x)) chASSERTFAIL(__FILE__, __LINE__, #x)
#else
#define chASSERT(x)
#endif

/* Assert in debug builds, but don't remove the code in retail builds. */
#ifdef _DEBUG
#define chVERIFY(x) chASSERT(x)
#else
#define chVERIFY(x) (x)
#endif

#endif
