/* 
	ntonly.c

	Source code for NT specific routines.
*/

#include "userdefines.h"

#ifdef WIN_NT

#include <windows.h>
#include <stdio.h>
#include "ntonly.h"

#define _MIN(a,b) (((a)<(b))?(a):(b))


DWORD prng_slow_poll(BYTE *buf,UINT bufsize)
/* Slow pool returns a ton of data from the performance data regsitry key */
{
	DWORD len = bufsize;

	RegQueryValueEx(HKEY_PERFORMANCE_DATA,"Global",NULL,NULL,buf,&len);
	RegCloseKey(HKEY_PERFORMANCE_DATA);
	
	return _MIN(bufsize,len);
}

/*
Abstract:

	This code was taken from one of the samples included with VC++ 5.0. It was
	originally written by Scott Field. Minor changes for compatibility with the
	Counterpane PRNG code were made by Ari Benbasat. Original abstract follows.



    This sample illustrates how to regulate access to the performance data
    provided by the registry key HKEY_PERFORMANCE_DATA.

    The security on the following registry key dictates which users or groups
    can gain access to the performance data:

    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib

    This sample opens the registry key for WRITE_DAC access, which allows
    for a new Dacl to be applied to the registry key.

    A Dacl is then built, which grants the following users access:

    Administrators are granted full control to allow for future updates to the
    security on the key and to allow for querying performance data.

    Interactively logged on users, through the well-known Interactive Sid,
    are granted KEY_READ access, which allows for querying performance
    data.

    The new Dacl is then applied to the registry key using the
    RegSetKeySecurity() Win32 API.

    This sample relies on the import library advapi32.lib.
*/

BOOL prng_set_NT_security(void)
{
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    PSID pNonInteractiveSid = NULL;
    PSID pAdministratorsSid = NULL;
    SECURITY_DESCRIPTOR sd;
    PACL pDacl = NULL;
    DWORD dwAclSize;
    HKEY hKey;
    LONG lRetCode;
    BOOL bSuccess = FALSE; /* assume this function fails */

    /* open the performance key for WRITE_DAC access */
    lRetCode = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
       TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib"),
        0,
        WRITE_DAC,
        &hKey
        );

    if(lRetCode != ERROR_SUCCESS) {
        return FALSE;
    }

    /* prepare a Sid representing any non-Interactively logged-on user */
    if(!AllocateAndInitializeSid(
        &sia,
        3,
        SECURITY_DIALUP_RID,
        SECURITY_NETWORK_RID,
		SECURITY_BATCH_RID, 
		0, 0, 0, 0, 0,
        &pNonInteractiveSid
        )) {
        goto cleanup;
    }

    /* preprate a Sid representing the well-known admin group */
    if(!AllocateAndInitializeSid(
        &sia,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsSid
        )) {
        goto cleanup;
    }

    /* compute size of new acl */
    dwAclSize = sizeof(ACL) +
        2 * ( sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) ) +
        GetLengthSid(pNonInteractiveSid) +
        GetLengthSid(pAdministratorsSid) ;

    /* allocate storage for Acl */
    pDacl = (PACL)HeapAlloc(GetProcessHeap(), 0, dwAclSize);
    if(pDacl == NULL) goto cleanup;

    if(!InitializeAcl(pDacl, dwAclSize, ACL_REVISION)) {
        goto cleanup;
    }

    /* grant the non-Interactive Sid no access to the perf key */
    if(!AddAccessAllowedAce(
        pDacl,
        ACL_REVISION,
        0,
        pNonInteractiveSid
        )) {
        goto cleanup;
    }

    /* grant the Administrators Sid KEY_ALL_ACCESS access to the perf key */
    if(!AddAccessAllowedAce(
        pDacl,
        ACL_REVISION,
        KEY_ALL_ACCESS,
        pAdministratorsSid
        )) {
        goto cleanup;
    }

    if(!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        goto cleanup;
    }

    if(!SetSecurityDescriptorDacl(&sd, TRUE, pDacl, FALSE)) {
        goto cleanup;
    }

    /* apply the security descriptor to the registry key */
    lRetCode = RegSetKeySecurity(
        hKey,
        (SECURITY_INFORMATION)DACL_SECURITY_INFORMATION,
        &sd
        );

    if(lRetCode != ERROR_SUCCESS) {
        goto cleanup;
    }

    bSuccess = TRUE; /* indicate success */

cleanup:
    RegCloseKey(hKey);
    RegCloseKey(HKEY_LOCAL_MACHINE);

	/* Free allocated resources */
    if(pDacl != NULL)
        HeapFree(GetProcessHeap(), 0, pDacl);

    if(pNonInteractiveSid != NULL)
        FreeSid(pNonInteractiveSid);

    if(pAdministratorsSid != NULL)
        FreeSid(pAdministratorsSid);

	return bSuccess;
}

#endif