// Project1.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Project1.h"


// This is an example of an exported variable


// This is an example of an exported function.
BOOL  WINAPI SetKeyHook(BOOL bInstall, DWORD dwThreadId, HWND hWndCaller);

// This is the constructor of a class that has been exported.
// see Project1.h for the class definition
CProject1::CProject1()
{
    return;
}
