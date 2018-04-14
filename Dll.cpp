// Dll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "Dll.h"


// This is an example of an exported variable
//DLL_API int nDll=0;

// This is an example of an exported function.
//DLL_API int fnDll(void)
//{
    //return 42;
//}

// This is the constructor of a class that has been exported.
// see Dll.h for the class definition
CDll::CDll()
{
    return;
}
DLL_API VOID Fun(void);