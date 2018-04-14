#pragma once
#ifndef _XANTIDEBUG_H
#define _XANTIDEBUG_H

#include <Windows.h>
#include "ldasm.h"
#include "crc32.h"

#ifndef _WIN64
#include "wow64ext.h"
#endif // !_WIN64



#define XAD_NTDLL	L"ntdll.dll"
#define	XAD_PEHAD	0x1000

typedef enum
{
	XAD_OK = 0,
	XAD_ERROR_NTAPI = 1,
	XAD_ERROR_FILEOFFSET = 2,
	XAD_ERROR_OPENNTDLL = 3,
	XAD_ERROR_ALLOCMEM = 4
}XAD_STATUS;


typedef DWORD64(WINAPI* fn_SysCall64)(HANDLE hProcess, DWORD64 processclass, PVOID processInfo, DWORD length, PDWORD64 returnlengt);

typedef DWORD(WINAPI* fn_SysCall32)(HANDLE hProcess, DWORD processclass, PDWORD processInfo, DWORD length, PDWORD returnlength);

class XAntiDebug
{

public:
	XAntiDebug();
	~XAntiDebug();

	XAD_STATUS		initialize(); //初始化
	BOOL			IsDebuging(); //检测是否被调试？

private:
	DWORD			_crc32 = 0;
	DWORD			_eax = 0;
	DWORD64			_MyQueryInfomationProcess = 0;
	BOOL			_isX64 = FALSE;
	PVOID			_wow64FsReDirectory = NULL;
	PVOID			_executePage = NULL;

	fn_SysCall32	 pfnSyscall32 = NULL;
	fn_SysCall64	 pfnSyscall64 = NULL;
};

#endif
