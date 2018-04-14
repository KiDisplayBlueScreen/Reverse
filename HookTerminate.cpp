#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <SpecialAPI.h>
using namespace std;
PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPCWSTR lpModuleName);
WCHAR Path[] = L"C:\\Users\\hasee\\source\\repos\\GetLocalTime\\Release\\GetLocalTime.exe" ;
STARTUPINFO StartInfo = { sizeof(StartInfo) };
PROCESS_INFORMATION ProcessInfo;
int main()
{
	ElevateDebugPrivileges();
	HMODULE hMod = GetModuleHandle(L"kernel32.dll");
	BYTE* ProcAddr = (BYTE*)GetProcAddress(hMod, "TerminateProcess");
	BYTE OldCode[15] = { 0 };
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(hMod);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(L"kernel32.dll");
	DWORD BaseOfCode = pOptionalHeader->BaseOfCode;
	DWORD SizeOfCode = pOptionalHeader->SizeOfCode;
	MEMORY_BASIC_INFORMATION OldMem = { 0 };

	DWORD OldProtect;
	VirtualQuery(hMod + BaseOfCode/4, &OldMem, SizeOfCode);
	VirtualProtect(hMod + BaseOfCode/4, SizeOfCode, PAGE_EXECUTE_READWRITE, &OldProtect);

	BYTE NewCode[] = { 0xC3 };
	*ProcAddr = NewCode[0];
	for (int i = 0; i <= 14; i++)
	{
		OldCode[i] = *ProcAddr;
		ProcAddr++;
	}
	for (int i = 0; i <= 14; i++)
	{
		printf("%02X", OldCode[i]);
		cout << " ";
	}
	cout << endl;
	TerminateProcess((HANDLE)-1, 0);
	CreateProcess(0, Path, 0, 0, 1, 0, 0, 0, &StartInfo, &ProcessInfo);
	DWORD ThreadId=GetThreadId(ProcessInfo.hThread);
	cout << "GetThreadId Error Code:  " << GetLastError() << endl;
	printf("%08X \n", ThreadId);
	HMODULE hDll = LoadLibrary(L"C:\\Users\\hasee\\source\\repos\\Dll\\Release\\Dll.dll");
	cout << "LoadLibrary Error Code:  " << GetLastError() << endl;
	printf("%08X \n", hDll);
	DWORD FunProc = (DWORD)GetProcAddress(hDll, "HookProc1");
	cout << "GetProcAddress Error Code:   " << GetLastError() << endl;
	printf("%08X \n ", FunProc);
	HHOOK HOOK=SetWindowsHookEx(WH_CALLWNDPROC,(HOOKPROC)FunProc,hDll,0);
	cout <<"SetWindowsHookEx Error Code:   "<< GetLastError() << endl;
	cout << HOOK << endl;
	cout << endl;
	system("pause");
	UnhookWindowsHookEx(HOOK);
    return 0;
}

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPCWSTR lpModuleName)
{
	HMODULE hFile = GetModuleHandle(lpModuleName);
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(hFile);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((BYTE*)hFile + pDOSHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE*)hFile + pDOSHeader->e_lfanew + 24);
	return pOptionalHeader;
}

