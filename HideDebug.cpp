#include "stdafx.h"
#include <Windows.h>
#include <Winternl.h>
#include <iostream>
using namespace std;
LPVOID GetHeap(void);
BYTE ISDEBUGPRESENT[11] = { 0x64,0xA1,0x30,0,0,0,0xF,0xB6,0x40,2,0xC3 };
int DetectDebuggerByWindow();
DWORD DetectDebuggerByNtGlobalFlag();
int IsBreakPointPrensent(LPCWSTR lpModuleName, LPCSTR APIName);

typedef PVOID(WINAPI *RTLCREATEHEAP)
(
	ULONG Flags,
	PVOID HeapBase,
	SIZE_T ReverseSize,
	SIZE_T CommitSize,
	PVOID Lock,
	PVOID HeapParameters
);
typedef PVOID(WINAPI *RTLALLOCATEHEAP)
(
	PVOID  HeapHandle,
	 ULONG  Flags,
	 SIZE_T Size
);
int main()
{

	if (DetectDebuggerByWindow() == 1) cout << "Debugger Found" << endl;

	if (DetectDebuggerByNtGlobalFlag()==0x70) cout << "Debugger Found" << endl;


	if (IsBreakPointPrensent(L"user32.dll","MessageBoxW")==1) cout << "Debugger Found" << endl;

	CHAR Buff[50] = { 1 };











	//EnableWindow(GetForegroundWindow(), FALSE);
	BlockInput(0);
    
	DWORD Heap[0x100] = { 0 };
	PDWORD pHeapData = (PDWORD)GetHeap();
	DWORD EAX1;
	DWORD EDX1;
	__asm
	{
		rdtsc
		mov EAX1, eax
		mov EDX1, edx
	}
	__asm
	{
		rdtsc
        sub eax,EAX1
		MOV EAX1,EAX
		sub EDX1,edx
	}
	BlockInput(1);
	//EnableWindow(GetForegroundWindow(), TRUE);
	PBYTE Code=(PBYTE)VirtualAlloc(0, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PBYTE Code1 = Code;
	for (int i = 0; i <= 10; i++)
	{
		*Code = ISDEBUGPRESENT[i];
		 Code++;
	}
	__asm
	{
		mov eax,Code1
		call eax
	}
	RTLCREATEHEAP RtlCreateHeap = (RTLCREATEHEAP)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateHeap");
	RTLALLOCATEHEAP RtlAllocateHeap = (RTLALLOCATEHEAP)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlAllocateHeap");
	PVOID pHeap=RtlCreateHeap(HEAP_GROWABLE, 0, 0x100, 0x100, 0, 0);
	RtlAllocateHeap(pHeap, HEAP_ZERO_MEMORY, 0x100);
	printf("EAX=%08X \n", EAX1);
	printf("EDX=%08X \n", EDX1);
	system("pause");
    return 0;
}
LPVOID GetHeap()
{
	return HeapAlloc(GetProcessHeap(), 0, 0x100);
}
int DetectDebuggerByWindow()
{

	WCHAR Buffer[150] = { 0 };
	HWND hWindows = GetForegroundWindow();
	GetWindowText(hWindows, Buffer, 150);
	if (Buffer[0] == 0x543E && Buffer[1] == 0x611B && Buffer[2] == 0x7834)
	{ 
		return 1; 
	}

	if (Buffer[0] == 0x4F && Buffer[1] == 0x6C && Buffer[2] == 0x6C&&Buffer[3]==0x79)
	{
		return 1;
	}

	if (Buffer[0] == 0x78 && Buffer[1] == 0x33 && Buffer[2] == 0x32 && Buffer[3] == 0x64&& Buffer[4]==0x62)
	{
		return 1;
	}
	return 0;

}
DWORD DetectDebuggerByNtGlobalFlag()
{
	DWORD NtGlobalFlags;
	__asm
	{
		mov eax, FS:[0X30];
		mov eax, [eax + 0x68];
		mov NtGlobalFlags, eax
	}
	return NtGlobalFlags;
}
int IsBreakPointPrensent(LPCWSTR lpModuleName,LPCSTR APIName)
{
	if (lpModuleName == NULL || APIName == NULL)
	{
		return -1;
	}
	PBYTE APIAddress=(PBYTE)GetProcAddress(GetModuleHandle(lpModuleName), APIName);
	if (*APIAddress == 0xCC)
	{
		return 1;
	}
	return 0;
}