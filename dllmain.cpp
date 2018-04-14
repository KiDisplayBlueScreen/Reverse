// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <iostream>
VOID Fun();
VOID Fun1();
int Flags;
BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Flags = 0;
		Fun1();
	case DLL_THREAD_ATTACH:


	case DLL_THREAD_DETACH:
		

	case DLL_PROCESS_DETACH:
	

		break;
	}
	return TRUE;
}

VOID Fun()
{
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	DWORD ProcAddr = (DWORD)GetProcAddress(hKernel32, "GetLocalTime");
	DWORD IsDebug = (DWORD)GetProcAddress(hKernel32, "IsDebuggerPresent");

	MessageBox(0, L"I am Dll Proc", L"", MB_OK);
	HMODULE hFile = GetModuleHandle(0);
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(hFile);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((BYTE*)hFile + pDOSHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE*)hFile + pDOSHeader->e_lfanew + 24);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)hFile + pDOSHeader->e_lfanew + 24 + pFileHeader->SizeOfOptionalHeader);
	PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionalHeader->DataDirectory);
	PDWORD VirtualAddress = &(pDataDirectory->VirtualAddress);
	PDWORD Size = &(pDataDirectory->Size);
	IMAGE_DATA_DIRECTORY DataDirectory[16] = { 0 };
	for (int i = 0; i <= 15; i++)
	{
		DataDirectory[i].Size = *Size;
		DataDirectory[i].VirtualAddress = *VirtualAddress;
		printf("My Number %d DataDirectory's VirtualAddress :%08X \n", i + 1, *VirtualAddress);
		printf("My Number %d DataDirectory's Size :%08X \n \n", i + 1, *Size);
		VirtualAddress = VirtualAddress + 0x2;
		Size = Size + 0x2;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hFile + DataDirectory[1].VirtualAddress);
	int j = 0;
	DWORD OldProtect;
	VirtualProtect((hFile + DataDirectory[12].VirtualAddress / 4), 0x1000, PAGE_READWRITE, &OldProtect);
	PDWORD PAddr = (PDWORD)((BYTE*)hFile + DataDirectory[12].VirtualAddress);
	DWORD x = (DataDirectory[12].Size) / 4;
	for (int i = 0; *PAddr != 0 && i <= x; i++)
	{
		if (*PAddr == IsDebug) *PAddr = ProcAddr;

		PAddr = PAddr + 1;

		if (*PAddr == 0 || ((*PAddr) - (DWORD)(hFile))<0x2000)
		{
			PAddr = PAddr + 1;
		}
	}

	printf("\n I am here");
	
}
VOID  Fun1()
{
	 HMODULE hMod = GetModuleHandle(L"kernel32.dll");
	 BYTE* ProcAddr = (BYTE*)GetProcAddress(hMod, "TerminateProcess");
	 BYTE OldCode[15] = { 0 };
	 PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(hMod);
	 PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE*)hMod + pDOSHeader->e_lfanew + 24);
	 DWORD BaseOfCode = pOptionalHeader->BaseOfCode;
	 DWORD SizeOfCode = pOptionalHeader->SizeOfCode;
	 MEMORY_BASIC_INFORMATION OldMem = { 0 };

	 DWORD OldProtect;
	 VirtualQuery(hMod + BaseOfCode / 4, &OldMem, SizeOfCode);
	 VirtualProtect(hMod + BaseOfCode / 4, SizeOfCode, PAGE_EXECUTE_READWRITE, &OldProtect);

	 BYTE NewCode[] = { 0xC3 };
	 *ProcAddr = NewCode[0];
}
 LRESULT CALLBACK HookProc(int Code, WPARAM wParam, LPARAM lParam)
 {
	 HMODULE hMod = GetModuleHandle(L"kernel32.dll");
	 BYTE* ProcAddr = (BYTE*)GetProcAddress(hMod, "TerminateProcess");
	 BYTE OldCode[15] = { 0 };
	 PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(hMod);
	 PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE*)hMod + pDOSHeader->e_lfanew + 24);
	 DWORD BaseOfCode = pOptionalHeader->BaseOfCode;
	 DWORD SizeOfCode = pOptionalHeader->SizeOfCode;
	 MEMORY_BASIC_INFORMATION OldMem = { 0 };

	 DWORD OldProtect;
	 VirtualQuery(hMod + BaseOfCode / 4, &OldMem, SizeOfCode);
	 VirtualProtect(hMod + BaseOfCode / 4, SizeOfCode, PAGE_EXECUTE_READWRITE, &OldProtect);

	 BYTE NewCode[] = { 0xC3 };
	 *ProcAddr = NewCode[0];
	 return CallNextHookEx(0,Code, wParam, lParam);
 }
 VOID MyGetLocalTime(LPSYSTEMTIME lpSystemTime)
 {

	 lpSystemTime->wYear = 2016;
	 lpSystemTime->wHour = 12;
	 lpSystemTime->wMonth = 11;
	 lpSystemTime->wDay = 5;
	 lpSystemTime->wMinute = 50;

 }

LRESULT CALLBACK HookProc1(int Code, WPARAM wParam, LPARAM lParam)
 {
	
	if (Flags == 0)
	{
		HMODULE hItself=LoadLibrary(L"C:\\Users\\hasee\\source\\repos\\Dll\\Release\\Dll.dll");
		DWORD GetLocalTimeMe = (DWORD)GetProcAddress(hItself, "MyGetLocalTime");
		HMODULE hFile = GetModuleHandle(0);
		HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
		DWORD ProcAddr = (DWORD)GetProcAddress(hKernel32, "GetLocalTime");
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)(hFile);
		PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE*)hFile + pDOSHeader->e_lfanew + 24);
		MEMORY_BASIC_INFORMATION OldMem = { 0 };
		DWORD OldProtect;
		DWORD BaseOfCode = pOptionalHeader->BaseOfCode;
		DWORD SizeOfCode = pOptionalHeader->SizeOfCode;
		VirtualQuery(hFile + BaseOfCode / 4, &OldMem, SizeOfCode);
		//VirtualProtect(hFile + BaseOfCode / 4, SizeOfCode, PAGE_EXECUTE_READWRITE, &OldProtect);
		PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pOptionalHeader->DataDirectory);
		PDWORD VirtualAddress = &(pDataDirectory->VirtualAddress);
		PDWORD Size = &(pDataDirectory->Size);
		IMAGE_DATA_DIRECTORY DataDirectory[16] = { 0 };
		for (int i = 0; i <= 15; i++)
		{
			DataDirectory[i].Size = *Size;
			DataDirectory[i].VirtualAddress = *VirtualAddress;
			VirtualAddress = VirtualAddress + 0x2;
			Size = Size + 0x2;
		}
		PDWORD PAddr = (PDWORD)((BYTE*)hFile + DataDirectory[12].VirtualAddress);
		DWORD x = (DataDirectory[12].Size) / 4;
		VirtualProtect(PAddr, SizeOfCode, PAGE_EXECUTE_READWRITE, &OldProtect);
		for (int i = 0; *PAddr != 0 && i <= x; i++)
		{
			if (*PAddr == ProcAddr) *PAddr = GetLocalTimeMe;
			//printf("My No.%d Import Function's RVA is  : %08X \n \n", i + 1, *PAddr);
			PAddr = PAddr + 1;
			if (*PAddr == 0)
			{
				PAddr = PAddr + 1;
			}
		}
		Flags = 1;
		return CallNextHookEx(0, Code, wParam, lParam);
	}
	else
	{
		return CallNextHookEx(0, Code, wParam, lParam);
	}
 }