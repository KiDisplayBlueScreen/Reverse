#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <SpecialAPI.h>
#define FileName L"CheckSum.txt"
using namespace std;
BOOL CheckSum();
BOOL PatchCheck();
int main()
{
	cout << "Testing Whether This Program Has Been Patch Or Not....." << endl;
	CheckSum();
	getchar();
    return 0;
}
BOOL CheckSum()
{    
	WIN32_FIND_DATA FileDate;
	HANDLE hFile = FindFirstFile(FileName, &FileDate);//查找当前目录下是否存在CheckSum.txt
	if (GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		hFile = CreateFile(FileName, GENERIC_ALL, FILE_SHARE_READ, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);//不存在就创建一个
		CloseHandle(hFile);
		//CloseHandle(hFile);
		TCHAR FileName1[100] = { 0 };
		GetModuleFileName(0, FileName1, 100 * sizeof(TCHAR));
		CopyFile(FileName1, L"C:\\360安全浏览器下载\\PatchCheck.exe", 0);
		hFile = CreateFile(L"C:\\360安全浏览器下载\\PatchCheck.exe", GENERIC_ALL, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			cout << "Open File Fail !" << endl;
			getchar();
			return 0;
		}
		DWORD dwSize = GetFileSize(hFile, &dwSize);
		BYTE *pBuffer = new BYTE[dwSize];
		ReadFile(hFile, pBuffer, dwSize, NULL, 0);
		DWORD i = 0;
		ULONG S = 0;
		for (i = 1; i <= dwSize; i++)
		{
			S = S + pBuffer[i - 1];
		}
		CloseHandle(hFile);
		hFile = CreateFile(FileName, GENERIC_ALL, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			cout << "Invalid Handle!" << endl;
			return 0;
		}
		LONG Buffer[1] = { 0 };
		Buffer[0] = S;
		WriteFile(hFile, Buffer, 4, 0, 0);
		CloseHandle(hFile);
		return S;
	}
	else
	{   
		ZeroMemory(&FileDate, sizeof(FileDate));
		TCHAR FileName1[100] = { 0 };
		GetModuleFileName(0, FileName1, 100 * sizeof(TCHAR));
		CopyFile(FileName1, L"C:\\360安全浏览器下载\\PatchCheck.exe", 0);
		PatchCheck();//存在就调用PatchCheck();
		return 0;
	}
}
BOOL PatchCheck()
{
	HANDLE hFile = CreateFile(L"C:\\360安全浏览器下载\\PatchCheck.exe", GENERIC_ALL, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	//cout << GetLastError() << endl;
	BYTE* p = NULL;
	DWORD hSize = GetFileSize(hFile, 0);
	HANDLE hFileMapping = CreateFileMapping(hFile, 0, PAGE_EXECUTE_READWRITE, 0, hSize, 0);
	LPVOID MapBaseAddr= MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	p = (BYTE*)MapBaseAddr;
	if (p == NULL)
	{
		cout << "Map Fail" << endl;
		getchar();
		return 0;
	}
	ULONG S = 0;
	for (DWORD i = 1;i<=hSize; i++)
	{
		if (p >((BYTE*)MapBaseAddr+hSize)) break;
		S = S + (*p);
		p = p++;
	}
	//printf("%02X",S);
	//cout << endl;
	hFile = CreateFile(FileName,GENERIC_ALL, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//cout << GetLastError()<< endl;
	LONG Buffer[1] = { 0 };
	LPDWORD lpNumberOfBytesRead = NULL;
	ReadFile(hFile, Buffer, 4, lpNumberOfBytesRead, 0);
	if (S != Buffer[0])
		cout << "This File Have Been Patch!" << endl;
	else cout << "This File Haven't Been Patch" << endl;
	CloseHandle(hFile);
	return 1;
}
BOOL RegCheck()
{






}

