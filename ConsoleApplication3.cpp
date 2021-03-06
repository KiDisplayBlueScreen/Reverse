#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
using namespace std;
WCHAR* WINAPI GetProcessNameByPID(DWORD ProcessID);
WCHAR* WINAPI GetParentNameByProcName(LPCWSTR ProcessName);
BOOL GetAllProcess();
typedef struct tagProcessInfo
{
	DWORD PID;
	WCHAR* ProcessName;
	WCHAR* ParentName;
}SimProcessInfo;
SimProcessInfo ProcInfo[200] = { 0 };
int main()
{
	DWORD ProcessID;
	DWORD ProcessIds[200] = { 0 };
	DWORD cb = 200 * sizeof(DWORD);
	DWORD BytesReturned = 0;
	EnumProcesses(ProcessIds, cb, &BytesReturned);
	int ProcessNumber = BytesReturned / sizeof(DWORD);
	GetAllProcess();
	cout << "There Are " << ProcessNumber << " Processes in Current System" << endl;
begin:
	cout << endl;
	cout << "Input a Process Id To Find Correspond Process" << endl;
	cin >> ProcessID;
	WCHAR* ProcessName = NULL;
	WCHAR* ParentName = NULL;
	ProcessName = GetProcessNameByPID(ProcessID);
	if (ProcessName == NULL)
	{
		cout << "Get Process Name Fail." << endl;
		getchar();
		goto begin;
	}
	if (ProcessName != NULL)
	{
		cout << "Get Process Name Success ." << endl;
		printf("Process Name Is: %S \n", ProcessName);

	}
	ParentName = GetParentNameByProcName(ProcessName);
	if (ParentName != NULL)
	{
		printf("This Process's Parent Process Name Is: %S \n", ParentName);
		goto begin;
	}

	if (ParentName == NULL)
		cout << "Get Parent Process Name Fail,Maybe This Process Has No Parent Process Or Access Denied." << endl;
	goto begin;
	getchar();
	return 0;
}
WCHAR* WINAPI GetProcessNameByPID(DWORD ProcessID)
{

	WCHAR* pProcessName = NULL;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 ProcessInfo;
	ProcessInfo.dwSize = sizeof(ProcessInfo);
	BOOL bMore = Process32First(hSnapShot, &ProcessInfo);
	while (bMore)
	{
		if (ProcessInfo.th32ProcessID == ProcessID)
		{
			pProcessName = (ProcessInfo.szExeFile);
			break;
		}
		bMore = Process32Next(hSnapShot, &ProcessInfo);
	}

	if (pProcessName == NULL)
	{
		CloseHandle(hSnapShot);
		return 0;
	}
	else
	{
		CloseHandle(hSnapShot);
		return pProcessName;
	}
}
WCHAR* WINAPI GetParentNameByProcName(LPCWSTR ProcessName)
{
	WCHAR* pProcessName = NULL;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 ProcessInfo;
	DWORD ParentProcessID = 0;
	ProcessInfo.dwSize = sizeof(ProcessInfo);
	BOOL bMore = Process32First(hSnapShot, &ProcessInfo);
	while (bMore)
	{
		if (wcscmp(ProcessName, ProcessInfo.szExeFile) == 0)
		{
			ParentProcessID = (ProcessInfo.th32ParentProcessID);
			break;
		}
		bMore = Process32Next(hSnapShot, &ProcessInfo);
	}

	if (ParentProcessID != 0)
	{
		pProcessName = GetProcessNameByPID(ParentProcessID);
	}

	if (pProcessName != NULL)
	{
		CloseHandle(hSnapShot);
		return pProcessName;
	}
	else
	{
		CloseHandle(hSnapShot);
		return 0;
	}

}

BOOL GetAllProcess()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		cout << "Get Process Snap Shot Fail ." << endl;
		return 0;
	}
	BOOL bMore = Process32First(hSnapShot, &pe32);
	for (int i = 0; bMore != FALSE; i++)
	{
		ProcInfo[i].PID = pe32.th32ProcessID;
		ProcInfo[i].ProcessName = pe32.szExeFile;
		ProcInfo[i].ParentName = GetProcessNameByPID(pe32.th32ParentProcessID);
		printf("Process Name: %S \n", pe32.szExeFile);
		printf("Process ID : %u \n", pe32.th32ProcessID);
		if (ProcInfo[i].ParentName != NULL)
		{
			printf("Process Parent Name: %S \n \n", ProcInfo[i].ParentName);

		}
		if (ProcInfo[i].ParentName == NULL)
		{
			printf("This Process May Has No Parent Process. \n \n");

		}

		bMore = Process32Next(hSnapShot, &pe32);
	}
	CloseHandle(hSnapShot);
	return 1;
}

