#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <math.h>
#include <iomanip>
#include <cmath>
#include <time.h>
using namespace std;
int WINAPI MylstrlenA(LPCSTR lpString);
ULONG IsNumberPrime(ULONG x);
DOUBLE StringToNumber(PCHAR pString);
ULONG StringToUlong(PCHAR pString, int Length);
LONG StringToLong(PCHAR pString, int Length);
WORD IsNumberFloat(PCHAR pString);
DOUBLE StringToFloat(PCHAR pString);
int main(int argc, char *argv[])
{

	
	char Number[50] = { 0 };
	PBYTE p =(PBYTE)Number;
	begin:
	cin >> p;


	cout << fixed << setprecision(10) << StringToNumber(Number)<< endl;
	cout << endl;
	system("pause");
	return 0;
}

int WINAPI MylstrlenA(LPCSTR lpString)
{
	if (lpString == NULL) return 0;
	PBYTE String1 =(PBYTE) lpString;
	PBYTE String2 = (PBYTE)lpString;
	while (*String1 != 0)
	{
		String1++;
	}
	return String1 - String2;
}
ULONG IsNumberPrime(ULONG x)
{
	DWORD m = 2;
	if (x == 0 || x == 1) { return 0; }
	for (m = 2; m <= sqrt(x); m = m + 1)
		if (x%m == 0)
			return 0;
	return 1;
}
DOUBLE StringToNumber(PCHAR pString)
{
	PBYTE p = (PBYTE)pString;
	int Flags1 = 0;
	int i = strlen(pString);
	int RealPart=0;
	int FloatPar=0;
	int Flags2 = IsNumberFloat(pString);
	for (; i > 0; i--)
	{
		if (*p == 0x2D)
		{
			p++;
			Flags1 = 1;
			continue;
		}
		if((*p < 0x30 || *p>0x39)&&Flags2==0)
		{
			return 0;
		}
		p++;
	}
	i = strlen(pString);
	if (Flags1 == 0&&Flags2==0)
	{
		return StringToUlong(pString, i);
	}
	if (Flags1 == 1 && Flags2 == 0)
	{
		return StringToLong(pString, i);
	}

	if (Flags1 == 0 && Flags2 == 1)
	{
		return StringToFloat(pString);
	}
}

ULONG StringToUlong(PCHAR pString,int Length)
{
	PBYTE p = (PBYTE)pString;
	ULONG x = 0;
	for (; Length > 0; Length--)
	{
		x = x + (*p - 0x30)*pow(10, Length - 1);
		p++;
	}
	return x;
}

LONG StringToLong(PCHAR pString, int Length)
{
	PBYTE p = (PBYTE)pString+1;
	LONG x = 0;
	for (; Length-1>0; Length--)
	{
		x = x + (*p - 0x30)*pow(10, Length - 2);
		p++;
	}
	return (~x + 1);
}
WORD IsNumberFloat(PCHAR pString)
{
	PBYTE p = (PBYTE)pString;
	WORD Flag = 0;
	while (*p != 0)
	{
		if (*p == 0x2E)
		{
			Flag = 1;
			break;
		}
		p++;
	}
	return Flag;
}
DOUBLE StringToFloat(PCHAR pString)
{
	PBYTE p = (PBYTE)pString;
	LONG RealLong = 0;
	LONG FloatLong = 0;
	while (*p != 0x2E)
	{
		RealLong++;
		p++;
	}
	p = (PBYTE)pString;
	FloatLong = strlen(pString) - RealLong - 1;
	DOUBLE RealPart = StringToUlong((PCHAR)p, RealLong);
	p= (PBYTE)pString + RealLong+1;
	DOUBLE FloatPart = StringToUlong((PCHAR)p, FloatLong);
	FloatPart = FloatPart / pow(10, FloatLong);
	return  (DOUBLE)(RealPart+FloatPart);
}