#include "stdafx.h"
#include <Windows.h>
#include <iostream>
using namespace std;
PBYTE GetDWORDBit(DWORD Dest);
PBYTE Func004BB5F4(PBYTE FakeReg);
PBYTE Func004BB540(PBYTE FakeReg);
PBYTE Func004BB910(PBYTE UserName, PBYTE MachineCode);
int main()
{
	LPCSTR lpRootPathName = "C:\\";
	DWORD VolumeSerialNumber;
	DWORD MaximumComponentLength;
	DWORD FileSystemFlags;
	CHAR VolumeSerial[10] = { 0 };
	CHAR Volume[9] = { 0 };
	BYTE MachineCode[15] = { 0 };
	GetVolumeInformationA(lpRootPathName, 0, 0, &VolumeSerialNumber, &MaximumComponentLength, &FileSystemFlags, 0, 0);
	printf("VolumeSerialNumber: 0x%08X \n ", VolumeSerialNumber);
	wsprintfA(VolumeSerial, "%#X", VolumeSerialNumber);
	for (int i = 2; i <= 9; i++)
	{
		Volume[i - 2] = VolumeSerial[i];
	}



	for (int i = 7; i >= 0; i--)
	{
		if (Volume[i] == 0x39 || Volume[i] == 0x5A)
		{
			MachineCode[7 - i] = Volume[i];
		}
		else 
		{
			MachineCode[7 - i] = Volume[i] + 1;
		}
	}
		printf("%s \n", MachineCode);
		
		BYTE FakeCode[50] = { 0 };
		BYTE UserName[50] = { 0 };
		cout << "Input The UserName" << endl;
		cin >> UserName;
		cout << "Input The Fake Code" << endl;
		cin >> FakeCode;



		PBYTE P=Func004BB5F4(FakeCode);
		printf("%s \n", P);
		PBYTE P2 = Func004BB540(P);
		printf("%s \n", P2);

		P2 = Func004BB910(UserName, MachineCode);
		printf("%s \n", P2);







	PAUSE;
    return 0;
}
PBYTE Func004BB5F4(PBYTE FakeReg)
{
	LPCSTR Temp = (LPCSTR)FakeReg;
	int i = 0;
	int Length = strlen(Temp) - 1;
	if (Length != 39) return 0;
	BYTE Buffer1[2] = { 0 };
	BYTE Buffer2[0x40] = { 0 };
	for (; i <= Length && *FakeReg != 0; i=i+2)
	{
		int t;
		if (i == 0)
		{
			t = i;
		}
		if (i >= 2)
		{
			t = i >>1;//第1次t=0,第2次t=1,第3次t=5/2,第4次t=7/2
		}
		BYTE AL = FakeReg[i + 1];
		Buffer1[1] = AL & 0x4F;
		Buffer1[0] = (AL & 0x30&0xFF)>>4;
		if (AL >= 0x40)
		{
			if (Buffer1[1] >= 0x43)
			{
				Buffer1[1] -= 0x43;
				AL = FakeReg[i];
				AL=AL >> Buffer1[1];
				Buffer2[t] = AL;
				continue;
			}
			else
			{
				//AL = 0x43;
				Buffer1[1] = 0x43 - Buffer1[1];
				BYTE BLX = FakeReg[i];
				BLX = (BLX <<Buffer1[1])|Buffer1[0];
				BLX =BLX | Buffer1[0];
				AL = BLX;
				Buffer2[t] = AL;
				continue;
			}
			AL = FakeReg[i];
			Buffer2[t] = AL;
		}

		else 
		{
			Buffer2[t] = 0;
		}
	}
	return Buffer2;
}
PBYTE Func004BB540(PBYTE FakeReg)
{
	DWORD ESI = 0x3D6;
	DWORD Local2 = 0x3183;
	DWORD Arg2 = 0x8C34;
	BYTE Buffer[0x20] = { 0 };
	for (int i = 0; i <= 0x13 && *FakeReg != 0; i++)
	{
		
		BYTE Temp = (BYTE)( (ESI >> 8) & 0xFF );
		Buffer[i] = FakeReg[i] ^ Temp;
		ESI += FakeReg[i];
		ESI *= Local2;
		ESI += Arg2;
	}
	return Buffer;

}
PBYTE Func004BB910(PBYTE UserName, PBYTE MachineCode)
{
	strcat_s((PCHAR)UserName, 50, (PCHAR)MachineCode);
	strlen((LPCSTR)UserName);





	return UserName;

}


























PBYTE GetDWORDBit(DWORD Dest)
{
	BYTE Return[8] = { 0 };
	__asm
	{
		mov eax, Dest
		and eax, 0xF0000000
		shr eax, 0x1C
		mov Return[0], al

		mov eax, Dest
		and eax, 0xF000000
		sar eax, 0x18
		mov Return[1], al

		mov eax, Dest
		and eax, 0xF00000
		sar  eax, 0x14
		mov Return[2], al


		mov eax, Dest
		and eax, 0xF0000
		sar  eax, 0x10
		mov Return[3], al

		mov eax, Dest
		and eax, 0xF000
		sar  eax, 0xC
		mov Return[4], al

		mov eax, Dest
		and eax, 0xF00
		sar  eax, 0x8
		mov Return[5], al

		mov eax, Dest
		and eax, 0xF0
		sar  eax, 0x4
		mov Return[6], al


		mov eax, Dest
		and eax, 0xF
		mov Return[7], al
	}
	return Return;
}