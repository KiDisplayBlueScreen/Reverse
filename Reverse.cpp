// Reverse.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

WSADATA w;
int  b, c=0;
SOCKET d;
HDC a;
SOCKADDR SOCK;
VOID f(void);
int main()
{
	 a=GetDC(0);
	 b=GetDeviceCaps(a, 0x8);
	 c = GetDeviceCaps(a, 0xA);
	 f();
	 system("pause");

    return 0;
}

VOID f(void)
{  
	int name=16;
	WSAStartup(0x101, &w);
	d=socket(2, 2, 0);
	SOCK.sa_family = 2;
	bind(d, &SOCK, 0x10);
	getsockname(d, &SOCK,&name);
	LPWSTR Buffer = new TCHAR[20];
	u_short *p = &SOCK.sa_family;

	__asm
	{
		lea ebx, p
		mov eax, p
		mov eax, [eax + 0x2]
		xchg ah, al
		mov [ebx], eax
	}


	wsprintfW(Buffer, L"Service On,Port Num: %d",p);
	MessageBox(0, Buffer, L"Tip", MB_OK);
}
