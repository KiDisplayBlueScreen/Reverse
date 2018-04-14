#include "stdafx.h"
#include <iostream>
#include <Windows.h>
using namespace std;
int addsub(BOOL Flags);
int add(char int1[4], char int2[4]);
int sub(char int1[4], char int2[4]);

int main()
{

	char GDT[6];
	unsigned long GDT_ADDR;
	unsigned short GDT_LIMIT;
	_asm sgdt GDT;
	GDT_ADDR = *(unsigned long *)(&GDT[2]);
	GDT_LIMIT = *(unsigned short *)(&GDT[0]);
	printf("GDT Base: %08X\n", GDT_ADDR);
	printf("GDT Limit: %04X\n", GDT_LIMIT);
	char int1[4] = { 0 };
	char int2[4] = { 0 };
	char *a = int1;
	char *b = int2;
	cin >> a;
	cin >> b;
	//add(int1, int2);

	cout << endl;
	sub(int1, int2);
	cout << endl;
	system("pause");
    return 0;
}
int addsub(BOOL Flags)
{
	int m;
	int *p = new int[m];
	return 0;
}
int add(char int1[4], char int2[4])
{
	int c[4] = { 0,0,0,0 };
	int Plus = 0;
	int i = 0;
	for (i = 0; i <= 3; i++)
	{
		int1[i] = int1[i] - 0x30;
		int2[i] = int2[i] - 0x30;
	}
	c[3] = int1[3] ^ int2[3] ^ Plus;
	if (int1[3] == 1 && int2[3] == 1) { Plus = 1; }
	for (i = 2; i >= 0; i--)
	{
		c[i] = int1[i] ^ int2[i] ^ Plus;
		if (int1[i] == 1 && int2[i] == 1 || int1[i] == 1 && Plus == 1 || int2[i] == 1 && Plus == 1)
			Plus = 1;
		else Plus = 0;
	}
	for (i = 0; i <= 3; i++)
	{
		c[i] += 0x30;
		int1[i] = c[i];
		cout << int1[i] << " ";
	}
	return 0;

}
int sub(char int1[4], char int2[4])
{
	char f[4] = {'0','0','0','1'};
	char a = int2[0];
	char b = int2[1];
	char c= int2[2];
	char d = int2[3];
	__asm
	{
		mov al,a
		sub al,0x30
		not al
		add al, 0x32
		mov a, al
		mov al, b
		sub al, 0x30
		not al
		add al, 0x32
		mov b, al
		mov al, c
		sub al, 0x30
		not al
		add al, 0x32
		mov c, al
		mov al,d
		sub al, 0x30
		not al
		add al,0x32
		mov d, al
	}
	int2[0] = a;
	int2[1] = b;
	int2[2] = c ;
	int2[3] = d;
	add(int2, f);
	cout << endl;
	add(int1, int2);
	return 0;
}
