#include "stdafx.h"
#include <iostream>
#include <Windows.h>
using namespace std;
int main()
{
	LPCSTR D = "%d";
	float x = 0;
	float i = 1;
	for (; i <= 100; i++)
	{
		x = x + 1 / i;
	}

	cout << x << endl;

	system("pause");
	return 0;








}