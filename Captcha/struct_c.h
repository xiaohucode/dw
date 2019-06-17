#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <tchar.h>

typedef struct _logindata
{
	CHAR userid[255];
	CHAR password[255];
	UINT Area;
	CHAR cp[255];
}logindata;

#define MAX_SIZE_BYTE 256
#define Read_Size_Buffer 4096
#define GameName _T("KartRider.exe")