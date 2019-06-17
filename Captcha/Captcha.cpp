// Captcha.cpp : 定义 DLL 应用程序的导出函数。
//
#include "struct_c.h"
#include <detours.h>
#pragma comment(lib, "detours.lib")

BOOL DetourFunc(bool enable, void** function, void* redirection)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(function, redirection);
	DetourTransactionCommit();
	DetourTransactionAbort();
	return false;
}


DWORD _ReadOffset(BYTE *arrayBytes, BYTE *bytes, BYTE *byteStep, DWORD len, DWORD Start_Offset)
{
	for (UINT i = Start_Offset; i < 4096 - len; i = i)
	{
		UINT p = 0;
		for (UINT j = 0; j < len; j++)
		{
			if (arrayBytes[i + j] != bytes[j]) {
				i += byteStep[arrayBytes[i + len]];
				break;
			}
			else { p++; }
		}
		if (p == len) { return i; }
	}
	return -1;
}
DWORD MemoryScan(BYTE ccode[], SIZE_T sLen, DWORD startAddr, DWORD endAddr)
{
	if (startAddr >= endAddr) { return -2; }//范围错误
	DWORD Start = ((DWORD)startAddr / Read_Size_Buffer) * Read_Size_Buffer;
	DWORD Start_Offset = startAddr - Start;	
	BYTE *bytes = new BYTE[sLen];
	memcpy(bytes, ccode, sLen);
	BYTE byteStep[MAX_SIZE_BYTE];
	for (UINT i = 0; i < MAX_SIZE_BYTE; i++)
		byteStep[i] = (BYTE)sLen + 1;//如果不存在则设置值为 “小串长度+1”		
	for (UINT i = 0; i < sLen; i++)
		byteStep[bytes[i]] = (BYTE)(sLen - i);//如果存在则设置值为 “从右边数的位置(从1开始)”			
	for (DWORD i = Start; i < endAddr; i += Read_Size_Buffer)
	{
		DWORD oldProtect = NULL;
		if (!VirtualProtect((LPVOID)i, Read_Size_Buffer, PAGE_EXECUTE_READWRITE, &oldProtect))
			continue;
		BYTE *arrayBytes = new BYTE[Read_Size_Buffer];
		memcpy(arrayBytes, (LPVOID)i, Read_Size_Buffer);
		//ReadProcessMemory(GetCurrentProcess(), (LPVOID)i, arrayBytes, Read_Size_Buffer, NULL);
		VirtualProtect((LPVOID)i, Read_Size_Buffer, oldProtect, NULL);
		DWORD offset = _ReadOffset(arrayBytes, bytes, byteStep, sLen, Start_Offset);
		if (arrayBytes != NULL)
			delete arrayBytes;//删掉指针

		if (offset != -1)
		{
			if (bytes != NULL)
				delete bytes;//删掉指针
			return i + offset;	//如果找到则返回位置
		}
		Start_Offset = 0;//还原开始偏移位置
	}
	if (bytes != NULL)
		delete bytes;//删掉指针
	return -4;//未找到特征码
}

void WINAPI MyDbgPrintFun(char *lpFmt, ...)   
{
	char szMsg[1024] = { 0 };
	va_list	arglist;
	char *ptr = szMsg;
	va_start(arglist, lpFmt);
	vsprintf(ptr, lpFmt, arglist);
	va_end(arglist);
	OutputDebugStringA(szMsg); 
}

bool Hook_GetCaptchaForGame()
{
	typedef BOOL(WINAPI* GetCaptchaForGame_T)(PCHAR UserID, DWORD flags, PVOID pUnknown, PVOID *CaptchaData, PDWORD CaptchaLen);
	static GetCaptchaForGame_T GetCaptchaForGame_ = reinterpret_cast<GetCaptchaForGame_T>(GetProcAddress(GetModuleHandle(NULL), "?GetCaptchaForGame@Lexian_Sdk_Client@@QAEHPADHAAHPAPAEAAK@Z"));

	//MyDbgPrintFun("GetCaptchaForGame_:[%08X]\n", GetCaptchaForGame_);

	GetCaptchaForGame_T GetCaptchaForGame_Hook = [](
		PCHAR UserID,
		DWORD flags,
		PVOID pUnknown,
		PVOID *CaptchaData,
		PDWORD CaptchaLen
		)->BOOL
	{
		
		BOOL result = GetCaptchaForGame_(UserID, flags, pUnknown, CaptchaData, CaptchaLen);
		 
		if (result)		{
			CHAR MapFileName[MAX_PATH] = { 0 };
			sprintf(MapFileName, "Global\\Mappingcap%s", UserID);
			HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, MapFileName);

			if (hMapFile)			{
				void* mapping_view = MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
				memcpy(mapping_view, *CaptchaData, *CaptchaLen);
				CHAR UserEventName[MAX_PATH] = { 0 };
				sprintf_s(MapFileName, "Global\\Eventcap%s", UserID);
				HANDLE hUserEven = OpenEventA(EVENT_ALL_ACCESS, FALSE, MapFileName);

				if (hUserEven)				{
					SetEvent(hUserEven);
					WaitForSingleObject(hUserEven, -1);
					CloseHandle(hUserEven);
				}
				UnmapViewOfFile(mapping_view);
				CloseHandle(hMapFile);
			}
		}
		return result;
	};
	return DetourFunc(true, reinterpret_cast<PVOID*>(&GetCaptchaForGame_), GetCaptchaForGame_Hook);
}

//int __thiscall Lexian_Sdk_Client::AuthLogin(Lexian_Sdk_Client *this, char *a2, char *a3, int a4, char *a5, char *a6, char **a7)


DWORD g_ecx;

VOID __declspec(naked) pushecx()
{
	__asm mov dword ptr [g_ecx], ecx;
	__asm retn;
}
VOID __declspec(naked) popecx()
{
	__asm mov  ecx, dword ptr[g_ecx];
	__asm retn;
}

bool Hook_AuthLogin()
{
	typedef DWORD(WINAPI* AuthLogin_T)(PCHAR UserID, PCHAR PassWord, UINT Area, PCHAR CaptchaStr, char *a6, char **a7);
	static AuthLogin_T AuthLogin_ = reinterpret_cast<AuthLogin_T>(GetProcAddress(GetModuleHandle(NULL), "?AuthLogin@Lexian_Sdk_Client@@QAEHPAD0H00PAPAD@Z"));

	AuthLogin_T AuthLogin_Hook = [](PCHAR UserID, PCHAR PassWord, UINT Area, PCHAR CaptchaStr, char *a6, char **a7	)->DWORD
	{
		pushecx();
		DWORD result = NULL;
		CHAR MapFileName[MAX_PATH] = { 0 };
		sprintf(MapFileName, "Global\\Mappinglogin%s", UserID);
		HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, MapFileName);
		if (hMapFile)
		{
			logindata *longin = reinterpret_cast<logindata*>(MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));

			UserID = longin->userid;
			PassWord = longin->password;
			Area = longin->Area;
			CaptchaStr = longin->cp;

			popecx();
			result = AuthLogin_(UserID, PassWord, Area, CaptchaStr, a6, a7);
			UnmapViewOfFile(longin);
			CloseHandle(hMapFile);
		}
		else
		{
			result = AuthLogin_(UserID, PassWord, Area, CaptchaStr, a6, a7);
		}

	

		return result;
	};
	return DetourFunc(true, reinterpret_cast<PVOID*>(&AuthLogin_), AuthLogin_Hook);
}


BYTE CapCheck[] = { 0x85,0xC0,0x74,0x0C,0xC7,0x85,0xE4,0xFE,0xFF,0xFF,0x01,0x00,0x00,0x00 };
BYTE AutoLogin[] = { 0x33,0xC0,0xE9,0x66,0x15,0x00,0x00 };
BYTE AutoLoginR[] = { 0x83, 0xBD, 0x44, 0xFE, 0xFF, 0xFF, 0x00, 0x0F, 0x85, 0x9C, 0x00, 0x00, 0x00 };

VOID Init()
{
	while (!GetModuleHandle(_T("BlackCall.aes")))
		Sleep(1000);
	Hook_GetCaptchaForGame();
	Hook_AuthLogin();

	auto CapCheckAddr=
	MemoryScan(CapCheck,sizeof(CapCheck), 0xA00000, 0x1000000);
	//检查验证码是否符合标准
	if (CapCheckAddr)	{
		MyDbgPrintFun("CapCheckAddr:[%08X]\n", CapCheckAddr);
		*(BYTE*)(CapCheckAddr + 0x2) = 0xEB;
	}
	auto AutoLoginAddr= MemoryScan(AutoLogin, sizeof(AutoLogin), 0xA00000, 0x1000000);


	//当登陆界面初始完毕自动调用登陆函数
	if (AutoLoginAddr)	{
		MyDbgPrintFun("AutoLoginAddr:[%08X]\n", AutoLoginAddr);
		*(DWORD*)(AutoLoginAddr + 0x3) = 0x34C;
	}
	auto AutoLoginRAddr = MemoryScan(AutoLoginR, sizeof(AutoLoginR), 0xA00000, 0x1000000);
	//当验证码不正确.循环获取
	if (AutoLoginRAddr)	{
		MyDbgPrintFun("AutoLoginRAddr:[%08X]\n", AutoLoginRAddr);
		*(long*)(AutoLoginRAddr + 0x9) = 0xFFFFFE00;
		//memcpy((PBYTE)AutoLoginRAddr + 0x36, "\x0F\x84\xD1\xFD\xFF\xFF\x90\x90\x90", 9);
	}

	auto fpMessageBoxW = GetProcAddress(LoadLibrary(_T("user32.dll")), "MessageBoxW");
	auto oldProtect = NULL;
	if (VirtualProtect((PVOID)fpMessageBoxW, 4, PAGE_EXECUTE_READWRITE, reinterpret_cast<PDWORD>(&oldProtect)))	{
		MyDbgPrintFun("fpMessageBoxW:[%08X]\n", fpMessageBoxW);

		*(DWORD*)((DWORD)fpMessageBoxW) = 0x8B0010C2;
	} 
	 
	//
}
