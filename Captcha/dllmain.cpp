// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "struct_c.h"
#include "Captcha.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		
		TCHAR module_file_path[MAX_PATH];
		GetModuleFileName(GetModuleHandle(NULL), module_file_path, MAX_PATH);

		if (!lstrcmpi(module_file_path + lstrlenW(module_file_path) - lstrlenW(GameName), GameName))
		{
			CloseHandle(CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Init, NULL, NULL, NULL));
			return TRUE;
		}
		
	}
	break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

