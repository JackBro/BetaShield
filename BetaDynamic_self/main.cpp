#include "main.h"
#include "Functions.h"
#include "JunkMacros.h"
#include "../BetaStatic/XOR.h"

#pragma optimize("", off )
HMODULE hCurrentModule;
static PANTI_MODULE_INFO pami = new ANTI_MODULE_INFO;
bool bModuleInfoRet;
#pragma optimize("", on )


#pragma optimize("", off )
extern "C" __declspec(dllexport) int __cdecl Initialize() {
	return 0;
}

int Init() {
	KARMA_MACRO_3
	Anti_Common lpCommon;
	KARMA_MACRO_1
	static char* cIpList[] = { "127.0.0.2", "46.20.13.166" };

	if (bModuleInfoRet == true) {
		lpCommon.InitAntiCheat("456", cIpList, 2, "", hCurrentModule, (const char*)pami, 1903);
		return 0;
	}
	lpCommon.InitAntiCheat("456", cIpList, 2, "", hCurrentModule, nullptr, 1903);
	KARMA_MACRO_2

	return 0;
}

extern "C" __declspec(dllexport) void __cdecl InitializeShadow(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	KARMA_MACRO_2
	Anti_Common lpCommon;
	KARMA_MACRO_3
	lpCommon.InitShadow(hwnd, hinst, lpszCmdLine, nCmdShow);
}
#pragma optimize("", on )

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (bModuleInfoRet == false) {
		hCurrentModule = hModule;
		bModuleInfoRet = CFunctions::CreateInfoData(pami, hModule);
	}

	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
#ifndef _DEBUG
			CFunctions::DestroyIAT((HMODULE)pami->BaseAddress);
			CFunctions::DestroySections((HMODULE)pami->BaseAddress);
			CFunctions::HideModuleLinks((HMODULE)pami->BaseAddress);
#endif
			Init();
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
