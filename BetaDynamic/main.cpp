#include "main.h"
#include "Functions.h"
#include "JunkMacros.h"

#pragma optimize("", off )
HMODULE hCurrentModule = nullptr;
static PANTI_MODULE_INFO pami = new ANTI_MODULE_INFO;
bool bModuleInfoRet = false;
#pragma optimize("", on )



#pragma optimize("", off )
extern "C" __declspec(dllexport) int __cdecl Initialize(const char* c_szLicenseCode, char* cIpList[], int iIpCount, const char* c_szPatcherName, int iGameCode)
{
	DWORD dwCaller = 0;
	__asm {
		push dword ptr[ebp + 4]
		pop  dword ptr[dwCaller]
	}
	KARMA_MACRO_3
	if (!strlen(c_szLicenseCode) || !cIpList || !iIpCount || !iGameCode)
		return 0;

	Anti_Common lpCommon;
	KARMA_MACRO_1
	if (bModuleInfoRet == true) {
		lpCommon.InitAntiCheat(c_szLicenseCode, cIpList, iIpCount, c_szPatcherName, hCurrentModule, (const char*)pami, iGameCode  /* , dwCaller */);
		return 0;
	}
	lpCommon.InitAntiCheat(c_szLicenseCode, cIpList, iIpCount, c_szPatcherName, hCurrentModule, nullptr, iGameCode  /* , dwCaller */);
	KARMA_MACRO_2

	return 0;
}

extern "C" __declspec(dllexport) void __cdecl FunctionTrigger(void * lpTarget, int iType)
{
	DWORD dwCaller = 0;
	__asm {
		push dword ptr[ebp + 4]
		pop  dword ptr[dwCaller]
	}
	KARMA_MACRO_1
	Anti_Common lpCommon;
	KARMA_MACRO_2
	lpCommon.GameFunctionTrigger(lpTarget, iType /* , dwCaller */);
	KARMA_MACRO_3
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
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
