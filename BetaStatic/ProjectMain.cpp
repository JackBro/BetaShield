#include "ProjectMain.h"
#include "AntiCheat_Index.h"
#include "Data.h"
#include "Main.h"
#include "Functions.h"
#include "Metin2_Plugin.h"

#ifdef SCRENSHOT_FEATURE
#pragma comment(lib, "gdiplus.lib")
#endif
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "MPR")
#pragma comment(lib, "wbemuuid.lib")


#pragma optimize("", off )
namespace BetaNameSpace
{
	int Anti_Common::InitAntiCheat(const char* c_szLicenseCode, char* cIpList[], size_t szIpCount, const char* c_szPatcherName, HMODULE hAntiModule, const char* lpInfo, int iGameCode)
	{
		KARMA_MACRO_2
		DWORD dwCaller = 0;
		__asm {
			push dword ptr[ebp + 4]
			pop  dword ptr[dwCaller]
		}

		KARMA_MACRO_1
		LPMain = new CMain();
		LPMain->InitClasses();
		KARMA_MACRO_2

		__MUTATE_START__("pm+")

		LPData->SetInitializedMain(false); KARMA_MACRO_2

		LPData->SetLicenseCode(c_szLicenseCode); KARMA_MACRO_1
		LPData->SetLicensedIPs(cIpList, szIpCount); KARMA_MACRO_2
		LPData->SetPatcherName(c_szPatcherName); KARMA_MACRO_2
		LPData->SetAntiModule(hAntiModule); KARMA_MACRO_1 /* TODO: Anti gethandle */	
		LPData->SetAntiModuleInformations(lpInfo);
		LPData->SetGameCode(iGameCode); KARMA_MACRO_2
		__MUTATE_END__("pm-")

		LPMain->InitMain(dwCaller); KARMA_MACRO_2

		__MUTATE_START__("pm2+")
		LPData->SetInitializedMain(true); KARMA_MACRO_2
		__MUTATE_END__("pm2-")

		return 1;
	}

	void Anti_Common::GameFunctionTrigger(void * lpTarget, int iType)
	{
		KARMA_MACRO_1
		DWORD dwCaller = 0;
		__asm {
			push dword ptr[ebp + 4]
			pop  dword ptr[dwCaller]
		}
		KARMA_MACRO_2

		if (LPData->MainIsInitialized() == false)
			return;

		KARMA_MACRO_2
		LPPluginMetin2->GameFunctionTrigger(dwCaller, lpTarget, iType);
	}

	void Anti_Common::InitShadow(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
	{
		KARMA_MACRO_2
		DWORD dwCaller = 0;
		__asm {
			push dword ptr[ebp + 4]
			pop  dword ptr[dwCaller]
		}
		KARMA_MACRO_1

		if (LPData->IsShadowInitialized() == true)
			return;

		KARMA_MACRO_2
		LPFunctions->InitShadowEx(hwnd, hinst, lpszCmdLine, nCmdShow);
		KARMA_MACRO_1

		LPData->SetShadowInitialized(true);
	}
}

#pragma optimize("", on )
