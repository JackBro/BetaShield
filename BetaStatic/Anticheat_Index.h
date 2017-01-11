#pragma once
#include <Windows.h>
#include <Psapi.h>

namespace BetaNameSpace {
	class Anti_Common {
		public:
			int InitAntiCheat(const char* c_szLicenseCode, char* cIpList[], size_t szIpCount, const char* c_szPatcherName, HMODULE hAntiModule, const char* lpInfo, int iGameCode);
			void GameFunctionTrigger(void * lpTarget, int iType);
			void InitShadow(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
	};
}

