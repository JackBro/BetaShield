#include "ProjectMain.h"
#include "NktHookWrapper.h"
#include "NktHookLib.h"

#ifdef _DEBUG

#ifdef _WIN64
#pragma comment(lib, "NktHookLib_Debug_64.lib")
#else
#pragma comment(lib, "NktHookLib_Debug.lib")
#endif

#else

#ifdef _WIN64
#pragma comment(lib, "NktHookLib_64.lib")
#else
#pragma comment(lib, "NktHookLib.lib")
#endif

#endif

static const wchar_t* CharToWchar(const char* c_szTmpName)
{
	std::string szTmpName = c_szTmpName;
	std::wstring wszTmpName(szTmpName.begin(), szTmpName.end());
	return wszTmpName.c_str();
}
static const char* WCharToChar(const wchar_t* c_wszTmpName)
{
	std::wstring wszTmpName = c_wszTmpName;
	std::string szTmpName(wszTmpName.begin(), wszTmpName.end());
	return szTmpName.c_str();
}


PVOID NktHelper::GetModuleBaseAddress_A(const char* c_szModuleName)
{
	const wchar_t* c_wszName = nullptr;
	HINSTANCE result = NULL;
	__try {
		c_wszName = CharToWchar(c_szModuleName);
		result = NktHookLibHelpers::GetModuleBaseAddress(c_wszName);
	}
	__except (1) {
	}
	return (PVOID)result;
}

PVOID NktHelper::GetModuleBaseAddress_W(const wchar_t* c_wszModuleName)
{
	HINSTANCE result = NULL;
	__try {
		result = NktHookLibHelpers::GetModuleBaseAddress(c_wszModuleName);
	}
	__except (1) {
	}
	return (PVOID)result;
}

PVOID NktHelper::GetProcAddress_A(HMODULE hModule, const char* c_szProcName)
{
	LPVOID result = NULL;
	__try {
		result = NktHookLibHelpers::GetProcedureAddress(hModule, c_szProcName);
	}
	__except (1) {
	}
	return result;
}

PVOID NktHelper::GetProcAddress_W(HMODULE hModule, const wchar_t* c_wszProcName)
{
	const char* c_szName = nullptr;
	LPVOID result = NULL;
	__try {
		c_szName = WCharToChar(c_wszProcName);
		result = NktHookLibHelpers::GetProcedureAddress(hModule, c_szName);
	}
	__except (1) {
	}
	return result;
}
