#include "ProjectMain.h"
#include "NktHookWrapper.h"
#include "DynamicWinapi.h"
#include "BasePointers.h"
#include "Functions.h"
#include "XOR.h"
#include "VersionHelpers.h"
#include "Main.h"
#include <boost/algorithm/string/predicate.hpp>
#include "Data.h"
#include "CLog.h"
#include "DirFuncs.h"
#include "Scan.h"

/*  ---  */
WINAPI_MODULE_TABLE* BetaModuleTable;
WINAPI_API_TABLE* BetaFunctionTable;
CWinapi* LPWinapi;
CWinapi::CWinapi()
{
}

CWinapi::~CWinapi()
{

}

/*  ---  */
#pragma optimize("", off )
PVOID CWinapi::GetModuleAddressFromName(const wchar_t* c_wszName, bool bIsCompleteCheck)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (bIsCompleteCheck && boost::iequals(Current->FullDllName.Buffer, c_wszName))
			return Current->DllBase;
		else if (!bIsCompleteCheck && boost::contains(Current->FullDllName.Buffer, c_wszName))
			return Current->DllBase;

		CurrentEntry = CurrentEntry->Flink;
	}
	return nullptr;
}
bool CWinapi::IsLoadedAddress(DWORD dwAddress)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (dwAddress == (DWORD)Current->DllBase)
			return true;

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}
bool CWinapi::DestroyEntrypoint(DWORD dwAddress)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (dwAddress == (DWORD)Current->DllBase) {
			Current->EntryPoint = nullptr; // convert to memset
			return true;
		}

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}



std::vector<HMODULE>vModuleList;
inline HMODULE _GetModuleHandle(_In_ LPCTSTR lpModuleName)
{
	NktHelper nkt;
#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic called module: %s", lpModuleName);
#endif

	HMODULE tmpModule = BetaFunctionTable->GetModuleHandleA(lpModuleName);
	if (!tmpModule)
		tmpModule = BetaFunctionTable->LoadLibraryA(lpModuleName);

	KARMA_MACRO_1
	if (!tmpModule && !strstr(lpModuleName, XOR("python")))
	{
		char szWarn[1024];
		sprintf(szWarn, XOR("Module not found : %s"), lpModuleName);
		LPFunctions->CloseProcess(szWarn, false, "");
	}

	KARMA_MACRO_1
	if (tmpModule && std::find(vModuleList.begin(), vModuleList.end(), tmpModule) == vModuleList.end())
		vModuleList.push_back(tmpModule);

	
	const size_t cSize = strlen(lpModuleName) + 1;
	wchar_t* c_wszModuleName = new wchar_t[cSize];
	mbstowcs(c_wszModuleName, lpModuleName, cSize);

	PVOID lpAddressFromMemory_nkt = nkt.GetModuleBaseAddress_W(c_wszModuleName);

	if (lpAddressFromMemory_nkt && LPData->GetAntiModule() &&
		lpAddressFromMemory_nkt != tmpModule && LPData->GetAntiModule() != lpAddressFromMemory_nkt)
	{
		char szWarn[1024];
		sprintf(szWarn, XOR("Module manipulation detected: %s | %p-%p"), lpModuleName, lpAddressFromMemory_nkt, tmpModule);
		LPFunctions->CloseProcess(szWarn, false, "");
	}

	delete[] c_wszModuleName;

	KARMA_MACRO_2
	return tmpModule;
}

FARPROC WINAPI _GetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
{
	NktHelper nkt;
//#ifdef _DEBUG
//	LPLog->AddLog(0, "Dynamic called api: %s", lpProcName);
//#endif

	KARMA_MACRO_1

	FARPROC fptmpAdr = reinterpret_cast<FARPROC>(nkt.GetProcAddress_A(hModule, lpProcName));
	if (!fptmpAdr) {
		BasePointers lpBasePointers;
		VTABLE lpTable;

		if (lpBasePointers.GetBasePointers(&lpTable) && lpTable.GetProcAddress)
			fptmpAdr = lpTable.GetProcAddress(hModule, lpProcName);
	}
	if (!fptmpAdr) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', '%', 's', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'A', 'P', 'I', ' ', 'n', 'o', 't', ' ', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'd', '[', '0', 'x', '2', ']', '!', 0x0 }; // ERROR! %s Windows API not initialized[0x2]!

		char cTmpString[1024];
		sprintf(cTmpString, __warn, lpProcName);
		LPFunctions->CloseProcess(cTmpString, false, "");
	}

	KARMA_MACRO_2
	return fptmpAdr;
}


inline HMODULE _GetPythonHandle()
{	
	if (LPData->GetPythonHandle())
		return LPData->GetPythonHandle();

	HMODULE hTmp22 = _GetModuleHandle(XOR("python22.dll"));
	HMODULE hTmp27 = _GetModuleHandle(XOR("python27.dll"));

	KARMA_MACRO_1
	if (hTmp27) {
		LPData->SetPythonName(XOR("python27.dll"));
		LPData->SetPythonHandle(hTmp27);
		return hTmp27;
	}
	else if (hTmp22) {
		LPData->SetPythonName(XOR("python22.dll"));
		LPData->SetPythonHandle(hTmp22);
		return hTmp22;
	}

	KARMA_MACRO_2
	return 0;
}

inline HMODULE GetProcessInstance() {	
	KARMA_MACRO_2
	return BetaFunctionTable->GetModuleHandleA(NULL);
	KARMA_MACRO_1
}

inline void CheckModulesPaths()
{
	KARMA_MACRO_2
	for (auto &i : vModuleList)
	{
		if (i == BetaModuleTable->hBaseModule /* if module is game process */)
			continue;

		char szModuleFilePath[MAX_PATH] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'M', 'o', 'd', 'u', 'l', 'e', 0x0 };
		if (!BetaFunctionTable->GetModuleFileNameA(i, szModuleFilePath, MAX_PATH))
			continue;

		// TODO: Check python dll integrity

		std::string szLowerModuleFilePath	= szModuleFilePath;
		std::wstring wszLowerModuleFilePath(szLowerModuleFilePath.begin(), szLowerModuleFilePath.end());
		std::string szLowerWindowsPath		= LPDirFunctions->WinPath();
		std::string szLowerProcessPath		= LPDirFunctions->ExePath();
		transform(szLowerModuleFilePath.begin(), szLowerModuleFilePath.end(), szLowerModuleFilePath.begin(), tolower);
		transform(szLowerWindowsPath.begin(), szLowerWindowsPath.end(), szLowerWindowsPath.begin(), tolower);
		transform(szLowerProcessPath.begin(), szLowerProcessPath.end(), szLowerProcessPath.begin(), tolower);

		KARMA_MACRO_1
		BOOL bIsFromGamePath = BOOL(strstr(szLowerModuleFilePath.c_str(), szLowerProcessPath.c_str()));
		BOOL bIsFromWindows = BOOL(strstr(szLowerModuleFilePath.c_str(), szLowerWindowsPath.c_str()));

		if (LPData->GetGameCode() == METIN2_GAME)
		{
			auto bIsPython = (i == _GetPythonHandle());
			auto bIsPythonAndNotFromGame = (bIsPython && !bIsFromGamePath);
			auto bIsPythonAndNotFromWindows = (bIsPython && !bIsFromWindows);
			auto bIsNotPythonAndNotFromWindows = (!bIsPython && !bIsFromWindows);

			if ( (bIsPythonAndNotFromGame && bIsPythonAndNotFromWindows) || bIsNotPythonAndNotFromWindows)
			{
				CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'M', 'a', 'n', 'i', 'p', 'u', 'l', 'a', 't', 'e', 'd', ' ', 'm', 'o', 'd', 'u', 'l', 'e', ' ', '%', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // ERROR! Manipulated module %s detected!

				char cTmpString[1024];
				sprintf(cTmpString, XOR(__warn), szLowerModuleFilePath.c_str());
				LPFunctions->CloseProcess(cTmpString, false, "");
			}

			static BOOL bSignRet = FALSE;
			LPScan->IsSignedFile(wszLowerModuleFilePath.c_str(), &bSignRet);
			if (bSignRet == FALSE && bIsPython == false)
			{
#ifdef _DEBUG
				LPLog->ErrorLog(0, "Unsigned file(module handle): %s", szLowerModuleFilePath.c_str());
#endif

				// Game
				char szRealWarn[1024];
				CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 's', 'y', 's', 't', 'e', 'm', ' ', 'D', 'L', 'L', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', '!', ' ', 'D', 'L', 'L', ':', ' ', '%', 's', 0x0 }; // Unknown system DLL detected on process! DLL: %s
				sprintf(szRealWarn, __warn, szLowerModuleFilePath.c_str());
				LPFunctions->CloseProcess(szRealWarn, false, "");
			}
		}
		else
		{
			if (!bIsFromWindows) /* module not from windows */
			{
				CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'M', 'a', 'n', 'i', 'p', 'u', 'l', 'a', 't', 'e', 'd', ' ', 'm', 'o', 'd', 'u', 'l', 'e', ' ', '%', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // ERROR! Manipulated module %s detected!

				char cTmpString[1024];
				sprintf(cTmpString, __warn, szLowerModuleFilePath.c_str());
				LPFunctions->CloseProcess(cTmpString, false, "");
			}

			static BOOL bSignRet = FALSE;
			LPScan->IsSignedFile(wszLowerModuleFilePath.c_str(), &bSignRet);
			if (bSignRet == FALSE)
			{
#ifdef _DEBUG
				LPLog->ErrorLog(0, "Unsigned file(module handle): %s", szLowerModuleFilePath.c_str());
#endif

				// Console
				char szRealWarn[1024];
				CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 's', 'y', 's', 't', 'e', 'm', ' ', 'D', 'L', 'L', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', '!', ' ', 'D', 'L', 'L', ':', ' ', '%', 's', 0x0 }; // Unknown system DLL detected on process! DLL: %s
				sprintf(szRealWarn, __warn, szLowerModuleFilePath.c_str());
				LPFunctions->CloseProcess(szRealWarn, false, "");
			}
		}

	}
	KARMA_MACRO_2
}


/*  ---  */

int CWinapi::BindBaseAPIs() {
	CFunctions lpFuncs;
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic Windows Base APIs binding to struct!");
#endif

	int iErrorCode = 0;
	BasePointers lpBasePointers;
	VTABLE lpTable;

	KARMA_MACRO_1
	if (!lpBasePointers.GetBasePointers(&lpTable)) {
		iErrorCode = 1;
		goto _fail;
	}

	KARMA_MACRO_1
	BetaFunctionTable->GetProcAddress = _GetProcAddress;
	if (!BetaFunctionTable->GetProcAddress) {
		iErrorCode = 2;
		goto _fail;
	}

	KARMA_MACRO_2
	BetaFunctionTable->_GetProcAddress = lpTable.GetProcAddress;
	if (!BetaFunctionTable->_GetProcAddress) {
		iErrorCode = 3;
		goto _fail;
	}

	KARMA_MACRO_1
	BetaFunctionTable->GetModuleHandleA = lpTable.GetModuleHandleA;
	if (!lpTable.GetModuleHandleA) {
		iErrorCode = 4;
		goto _fail;
	}

	KARMA_MACRO_2
	BetaFunctionTable->LoadLibraryA = lpTable.LoadLibraryA;
	if (!lpTable.LoadLibraryA) {
		iErrorCode = 5;
		goto _fail;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic Windows Base APIs binded to struct!");
#endif
	return 1;

	KARMA_MACRO_2

_fail:
	CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'b', 'a', 's', 'e', ' ', 'i', 'n', 'i', 't', ' ', 'f', 'a', 'i', 'l', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Anticheat base init fail! Error code: %d

	char cTmpStr[512];
	sprintf(cTmpStr, __warn, iErrorCode);
	lpFuncs.CloseProcess(cTmpStr, false, "");
	return 0;
}

int CWinapi::BindModules() {
	CFunctions lpFuncs;
	CMain lpMain;
#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic Windows Modules binding to struct!");
#endif

	KARMA_MACRO_2
	int iErrorCode = 0;
	BasePointers lpBasePointers;
	VTABLE lpTable;
	KARMA_MACRO_2

	if (!lpBasePointers.GetBasePointers(&lpTable)) {
		iErrorCode = 1;
		goto _fail;
	}
	/* <-- BASE */
	KARMA_MACRO_1

	HMODULE hTmpBaseModule = GetProcessInstance();
	if (!hTmpBaseModule) {
		iErrorCode = 999;
		goto _fail;
	}
	BetaModuleTable->hBaseModule = hTmpBaseModule;
	/* <-- PROCESS EP */
	KARMA_MACRO_2

	//HMODULE hTmpKernel32 = (HMODULE)lpBasePointers.GetKernel32Handle();
	HMODULE hTmpKernel32 = _GetModuleHandle(XOR("kernel32.dll"));
	if (!hTmpKernel32) {
		iErrorCode = 2;
		goto _fail;
	}
	BetaModuleTable->hKernel32 = hTmpKernel32;
	/* <-- KERNEL32 */
	KARMA_MACRO_1

	HMODULE hTmpKernelbase = 0;
	if (IsWindows7OrGreater()) {
		hTmpKernelbase = _GetModuleHandle(XOR("kernelbase.dll"));
		if (!hTmpKernelbase) {
			iErrorCode = 3;
			goto _fail;
		}
	}
	BetaModuleTable->hKernelbase = hTmpKernelbase;
	/* <-- KERNELBASE */
	KARMA_MACRO_2

	HMODULE hNtdll = _GetModuleHandle(XOR("ntdll.dll"));
	if (!hNtdll) {
		iErrorCode = 4;
		goto _fail;
	}
	BetaModuleTable->hNtdll = hNtdll;
	/* <-- NTDLL */
	KARMA_MACRO_2

	HMODULE hUser32 = _GetModuleHandle(XOR("user32.dll"));
	if (!hUser32) {
		iErrorCode = 5;
		goto _fail;
	}
	BetaModuleTable->hUser32 = hUser32;
	/* <-- USER32 */
	KARMA_MACRO_2

	HMODULE hPython = 0;
	if (LPData->GetGameCode() == METIN2_GAME)
	{
		hPython = _GetPythonHandle();
		if (!hPython) {
#ifndef _DEBUG
			iErrorCode = 6;
			goto _fail;
#endif
		}
	}
	BetaModuleTable->hPython = hPython;
	/* <-- PYTHON */
	KARMA_MACRO_1

	HMODULE hPsapi = _GetModuleHandle(XOR("psapi.dll"));
	if (!hPsapi) {
		iErrorCode = 7;
		goto _fail;
	}
	BetaModuleTable->hPsapi = hPsapi;
	/* <-- PSAPI */
	KARMA_MACRO_2

	HMODULE hDbghelp = _GetModuleHandle(XOR("dbghelp.dll"));
	if (!hDbghelp) {
		iErrorCode = 8;
		goto _fail;
	}
	BetaModuleTable->hDbghelp = hDbghelp;
	/* <-- DBGHELP */
	KARMA_MACRO_1

	HMODULE hAdvapi32 = _GetModuleHandle(XOR("advapi32.dll"));
	if (!hAdvapi32) {
		iErrorCode = 9;
		goto _fail;
	}
	BetaModuleTable->hAdvapi32 = hAdvapi32;
	/* <-- ADVAPI32 */
	KARMA_MACRO_1

	HMODULE hWininet = _GetModuleHandle(XOR("wininet.dll"));
	if (!hWininet) {
		iErrorCode = 10;
		goto _fail;
	}
	BetaModuleTable->hWininet = hWininet;
	/* <-- WININET */
	KARMA_MACRO_2

	HMODULE hWinsta = _GetModuleHandle(XOR("winsta.dll"));
	if (!hWinsta) {
		iErrorCode = 11;
		goto _fail;
	}
	BetaModuleTable->hWinsta = hWinsta;
	/* <-- WINSTA */
	KARMA_MACRO_1

	HMODULE hShlwapi = _GetModuleHandle(XOR("shlwapi.dll"));
	if (!hShlwapi) {
		iErrorCode = 12;
		goto _fail;
	}
	BetaModuleTable->hShlwapi = hShlwapi;
	/* <-- SHLWAPI */
	KARMA_MACRO_2

	HMODULE hShell32 = _GetModuleHandle(XOR("shell32.dll"));
	if (!hShell32) {
		iErrorCode = 13;
		goto _fail;
	}
	BetaModuleTable->hShell32 = hShell32;
	/* <-- SHELL32 */
	KARMA_MACRO_1

	HMODULE hCrypt32 = _GetModuleHandle(XOR("crypt32.dll"));
	if (!hCrypt32) {
		iErrorCode = 14;
		goto _fail;
	}
	BetaModuleTable->hCrypt32 = hCrypt32;
	/* <-- CRYPT32 */
	KARMA_MACRO_2

	HMODULE hWs2_32 = _GetModuleHandle(XOR("ws2_32.dll"));
	if (!hWs2_32) {
		iErrorCode = 15;
		goto _fail;
	}
	BetaModuleTable->hWs2_32 = hWs2_32;
	/* <-- WS2_32 */
	KARMA_MACRO_1

	HMODULE hIphlpapi = _GetModuleHandle(XOR("iphlpapi.dll"));
	if (!hIphlpapi) {
		iErrorCode = 16;
		goto _fail;
	}
	BetaModuleTable->hIphlpapi = hIphlpapi;
	/* <-- IPHLPAPI */
	KARMA_MACRO_2

	HMODULE hMpr = _GetModuleHandle(XOR("mpr.dll"));
	if (!hMpr) {
		iErrorCode = 17;
		goto _fail;
	}
	BetaModuleTable->hMpr = hMpr;
	/* <-- mpr */
	KARMA_MACRO_2

	HMODULE hWintrust = _GetModuleHandle(XOR("wintrust.dll"));
	if (!hWintrust) {
		iErrorCode = 18;
		goto _fail;
	}
	BetaModuleTable->hWintrust = hWintrust;
	/* <-- wintrust */
	KARMA_MACRO_1

	HMODULE hDnsapi = _GetModuleHandle(XOR("DNSAPI.dll"));
	if (!hDnsapi) {
		iErrorCode = 19;
		goto _fail;
	}
	BetaModuleTable->hDnsapi = hDnsapi;
	/* <-- dnsapi */
	KARMA_MACRO_2

	HMODULE hOle32 = _GetModuleHandle(XOR("ole32.dll"));
	if (!hOle32) {
		iErrorCode = 20;
		goto _fail;
	}
	BetaModuleTable->hOle32 = hOle32;
	/* <-- ole32 */
	KARMA_MACRO_1

	HMODULE hGdiPlus = _GetModuleHandle(XOR("gdiplus.dll"));
	if (!hGdiPlus) {
		iErrorCode = 21;
		goto _fail;
	}
	BetaModuleTable->hGdiPlus = hGdiPlus;
	/* <-- Gdiplus */
	KARMA_MACRO_2

	HMODULE hGdi32 = _GetModuleHandle(XOR("gdi32.dll"));
	if (!hGdi32) {
		iErrorCode = 22;
		goto _fail;
	}
	BetaModuleTable->hGdi32 = hGdi32;
	/* <-- Gdi32 */
	KARMA_MACRO_2

	HMODULE hEvtApi = _GetModuleHandle(XOR("wevtapi.dll"));
	if (!hEvtApi) {
		iErrorCode = 23;
		goto _fail;
	}
	BetaModuleTable->hEvtApi = hEvtApi;
	/* <-- Wevtapi */
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic Windows Modules binded to struct!");
#endif
	return 1;

	KARMA_MACRO_1

_fail:
	CHAR __warn[] = { 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'm', 'o', 'd', 'u', 'l', 'e', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'e', 'r', 'r', 'o', 'r', '!', ' ', 'C', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Windows module initilization error! Code: %d

	char cTmpString[1024];
	sprintf(cTmpString, __warn, iErrorCode);
	lpFuncs.CloseProcess(cTmpString, false, "");
	return 0;
}

void CWinapi::BindAPIs() {
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic Windows APIs binding to struct!");
#endif
	KARMA_MACRO_1

	__PROTECTOR_START__("dw+")
	int iErrCode = 0;

	BetaFunctionTable->_GetModuleHandle = (lpGetModuleHandleA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetModuleHandleA"));
	if (!BetaFunctionTable->_GetModuleHandle)
		iErrCode = 1;

	BetaFunctionTable->IsDebuggerPresent = (lpIsDebuggerPresent)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("IsDebuggerPresent"));
	if (!BetaFunctionTable->IsDebuggerPresent)
		iErrCode = 2;

	BetaFunctionTable->AllocConsole = (lpAllocConsole)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("AllocConsole"));
	if (!BetaFunctionTable->AllocConsole)
		iErrCode = 3;

	BetaFunctionTable->lstrcmpA = (lplstrcmpA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("lstrcmpiA"));
	if (!BetaFunctionTable->lstrcmpA)
		iErrCode = 4;

	BetaFunctionTable->GetWindowsDirectoryA = (lpGetWindowsDirectoryA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetWindowsDirectoryA"));
	if (!BetaFunctionTable->GetWindowsDirectoryA)
		iErrCode = 5;

	BetaFunctionTable->Sleep = (lpSleep)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Sleep"));
	if (!BetaFunctionTable->Sleep)
		iErrCode = 6;

	BetaFunctionTable->NtWriteVirtualMemory = (lpNtWriteVirtualMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtWriteVirtualMemory"));
	if (!BetaFunctionTable->NtWriteVirtualMemory)
		iErrCode = 7;

	BetaFunctionTable->WinStationTerminateProcess = (lpWinStationTerminateProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWinsta, XOR("WinStationTerminateProcess"));
	if (!BetaFunctionTable->WinStationTerminateProcess)
		iErrCode = 8;

	BetaFunctionTable->OutputDebugStringA = (lpOutputDebugString)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("OutputDebugStringA"));
	if (!BetaFunctionTable->OutputDebugStringA)
		iErrCode = 9;

	BetaFunctionTable->CreateToolhelp32Snapshot = (lpCreateToolhelp32Snapshot)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateToolhelp32Snapshot"));
	if (!BetaFunctionTable->CreateToolhelp32Snapshot)
		iErrCode = 10;

	BetaFunctionTable->Process32First = (lpProcess32First)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Process32First"));
	if (!BetaFunctionTable->Process32First)
		iErrCode = 11;

	BetaFunctionTable->Process32Next = (lpProcess32Next)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Process32Next"));
	if (!BetaFunctionTable->Process32Next)
		iErrCode = 12;

	BetaFunctionTable->Module32First = (lpModule32First)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Module32First"));
	if (!BetaFunctionTable->Module32First)
		iErrCode = 13;

	BetaFunctionTable->Module32Next = (lpModule32Next)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Module32Next"));
	if (!BetaFunctionTable->Module32Next)
		iErrCode = 14;

	BetaFunctionTable->CharUpperBuffA = (lpCharUpperBuffA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("CharUpperBuffA"));
	if (!BetaFunctionTable->CharUpperBuffA)
		iErrCode = 15;

	BetaFunctionTable->MessageBoxA = (lpMessageBoxA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("MessageBoxA"));
	if (!BetaFunctionTable->MessageBoxA)
		iErrCode = 16;

	BetaFunctionTable->NtQueryInformationProcess = (lpNtQueryInformationProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtQueryInformationProcess"));
	if (!BetaFunctionTable->NtQueryInformationProcess)
		iErrCode = 17;

	BetaFunctionTable->NtQueryInformationThread = (lpNtQueryInformationThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtQueryInformationThread"));
	if (!BetaFunctionTable->NtQueryInformationThread)
		iErrCode = 18;

	BetaFunctionTable->NtQuerySystemInformation = (lpNtQuerySystemInformation)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtQuerySystemInformation"));
	if (!BetaFunctionTable->NtQuerySystemInformation)
		iErrCode = 19;

	BetaFunctionTable->ZwSetInformationThread = (lpZwSetInformationThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("ZwSetInformationThread"));
	if (!BetaFunctionTable->ZwSetInformationThread)
		iErrCode = 20;

	BetaFunctionTable->CheckRemoteDebuggerPresent = (lpCheckRemoteDebuggerPresent)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CheckRemoteDebuggerPresent"));
	if (!BetaFunctionTable->CheckRemoteDebuggerPresent)
		iErrCode = 21;

	BetaFunctionTable->ExitThread = (lpExitThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("ExitThread"));
	if (!BetaFunctionTable->ExitThread)
		iErrCode = 22;

	BetaFunctionTable->GetCurrentProcessId = (lpGetCurrentProcessId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetCurrentProcessId"));
	if (!BetaFunctionTable->GetCurrentProcessId)
		iErrCode = 23;

	BetaFunctionTable->VirtualFree = (lpVirtualFree)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualFree"));
	if (!BetaFunctionTable->VirtualFree)
		iErrCode = 24;

	BetaFunctionTable->VirtualProtect = (lpVirtualProtect)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualProtect"));
	if (!BetaFunctionTable->VirtualProtect)
		iErrCode = 25;

	BetaFunctionTable->CreateFileA = (lpCreateFile)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateFileA"));
	if (!BetaFunctionTable->CreateFileA)
		iErrCode = 27;

	BetaFunctionTable->SetUnhandledExceptionFilter = (lpSetUnhandledExceptionFilter)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetUnhandledExceptionFilter"));
	if (!BetaFunctionTable->SetUnhandledExceptionFilter)
		iErrCode = 28;

	BetaFunctionTable->CreateThread = (lpCreateThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateThread"));
	if (!BetaFunctionTable->CreateThread)
		iErrCode = 29;

	BetaFunctionTable->GetVersionExA = (lpGetVersionEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetVersionExA"));
	if (!BetaFunctionTable->GetVersionExA)
		iErrCode = 30;

	BetaFunctionTable->WriteProcessMemory = (lpWriteProcessMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("WriteProcessMemory"));
	if (!BetaFunctionTable->WriteProcessMemory)
		iErrCode = 31;

	BetaFunctionTable->GetAdaptersInfo = (lpGetAdaptersInfo)BetaFunctionTable->GetProcAddress(BetaModuleTable->hIphlpapi, XOR("GetAdaptersInfo"));
	if (!BetaFunctionTable->GetAdaptersInfo)
		iErrCode = 32;

	BetaFunctionTable->GetComputerNameA = (lpGetComputerName)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetComputerNameA"));
	if (!BetaFunctionTable->GetComputerNameA)
		iErrCode = 33;

	BetaFunctionTable->GetVolumeInformationA = (lpGetVolumeInformation)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetVolumeInformationA"));
	if (!BetaFunctionTable->GetVolumeInformationA)
		iErrCode = 34;

	BetaFunctionTable->GetDriveTypeA = (lpGetDriveType)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetDriveTypeA"));
	if (!BetaFunctionTable->GetDriveTypeA)
		iErrCode = 35;

	BetaFunctionTable->LocalAlloc = (lpLocalAlloc)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LocalAlloc"));
	if (!BetaFunctionTable->LocalAlloc)
		iErrCode = 36;

	BetaFunctionTable->GetModuleFileNameA = (lpGetModuleFileName)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetModuleFileNameA"));
	if (!BetaFunctionTable->GetModuleFileNameA)
		iErrCode = 37;

	BetaFunctionTable->GetThreadContext = (lpGetThreadContext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetThreadContext"));
	if (!BetaFunctionTable->GetThreadContext)
		iErrCode = 38;

	BetaFunctionTable->WaitForSingleObject = (lpWaitForSingleObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("WaitForSingleObject"));
	if (!BetaFunctionTable->WaitForSingleObject)
		iErrCode = 39;

	BetaFunctionTable->ResumeThread = (lpResumeThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("ResumeThread"));
	if (!BetaFunctionTable->ResumeThread)
		iErrCode = 40;

	BetaFunctionTable->CloseHandle = (lpCloseHandle)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CloseHandle"));
	if (!BetaFunctionTable->CloseHandle)
		iErrCode = 41;

	BetaFunctionTable->GetDeviceDriverBaseNameA = (lpGetDeviceDriverBaseName)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetDeviceDriverBaseNameA"));
	if (!BetaFunctionTable->GetDeviceDriverBaseNameA)
		iErrCode = 42;

	BetaFunctionTable->EnumDeviceDrivers = (lpEnumDeviceDrivers)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("EnumDeviceDrivers"));
	if (!BetaFunctionTable->EnumDeviceDrivers)
		iErrCode = 43;

	BetaFunctionTable->GetTickCount = (lpGetTickCount)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetTickCount"));
	if (!BetaFunctionTable->GetTickCount)
		iErrCode = 44;

	BetaFunctionTable->EnumWindows = (lpEnumWindows)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("EnumWindows"));
	if (!BetaFunctionTable->EnumWindows)
		iErrCode = 45;

	BetaFunctionTable->GetLastError = (lpGetLastError)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetLastError"));
	if (!BetaFunctionTable->GetLastError)
		iErrCode = 46;

	BetaFunctionTable->GetUserNameA = (lpGetUserName)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("GetUserNameA"));
	if (!BetaFunctionTable->GetUserNameA)
		iErrCode = 47;

	BetaFunctionTable->ShellExecute = (lpShellExecute)BetaFunctionTable->GetProcAddress(BetaModuleTable->hShell32, XOR("ShellExecuteA"));
	if (!BetaFunctionTable->ShellExecute)
		iErrCode = 48;

	BetaFunctionTable->GetModuleBaseNameA = (lpGetModuleBaseNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetModuleBaseNameA"));
	if (!BetaFunctionTable->GetModuleBaseNameA)
		iErrCode = 49;

	BetaFunctionTable->SetLastError = (lpSetLastError)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetLastError"));
	if (!BetaFunctionTable->SetLastError)
		iErrCode = 50;

	BetaFunctionTable->CallNextHookEx = (lpCallNextHookEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("CallNextHookEx"));
	if (!BetaFunctionTable->CallNextHookEx)
		iErrCode = 51;

	BetaFunctionTable->SetWindowsHookExA = (lpSetWindowsHookEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("SetWindowsHookExA"));
	if (!BetaFunctionTable->SetWindowsHookExA)
		iErrCode = 52;

	BetaFunctionTable->NtResumeProcess = (lpNtResumeProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtResumeProcess"));
	if (!BetaFunctionTable->NtResumeProcess)
		iErrCode = 53;

	BetaFunctionTable->AddVectoredExceptionHandler = (lpAddVectoredExceptionHandler)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("AddVectoredExceptionHandler"));
	if (!BetaFunctionTable->AddVectoredExceptionHandler)
		iErrCode = 54;

	BetaFunctionTable->VirtualQuery = (lpVirtualQuery)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualQuery"));
	if (!BetaFunctionTable->VirtualQuery)
		iErrCode = 55;

	BetaFunctionTable->MessageBoxTimeout = (lpMessageBoxTimeout)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("MessageBoxTimeoutA"));
	if (!BetaFunctionTable->MessageBoxTimeout)
		iErrCode = 56;

	BetaFunctionTable->NtClose = (lpNtClose)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtClose"));
	if (!BetaFunctionTable->NtClose)
		iErrCode = 57;

	BetaFunctionTable->NtSetInformationDebugObject = (lpNtSetInformationDebugObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtSetInformationDebugObject"));
	if (!BetaFunctionTable->NtSetInformationDebugObject)
		iErrCode = 58;

	BetaFunctionTable->NtRemoveProcessDebug = (lpNtRemoveProcessDebug)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtRemoveProcessDebug"));
	if (!BetaFunctionTable->NtRemoveProcessDebug)
		iErrCode = 59;

	BetaFunctionTable->FormatMessageA = (lpFormatMessage)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FormatMessageA"));
	if (!BetaFunctionTable->FormatMessageA)
		iErrCode = 60;

	BetaFunctionTable->MultiByteToWideChar = (lpMultiByteToWideChar)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("MultiByteToWideChar"));
	if (!BetaFunctionTable->MultiByteToWideChar)
		iErrCode = 61;

	BetaFunctionTable->WideCharToMultiByte = (lpWideCharToMultiByte)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("WideCharToMultiByte"));
	if (!BetaFunctionTable->WideCharToMultiByte)
		iErrCode = 62;

	BetaFunctionTable->CreateProcessA = (lpCreateProcessA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateProcessA"));
	if (!BetaFunctionTable->CreateProcessA)
		iErrCode = 63;

	BetaFunctionTable->GetStartupInfoA = (lpGetStartupInfoA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetStartupInfoA"));
	if (!BetaFunctionTable->GetStartupInfoA)
		iErrCode = 64;

	BetaFunctionTable->GetExitCodeProcess = (lpGetExitCodeProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetExitCodeProcess"));
	if (!BetaFunctionTable->GetExitCodeProcess)
		iErrCode = 65;

	BetaFunctionTable->PostQuitMessage = (lpPostQuitMessage)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("PostQuitMessage"));
	if (!BetaFunctionTable->PostQuitMessage)
		iErrCode = 66;

	BetaFunctionTable->OpenProcess = (lpOpenProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("OpenProcess"));
	if (!BetaFunctionTable->OpenProcess)
		iErrCode = 67;

	BetaFunctionTable->GetCurrentThreadId = (lpGetCurrentThreadId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetCurrentThreadId"));
	if (!BetaFunctionTable->GetCurrentThreadId)
		iErrCode = 68;

	BetaFunctionTable->GetModuleInformation = (lpGetModuleInformation)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetModuleInformation"));
	if (!BetaFunctionTable->GetModuleInformation)
		iErrCode = 69;

	BetaFunctionTable->GetMappedFileNameA = (lpGetMappedfilename)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetMappedFileNameA"));
	if (!BetaFunctionTable->GetMappedFileNameA)
		iErrCode = 70;

	BetaFunctionTable->GetModuleHandleExW = (lpGetModuleHandleExW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetModuleHandleExW"));
	if (!BetaFunctionTable->GetModuleHandleExW)
		iErrCode = 71;

	BetaFunctionTable->FreeLibrary = (lpFreeLibrary)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FreeLibrary"));
	if (!BetaFunctionTable->FreeLibrary)
		iErrCode = 72;

	BetaFunctionTable->GetModuleHandleW = (lpGetModuleHandleW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetModuleHandleW"));
	if (!BetaFunctionTable->GetModuleHandleW)
		iErrCode = 73;

	BetaFunctionTable->CallWindowProcA = (lpCallWindowProcA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("CallWindowProcA"));
	if (!BetaFunctionTable->CallWindowProcA)
		iErrCode = 75;

	BetaFunctionTable->FindWindowExA = (lpFindWindowExA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("FindWindowExA"));
	if (!BetaFunctionTable->FindWindowExA)
		iErrCode = 76;

	BetaFunctionTable->GetWindowThreadProcessId = (lpGetWindowThreadProcessId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindowThreadProcessId"));
	if (!BetaFunctionTable->GetWindowThreadProcessId)
		iErrCode = 77;

	BetaFunctionTable->IsWindowVisible = (lpIsWindowVisible)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("IsWindowVisible"));
	if (!BetaFunctionTable->IsWindowVisible)
		iErrCode = 78;

	BetaFunctionTable->GetClassNameA = (lpGetClassNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetClassNameA"));
	if (!BetaFunctionTable->GetClassNameA)
		iErrCode = 79;

	BetaFunctionTable->GetWindowTextA = (lpGetWindowTextA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindowTextA"));
	if (!BetaFunctionTable->GetWindowTextA)
		iErrCode = 80;

	BetaFunctionTable->SetWindowLongA = (lpSetWindowLongA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("SetWindowLongA"));
	if (!BetaFunctionTable->SetWindowLongA)
		iErrCode = 81;
	
	BetaFunctionTable->Thread32First = (lpThread32First)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Thread32First"));
	if (!BetaFunctionTable->Thread32First)
		iErrCode = 82;

	BetaFunctionTable->Thread32Next = (lpThread32Next)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Thread32Next"));
	if (!BetaFunctionTable->Thread32Next)
		iErrCode = 83;

	BetaFunctionTable->OpenThread = (lpOpenThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("OpenThread"));
	if (!BetaFunctionTable->OpenThread)
		iErrCode = 84;

	BetaFunctionTable->NtDuplicateObject = (lpNtDuplicateObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtDuplicateObject"));
	if (!BetaFunctionTable->NtDuplicateObject)
		iErrCode = 85;

	BetaFunctionTable->NtQueryObject = (lpNtQueryObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtQueryObject"));
	if (!BetaFunctionTable->NtQueryObject)
		iErrCode = 86;

	BetaFunctionTable->GetFileSize = (lpGetFileSize)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetFileSize"));
	if (!BetaFunctionTable->GetFileSize)
		iErrCode = 87;

	BetaFunctionTable->FindFirstFileA = (lpFindFirstFileA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FindFirstFileA"));
	if (!BetaFunctionTable->FindFirstFileA)
		iErrCode = 88;

	BetaFunctionTable->FindNextFileA = (lpFindNextFileA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FindNextFileA"));
	if (!BetaFunctionTable->FindNextFileA)
		iErrCode = 89;

	BetaFunctionTable->SetFileAttributesA = (lpSetFileAttributesA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetFileAttributesA"));
	if (!BetaFunctionTable->SetFileAttributesA)
		iErrCode = 90;

	BetaFunctionTable->RemoveDirectoryA = (lpRemoveDirectoryA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("RemoveDirectoryA"));
	if (!BetaFunctionTable->RemoveDirectoryA)
		iErrCode = 91;

	BetaFunctionTable->DeleteFileA = (lpDeleteFileA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("DeleteFileA"));
	if (!BetaFunctionTable->DeleteFileA)
		iErrCode = 92;

	BetaFunctionTable->GetFileAttributesA = (lpGetFileAttributesA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetFileAttributesA"));
	if (!BetaFunctionTable->GetFileAttributesA)
		iErrCode = 93;

	BetaFunctionTable->FindClose = (lpFindClose)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FindClose"));
	if (!BetaFunctionTable->FindClose)
		iErrCode = 94;

	BetaFunctionTable->LookupPrivilegeValueA = (lpLookupPrivilegeValueA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("LookupPrivilegeValueA"));
	if (!BetaFunctionTable->LookupPrivilegeValueA)
		iErrCode = 95;

	BetaFunctionTable->AdjustTokenPrivileges = (lpAdjustTokenPrivileges)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("AdjustTokenPrivileges"));
	if (!BetaFunctionTable->AdjustTokenPrivileges)
		iErrCode = 96;

	BetaFunctionTable->OpenProcessToken = (lpOpenProcessToken)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("OpenProcessToken"));
	if (!BetaFunctionTable->OpenProcessToken)
		iErrCode = 97;

	BetaFunctionTable->NtSetDebugFilterState = (lpNtSetDebugFilterState)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtSetDebugFilterState"));
	if (!BetaFunctionTable->NtSetDebugFilterState)
		iErrCode = 98;

	//	BetaFunctionTable->ZwQuerySystemInformation = (lpZwQuerySystemInformation)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("ZwQuerySystemInformation"));
	//	if (!BetaFunctionTable->ZwQuerySystemInformation)
	// 		iErrCode = 99;

	BetaFunctionTable->WNetGetProviderNameA = (lpWNetGetProviderNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hMpr, XOR("WNetGetProviderNameA"));
	if (!BetaFunctionTable->WNetGetProviderNameA)
		iErrCode = 100;

	BetaFunctionTable->NtTerminateProcess = (lpNtTerminateProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtTerminateProcess"));
	if (!BetaFunctionTable->NtTerminateProcess)
		iErrCode = 101;

	BetaFunctionTable->GetSystemInfo = (lpGetSystemInfo)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetSystemInfo"));
	if (!BetaFunctionTable->GetSystemInfo)
		iErrCode = 102;

	BetaFunctionTable->CreateFileMappingA = (lpCreateFileMappingA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateFileMappingA"));
	if (!BetaFunctionTable->CreateFileMappingA)
		iErrCode = 103;

	BetaFunctionTable->MapViewOfFile = (lpMapViewOfFile)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("MapViewOfFile"));
	if (!BetaFunctionTable->MapViewOfFile)
		iErrCode = 104;

	BetaFunctionTable->UnmapViewOfFile = (lpUnmapViewOfFile)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("UnmapViewOfFile"));
	if (!BetaFunctionTable->UnmapViewOfFile)
		iErrCode = 105;

	BetaFunctionTable->ReadProcessMemory = (lpReadProcessMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("ReadProcessMemory"));
	if (!BetaFunctionTable->ReadProcessMemory)
		iErrCode = 106;

	BetaFunctionTable->AllocateAndInitializeSid = (lpAllocateAndInitializeSid)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("AllocateAndInitializeSid"));
	if (!BetaFunctionTable->AllocateAndInitializeSid)
		iErrCode = 107;

	BetaFunctionTable->GetTokenInformation = (lpGetTokenInformation)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("GetTokenInformation"));
	if (!BetaFunctionTable->GetTokenInformation)
		iErrCode = 108;

	BetaFunctionTable->GlobalAlloc = (lpGlobalAlloc)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GlobalAlloc"));
	if (!BetaFunctionTable->GlobalAlloc)
		iErrCode = 109;

	BetaFunctionTable->InitializeAcl = (lpInitializeAcl)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("InitializeAcl"));
	if (!BetaFunctionTable->InitializeAcl)
		iErrCode = 110;

	BetaFunctionTable->AddAccessDeniedAce = (lpAddAccessDeniedAce)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("AddAccessDeniedAce"));
	if (!BetaFunctionTable->AddAccessDeniedAce)
		iErrCode = 111;

	BetaFunctionTable->AddAccessAllowedAce = (lpAddAccessAllowedAce)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("AddAccessAllowedAce"));
	if (!BetaFunctionTable->AddAccessAllowedAce)
		iErrCode = 112;

	BetaFunctionTable->SetSecurityInfo = (lpSetSecurityInfo)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("SetSecurityInfo"));
	if (!BetaFunctionTable->SetSecurityInfo)
		iErrCode = 113;

	BetaFunctionTable->FreeSid = (lpFreeSid)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("FreeSid"));
	if (!BetaFunctionTable->FreeSid)
		iErrCode = 114;

	BetaFunctionTable->GetForegroundWindow = (lpGetForegroundWindow)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetForegroundWindow"));
	if (!BetaFunctionTable->GetForegroundWindow)
		iErrCode = 116;

	BetaFunctionTable->TerminateThread = (lpTerminateThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("TerminateThread"));
	if (!BetaFunctionTable->TerminateThread)
		iErrCode = 117;

	BetaFunctionTable->SendMessageA = (lpSendMessageA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("SendMessageA"));
	if (!BetaFunctionTable->SendMessageA)
		iErrCode = 118;

	BetaFunctionTable->SetThreadContext = (lpSetThreadContext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetThreadContext"));
	if (!BetaFunctionTable->SetThreadContext)
		iErrCode = 119;

	BetaFunctionTable->SuspendThread = (lpSuspendThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SuspendThread"));
	if (!BetaFunctionTable->SuspendThread)
		iErrCode = 120;

	BetaFunctionTable->BlockInput = (lpBlockInput)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("BlockInput"));
	if (!BetaFunctionTable->BlockInput)
		iErrCode = 122;

	BetaFunctionTable->GetWindowModuleFileNameA = (lpGetWindowModuleFileNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindowModuleFileNameA"));
	if (!BetaFunctionTable->GetWindowModuleFileNameA)
		iErrCode = 123;

	BetaFunctionTable->RemoveVectoredExceptionHandler = (lpRemoveVectoredExceptionHandler)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("RemoveVectoredExceptionHandler"));
	if (!BetaFunctionTable->RemoveVectoredExceptionHandler)
		iErrCode = 124;

	BetaFunctionTable->NtQueryVirtualMemory = (lpNtQueryVirtualMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtQueryVirtualMemory"));
	if (!BetaFunctionTable->NtQueryVirtualMemory)
		iErrCode = 125;

	BetaFunctionTable->PeekMessageA = (lpPeekMessageA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("PeekMessageA"));
	if (!BetaFunctionTable->PeekMessageA)
		iErrCode = 126;

	BetaFunctionTable->GetMessageA = (lpGetMessageA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetMessageA"));
	if (!BetaFunctionTable->GetMessageA)
		iErrCode = 127;

	BetaFunctionTable->TranslateMessage = (lpTranslateMessage)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("TranslateMessage"));
	if (!BetaFunctionTable->TranslateMessage)
		iErrCode = 128;

	BetaFunctionTable->DispatchMessageA = (lpDispatchMessageA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("DispatchMessageA"));
	if (!BetaFunctionTable->DispatchMessageA)
		iErrCode = 129;

	BetaFunctionTable->UnhookWindowsHookEx = (lpUnhookWindowsHookEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("UnhookWindowsHookEx"));
	if (!BetaFunctionTable->UnhookWindowsHookEx)
		iErrCode = 130;
	
	BetaFunctionTable->SHGetSpecialFolderPathA = (lpSHGetSpecialFolderPathA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hShell32, XOR("SHGetSpecialFolderPathA"));
	if (!BetaFunctionTable->SHGetSpecialFolderPathA)
		iErrCode = 131;

	BetaFunctionTable->FreeLibraryAndExitThread = (lpFreeLibraryAndExitThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FreeLibraryAndExitThread"));
	if (!BetaFunctionTable->FreeLibraryAndExitThread)
		iErrCode = 132;

	BetaFunctionTable->NtUnmapViewOfSection = (lpNtUnmapViewOfSection)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtUnmapViewOfSection"));
	if (!BetaFunctionTable->NtUnmapViewOfSection)
		iErrCode = 133;

	BetaFunctionTable->EndTask = (lpEndTask)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("EndTask"));
	if (!BetaFunctionTable->EndTask)
		iErrCode = 134;

	BetaFunctionTable->VirtualAlloc = (lpVirtualAlloc)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualAlloc"));
	if (!BetaFunctionTable->VirtualAlloc)
		iErrCode = 135;

	BetaFunctionTable->DebugBreak = (lpDebugBreak)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("DebugBreak"));
	if (!BetaFunctionTable->DebugBreak)
		iErrCode = 136;

	BetaFunctionTable->GetModuleHandleExA = (lpGetModuleHandleExA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetModuleHandleExA"));
	if (!BetaFunctionTable->GetModuleHandleExA)
		iErrCode = 137;

	BetaFunctionTable->ReadFile = (lpReadFile)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("ReadFile"));
	if (!BetaFunctionTable->ReadFile)
		iErrCode = 138;

	BetaFunctionTable->NtSetInformationProcess = (lpNtSetInformationProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtSetInformationProcess"));
	if (!BetaFunctionTable->NtSetInformationProcess)
		iErrCode = 140;

	BetaFunctionTable->NtAllocateVirtualMemory = (lpNtAllocateVirtualMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtAllocateVirtualMemory"));
	if (!BetaFunctionTable->NtAllocateVirtualMemory)
		iErrCode = 141;

	BetaFunctionTable->GetShellWindow = (lpGetShellWindow)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetShellWindow"));
	if (!BetaFunctionTable->GetShellWindow)
		iErrCode = 142;

	BetaFunctionTable->CreateFileW = (lpCreateFileW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateFileW"));
	if (!BetaFunctionTable->CreateFileW)
		iErrCode = 143;

	BetaFunctionTable->CryptCATAdminCalcHashFromFileHandle = (lpCryptCATAdminCalcHashFromFileHandle)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWintrust, XOR("CryptCATAdminCalcHashFromFileHandle"));
	if (!BetaFunctionTable->CryptCATAdminCalcHashFromFileHandle)
		iErrCode = 144;

	BetaFunctionTable->CryptCATAdminAcquireContext = (lpCryptCATAdminAcquireContext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWintrust, XOR("CryptCATAdminAcquireContext"));
	if (!BetaFunctionTable->CryptCATAdminAcquireContext)
		iErrCode = 145;

	BetaFunctionTable->CryptCATAdminEnumCatalogFromHash = (lpCryptCATAdminEnumCatalogFromHash)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWintrust, XOR("CryptCATAdminEnumCatalogFromHash"));
	if (!BetaFunctionTable->CryptCATAdminEnumCatalogFromHash)
		iErrCode = 146;

	BetaFunctionTable->CryptCATAdminReleaseContext = (lpCryptCATAdminReleaseContext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWintrust, XOR("CryptCATAdminReleaseContext"));
	if (!BetaFunctionTable->CryptCATAdminReleaseContext)
		iErrCode = 147;

	BetaFunctionTable->CryptCATCatalogInfoFromContext = (lpCryptCATCatalogInfoFromContext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWintrust, XOR("CryptCATCatalogInfoFromContext"));
	if (!BetaFunctionTable->CryptCATCatalogInfoFromContext)
		iErrCode = 148;

	BetaFunctionTable->EnumProcessModules = (lpEnumProcessModules)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("EnumProcessModules"));
	if (!BetaFunctionTable->EnumProcessModules)
		iErrCode = 149;

	BetaFunctionTable->GetModuleFileNameExA = (lpGetModuleFileNameExA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetModuleFileNameExA"));
	if (!BetaFunctionTable->GetModuleFileNameExA)
		iErrCode = 150;

	BetaFunctionTable->RtlGetVersion = (lpRtlGetVersion)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlGetVersion"));
	if (!BetaFunctionTable->RtlGetVersion)
		iErrCode = 151;

	BetaFunctionTable->VerifyVersionInfoW = (lpVerifyVersionInfoW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VerifyVersionInfoW"));
	if (!BetaFunctionTable->VerifyVersionInfoW)
		iErrCode = 152;

	BetaFunctionTable->VerSetConditionMask = (lpVerSetConditionMask)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VerSetConditionMask"));
	if (!BetaFunctionTable->VerSetConditionMask)
		iErrCode = 153;

	BetaFunctionTable->MiniDumpWriteDump = (lpMiniDumpWriteDump)BetaFunctionTable->GetProcAddress(BetaModuleTable->hDbghelp, XOR("MiniDumpWriteDump"));
	if (!BetaFunctionTable->MiniDumpWriteDump)
		iErrCode = 154;

	BetaFunctionTable->GetWindowLongA = (lpGetWindowLongA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindowLongA"));
	if (!BetaFunctionTable->GetWindowLongA)
		iErrCode = 156;

	BetaFunctionTable->InitializeCriticalSection = (lpInitializeCriticalSection)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("InitializeCriticalSection"));
	if (!BetaFunctionTable->InitializeCriticalSection)
		iErrCode = 157;

	BetaFunctionTable->EnterCriticalSection = (lpEnterCriticalSection)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("EnterCriticalSection"));
	if (!BetaFunctionTable->EnterCriticalSection)
		iErrCode = 158;

	BetaFunctionTable->LeaveCriticalSection = (lpLeaveCriticalSection)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LeaveCriticalSection"));
	if (!BetaFunctionTable->LeaveCriticalSection)
		iErrCode = 159;

	BetaFunctionTable->DeleteCriticalSection = (lpDeleteCriticalSection)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("DeleteCriticalSection"));
	if (!BetaFunctionTable->DeleteCriticalSection)
		iErrCode = 160;

	BetaFunctionTable->GetProcessImageFileNameA = (lpGetProcessImageFileNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetProcessImageFileNameA"));
	if (!BetaFunctionTable->GetProcessImageFileNameA)
		iErrCode = 162;

	BetaFunctionTable->GetLogicalDriveStringsA = (lpGetLogicalDriveStringsA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetLogicalDriveStringsA"));
	if (!BetaFunctionTable->GetLogicalDriveStringsA)
		iErrCode = 163;

	BetaFunctionTable->GetSystemMetrics = (lpGetSystemMetrics)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetSystemMetrics"));
	if (!BetaFunctionTable->GetSystemMetrics)
		iErrCode = 164;
	
	BetaFunctionTable->RtlAdjustPrivilege = (lpRtlAdjustPrivilege)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlAdjustPrivilege"));
	if (!BetaFunctionTable->RtlAdjustPrivilege)
		iErrCode = 165;

	BetaFunctionTable->EnumProcesses = (lpEnumProcesses)BetaFunctionTable->_GetProcAddress(BetaModuleTable->hKernel32, XOR("EnumProcesses"));
	if (!BetaFunctionTable->EnumProcesses) {

		BetaFunctionTable->EnumProcesses = (lpEnumProcesses)BetaFunctionTable->_GetProcAddress(BetaModuleTable->hPsapi, XOR("EnumProcesses"));
		if (!BetaFunctionTable->EnumProcesses)
			iErrCode = 166;
	}

	BetaFunctionTable->OpenThreadToken = (lpOpenThreadToken)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("OpenThreadToken"));
	if (!BetaFunctionTable->OpenThreadToken)
		iErrCode = 167;

	BetaFunctionTable->GetModuleFileNameW = (lpGetModuleFileNameW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetModuleFileNameW"));
	if (!BetaFunctionTable->GetModuleFileNameW)
		iErrCode = 168;

	BetaFunctionTable->GetDeviceDriverFileNameA = (lpGetDeviceDriverFileNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("GetDeviceDriverFileNameA"));
	if (!BetaFunctionTable->GetDeviceDriverFileNameA)
		iErrCode = 169;

	BetaFunctionTable->OpenSCManagerA = (lpOpenSCManagerA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("OpenSCManagerA"));
	if (!BetaFunctionTable->OpenSCManagerA)
		iErrCode = 170;

	BetaFunctionTable->EnumServicesStatusA = (lpEnumServicesStatusA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("EnumServicesStatusA"));
	if (!BetaFunctionTable->EnumServicesStatusA)
		iErrCode = 171;

	BetaFunctionTable->CloseServiceHandle = (lpCloseServiceHandle)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("CloseServiceHandle"));
	if (!BetaFunctionTable->CloseServiceHandle)
		iErrCode = 172;

	BetaFunctionTable->Toolhelp32ReadProcessMemory = (lpToolhelp32ReadProcessMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("Toolhelp32ReadProcessMemory"));
	if (!BetaFunctionTable->Toolhelp32ReadProcessMemory)
		iErrCode = 173;

	BetaFunctionTable->OpenEventA = (lpOpenEventA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("OpenEventA"));
	if (!BetaFunctionTable->OpenEventA)
		iErrCode = 174;

	BetaFunctionTable->LocalFree = (lpLocalFree)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LocalFree"));
	if (!BetaFunctionTable->LocalFree)
		iErrCode = 175;

	BetaFunctionTable->SetEntriesInAclA = (lpSetEntriesInAclA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("SetEntriesInAclA"));
	if (!BetaFunctionTable->SetEntriesInAclA)
		iErrCode = 176;

	BetaFunctionTable->SetPriorityClass = (lpSetPriorityClass)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetPriorityClass"));
	if (!BetaFunctionTable->SetPriorityClass)
		iErrCode = 177;

	BetaFunctionTable->BuildExplicitAccessWithNameA = (lpBuildExplicitAccessWithNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("BuildExplicitAccessWithNameA"));
	if (!BetaFunctionTable->BuildExplicitAccessWithNameA)
		iErrCode = 178;	

	BetaFunctionTable->SetKernelObjectSecurity = (lpSetKernelObjectSecurity)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("SetKernelObjectSecurity"));
	if (!BetaFunctionTable->SetKernelObjectSecurity)
		iErrCode = 179;

	BetaFunctionTable->ConvertStringSecurityDescriptorToSecurityDescriptorA = (lpConvertStringSecurityDescriptorToSecurityDescriptorA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("ConvertStringSecurityDescriptorToSecurityDescriptorA"));
	if (!BetaFunctionTable->ConvertStringSecurityDescriptorToSecurityDescriptorA)
		iErrCode = 180;

	BetaFunctionTable->CoInitialize = (lpCoInitialize)BetaFunctionTable->GetProcAddress(BetaModuleTable->hOle32, XOR("CoInitialize"));
	if (!BetaFunctionTable->CoInitialize)
		iErrCode = 181;

	BetaFunctionTable->CoUninitialize = (lpCoUninitialize)BetaFunctionTable->GetProcAddress(BetaModuleTable->hOle32, XOR("CoUninitialize"));
	if (!BetaFunctionTable->CoUninitialize)
		iErrCode = 182;

	BetaFunctionTable->InternetOpenA = (lpInternetOpenA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetOpenA"));
	if (!BetaFunctionTable->InternetOpenA)
		iErrCode = 183;

	BetaFunctionTable->InternetOpenUrlA = (lpInternetOpenUrlA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetOpenUrlA"));
	if (!BetaFunctionTable->InternetOpenUrlA)
		iErrCode = 184;

	BetaFunctionTable->HttpQueryInfoA = (lpHttpQueryInfoA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("HttpQueryInfoA"));
	if (!BetaFunctionTable->HttpQueryInfoA)
		iErrCode = 185;

	BetaFunctionTable->InternetCloseHandle = (lpInternetCloseHandle)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetCloseHandle"));
	if (!BetaFunctionTable->InternetCloseHandle)
		iErrCode = 186;

	BetaFunctionTable->InternetReadFile = (lpInternetReadFile)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetReadFile"));
	if (!BetaFunctionTable->InternetReadFile)
		iErrCode = 187;

	BetaFunctionTable->WSAStartup = (lpWSAStartup)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWs2_32, XOR("WSAStartup"));
	if (!BetaFunctionTable->WSAStartup)
		iErrCode = 188;

	BetaFunctionTable->gethostbyname = (lpgethostbyname)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWs2_32, XOR("gethostbyname"));
	if (!BetaFunctionTable->gethostbyname)
		iErrCode = 189;

	BetaFunctionTable->WSACleanup = (lpWSACleanup)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWs2_32, XOR("WSACleanup"));
	if (!BetaFunctionTable->WSACleanup)
		iErrCode = 190;

	BetaFunctionTable->WSAGetLastError = (lpWSAGetLastError)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWs2_32, XOR("WSAGetLastError"));
	if (!BetaFunctionTable->WSAGetLastError)
		iErrCode = 191;

	BetaFunctionTable->inet_ntoa = (lpinet_ntoa)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWs2_32, XOR("inet_ntoa"));
	if (!BetaFunctionTable->inet_ntoa)
		iErrCode = 192;

	BetaFunctionTable->GetFileTime = (lpGetFileTime)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetFileTime"));
	if (!BetaFunctionTable->GetFileTime)
		iErrCode = 193;

	BetaFunctionTable->SetHandleInformation = (lpSetHandleInformation)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetHandleInformation"));
	if (!BetaFunctionTable->SetHandleInformation)
		iErrCode = 194;

	BetaFunctionTable->CreateMutexA = (lpCreateMutexA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateMutexA"));
	if (!BetaFunctionTable->CreateMutexA)
		iErrCode = 195;

	BetaFunctionTable->SetErrorMode = (lpSetErrorMode)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetErrorMode"));
	if (!BetaFunctionTable->SetErrorMode)
		iErrCode = 196;

	BetaFunctionTable->GetWindowRect = (lpGetWindowRect)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindowRect"));
	if (!BetaFunctionTable->GetWindowRect)
		iErrCode = 197;

	BetaFunctionTable->GetDesktopWindow = (lpGetDesktopWindow)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetDesktopWindow"));
	if (!BetaFunctionTable->GetDesktopWindow)
		iErrCode = 198;

	BetaFunctionTable->GetDC = (lpGetDC)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetDC"));
	if (!BetaFunctionTable->GetDC)
		iErrCode = 199;

	BetaFunctionTable->CreateCompatibleDC = (lpCreateCompatibleDC)BetaFunctionTable->GetProcAddress(BetaModuleTable->hGdi32, XOR("CreateCompatibleDC"));
	if (!BetaFunctionTable->CreateCompatibleDC)
		iErrCode = 200;

	BetaFunctionTable->BitBlt = (lpBitBlt)BetaFunctionTable->GetProcAddress(BetaModuleTable->hGdi32, XOR("BitBlt"));
	if (!BetaFunctionTable->BitBlt)
		iErrCode = 201;

	BetaFunctionTable->CreateCompatibleBitmap = (lpCreateCompatibleBitmap)BetaFunctionTable->GetProcAddress(BetaModuleTable->hGdi32, XOR("CreateCompatibleBitmap"));
	if (!BetaFunctionTable->CreateCompatibleBitmap)
		iErrCode = 202;

	BetaFunctionTable->SelectObject = (lpSelectObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hGdi32, XOR("SelectObject"));
	if (!BetaFunctionTable->SelectObject)
		iErrCode = 203;

	BetaFunctionTable->IsWow64Process = (lpIsWow64Process)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("IsWow64Process"));
	if (!BetaFunctionTable->IsWow64Process)
		iErrCode = 204;

	BetaFunctionTable->CheckTokenMembership = (lpCheckTokenMembership)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("CheckTokenMembership"));
	if (!BetaFunctionTable->CheckTokenMembership)
		iErrCode = 205;

	BetaFunctionTable->GetTempFileNameA = (lpGetTempFileNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetTempFileNameA"));
	if (!BetaFunctionTable->GetTempFileNameA)
		iErrCode = 206;

	BetaFunctionTable->GetTempPathA = (lpGetTempPathA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetTempPathA"));
	if (!BetaFunctionTable->GetTempPathA)
		iErrCode = 207;

	BetaFunctionTable->QueryWorkingSet = (lpQueryWorkingSet)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("QueryWorkingSet"));
	if (!BetaFunctionTable->QueryWorkingSet)
		iErrCode = 208;

	BetaFunctionTable->RtlImageNtHeader = (lpRtlImageNtHeader)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlImageNtHeader"));
	if (!BetaFunctionTable->RtlImageNtHeader)
		iErrCode = 209;

	BetaFunctionTable->ZwOpenDirectoryObject = (lpZwOpenDirectoryObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("ZwOpenDirectoryObject"));
	if (!BetaFunctionTable->ZwOpenDirectoryObject)
		iErrCode = 210;

	BetaFunctionTable->ZwClose = (lpZwClose)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("ZwClose"));
	if (!BetaFunctionTable->ZwClose)
		iErrCode = 211;

	BetaFunctionTable->ZwQueryDirectoryObject = (lpZwQueryDirectoryObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("ZwQueryDirectoryObject"));
	if (!BetaFunctionTable->ZwQueryDirectoryObject)
		iErrCode = 212;

	BetaFunctionTable->RtlInitUnicodeString = (lpRtlInitUnicodeString)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlInitUnicodeString"));
	if (!BetaFunctionTable->RtlInitUnicodeString)
		iErrCode = 213;

	BetaFunctionTable->DeviceIoControl = (lpDeviceIoControl)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("DeviceIoControl"));
	if (!BetaFunctionTable->DeviceIoControl)
		iErrCode = 214;

	BetaFunctionTable->GetThreadPriority = (lpGetThreadPriority)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetThreadPriority"));
	if (!BetaFunctionTable->GetThreadPriority)
		iErrCode = 216;

	BetaFunctionTable->SetThreadPriority = (lpSetThreadPriority)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetThreadPriority"));
	if (!BetaFunctionTable->SetThreadPriority)
		iErrCode = 217;

	BetaFunctionTable->InternetConnectA = (lpInternetConnectA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetConnectA"));
	if (!BetaFunctionTable->InternetConnectA)
		iErrCode = 218;

	BetaFunctionTable->HttpOpenRequestA = (lpHttpOpenRequestA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("HttpOpenRequestA"));
	if (!BetaFunctionTable->HttpOpenRequestA)
		iErrCode = 219;

	BetaFunctionTable->HttpAddRequestHeadersA = (lpHttpAddRequestHeadersA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("HttpAddRequestHeadersA"));
	if (!BetaFunctionTable->HttpAddRequestHeadersA)
		iErrCode = 220;

	BetaFunctionTable->HttpSendRequestExA = (lpHttpSendRequestExA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("HttpSendRequestExA"));
	if (!BetaFunctionTable->HttpSendRequestExA)
		iErrCode = 221;

	BetaFunctionTable->InternetWriteFile = (lpInternetWriteFile)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetWriteFile"));
	if (!BetaFunctionTable->InternetWriteFile)
		iErrCode = 222;

	BetaFunctionTable->HttpEndRequestA = (lpHttpEndRequestA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("HttpEndRequestA"));
	if (!BetaFunctionTable->HttpEndRequestA)
		iErrCode = 223;

	BetaFunctionTable->NtProtectVirtualMemory = (lpNtProtectVirtualMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtProtectVirtualMemory"));
	if (!BetaFunctionTable->NtProtectVirtualMemory)
		iErrCode = 224;

	BetaFunctionTable->VirtualProtectEx = (lpVirtualProtectEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualProtectEx"));
	if (!BetaFunctionTable->VirtualProtectEx)
		iErrCode = 225;

	BetaFunctionTable->CoInitializeEx = (lpCoInitializeEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hOle32, XOR("CoInitializeEx"));
	if (!BetaFunctionTable->CoInitializeEx)
		iErrCode = 226;

	BetaFunctionTable->CoInitializeSecurity = (lpCoInitializeSecurity)BetaFunctionTable->GetProcAddress(BetaModuleTable->hOle32, XOR("CoInitializeSecurity"));
	if (!BetaFunctionTable->CoInitializeSecurity)
		iErrCode = 227;

	BetaFunctionTable->CoCreateInstance = (lpCoCreateInstance)BetaFunctionTable->GetProcAddress(BetaModuleTable->hOle32, XOR("CoCreateInstance"));
	if (!BetaFunctionTable->CoCreateInstance)
		iErrCode = 228;

	BetaFunctionTable->CoSetProxyBlanket = (lpCoSetProxyBlanket)BetaFunctionTable->GetProcAddress(BetaModuleTable->hOle32, XOR("CoSetProxyBlanket"));
	if (!BetaFunctionTable->CoSetProxyBlanket)
		iErrCode = 229;

	BetaFunctionTable->SetTimer = (lpSetTimer)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("SetTimer"));
	if (!BetaFunctionTable->SetTimer)
		iErrCode = 230;

	BetaFunctionTable->KillTimer = (lpKillTimer)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("KillTimer"));
	if (!BetaFunctionTable->KillTimer)
		iErrCode = 231;

	BetaFunctionTable->RtlComputeCrc32 = (lpRtlComputeCrc32)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlComputeCrc32"));
	if (!BetaFunctionTable->RtlComputeCrc32)
		iErrCode = 232;

	BetaFunctionTable->NtRaiseHardError = (lpNtRaiseHardError)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtRaiseHardError"));
	if (!BetaFunctionTable->NtRaiseHardError)
		iErrCode = 233;

	BetaFunctionTable->SetWinEventHook = (lpSetWinEventHook)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("SetWinEventHook"));
	if (!BetaFunctionTable->SetWinEventHook)
		iErrCode = 234;

	BetaFunctionTable->GetWindowInfo = (lpGetWindowInfo)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindowInfo"));
	if (!BetaFunctionTable->GetWindowInfo)
		iErrCode = 235;

	BetaFunctionTable->CommandLineToArgvW = (lpCommandLineToArgvW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hShell32, XOR("CommandLineToArgvW"));
	if (!BetaFunctionTable->CommandLineToArgvW)
		iErrCode = 236;

	BetaFunctionTable->GetCommandLineW = (lpGetCommandLineW)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetCommandLineW"));
	if (!BetaFunctionTable->GetCommandLineW)
		iErrCode = 237;

	BetaFunctionTable->RegOpenKeyExA = (lpRegOpenKeyExA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("RegOpenKeyExA"));
	if (!BetaFunctionTable->RegOpenKeyExA)
		iErrCode = 241;

	BetaFunctionTable->RegQueryValueExA = (lpRegQueryValueExA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("RegQueryValueExA"));
	if (!BetaFunctionTable->RegQueryValueExA)
		iErrCode = 242;

	BetaFunctionTable->RegCloseKey = (lpRegCloseKey)BetaFunctionTable->GetProcAddress(BetaModuleTable->hAdvapi32, XOR("RegCloseKey"));
	if (!BetaFunctionTable->RegCloseKey)
		iErrCode = 243;

	BetaFunctionTable->NtSuspendProcess = (lpNtSuspendProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtSuspendProcess"));
	if (!BetaFunctionTable->NtSuspendProcess)
		iErrCode = 244;

	BetaFunctionTable->NtResumeThread = (lpNtResumeThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtResumeThread"));
	if (!BetaFunctionTable->NtResumeThread)
		iErrCode = 245;

	BetaFunctionTable->NtGetContextThread = (lpNtGetContextThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtGetContextThread"));
	if (!BetaFunctionTable->NtGetContextThread)
		iErrCode = 246;

	BetaFunctionTable->NtSetContextThread = (lpNtSetContextThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtSetContextThread"));
	if (!BetaFunctionTable->NtSetContextThread)
		iErrCode = 247;

	BetaFunctionTable->NtReadVirtualMemory = (lpNtReadVirtualMemory)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtReadVirtualMemory"));
	if (!BetaFunctionTable->NtReadVirtualMemory)
		iErrCode = 248;

	BetaFunctionTable->NtWaitForSingleObject = (lpNtWaitForSingleObject)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtWaitForSingleObject"));
	if (!BetaFunctionTable->NtWaitForSingleObject)
		iErrCode = 249;

	BetaFunctionTable->VirtualAllocEx = (lpVirtualAllocEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualAllocEx"));
	if (!BetaFunctionTable->VirtualAllocEx)
		iErrCode = 250;

	BetaFunctionTable->ShowWindow = (lpShowWindow)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("ShowWindow"));
	if (!BetaFunctionTable->ShowWindow)
		iErrCode = 251;

	BetaFunctionTable->GetConsoleWindow = (lpGetConsoleWindow)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetConsoleWindow"));
	if (!BetaFunctionTable->GetConsoleWindow)
		iErrCode = 252;

	BetaFunctionTable->NtAdjustPrivilegesToken = (lpNtAdjustPrivilegesToken)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtAdjustPrivilegesToken"));
	if (!BetaFunctionTable->NtAdjustPrivilegesToken)
		iErrCode = 254;

	BetaFunctionTable->NtOpenProcessToken = (lpNtOpenProcessToken)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtOpenProcessToken"));
	if (!BetaFunctionTable->NtOpenProcessToken)
		iErrCode = 255;

	BetaFunctionTable->OpenMutexA = (lpOpenMutexA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("OpenMutexA"));
	if (!BetaFunctionTable->OpenMutexA)
		iErrCode = 256;

	BetaFunctionTable->InternetCheckConnectionA = (lpInternetCheckConnectionA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("InternetCheckConnectionA"));
	if (!BetaFunctionTable->InternetCheckConnectionA)
		iErrCode = 257;

	BetaFunctionTable->FtpPutFileA = (lpFtpPutFileA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hWininet, XOR("FtpPutFileA"));
	if (!BetaFunctionTable->FtpPutFileA)
		iErrCode = 258;

	BetaFunctionTable->GetNativeSystemInfo = (lpGetNativeSystemInfo)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetNativeSystemInfo"));
	if (!BetaFunctionTable->GetNativeSystemInfo)
		iErrCode = 259;

	BetaFunctionTable->GetWindow = (lpGetWindow)BetaFunctionTable->GetProcAddress(BetaModuleTable->hUser32, XOR("GetWindow"));
	if (!BetaFunctionTable->GetWindow)
		iErrCode = 260;
	
	BetaFunctionTable->GlobalFree = (lpGlobalFree)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GlobalFree"));
	if (!BetaFunctionTable->GlobalFree)
		iErrCode = 268;


	if (IsWindowsXPSP1OrGreater())
	{
		BetaFunctionTable->GetProcessId = (lpGetProcessId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetProcessId"));
		if (!BetaFunctionTable->GetProcessId)
			iErrCode = 161;
	}

	if (IsWindowsVistaOrGreater())
	{
		BetaFunctionTable->NtCreateThreadEx = (lpNtCreateThreadEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtCreateThreadEx"));
		if (!BetaFunctionTable->NtCreateThreadEx)
			iErrCode = 74;

		BetaFunctionTable->QueryFullProcessImageNameA = (lpQueryFullProcessImageNameA)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("QueryFullProcessImageNameA"));
		if (!BetaFunctionTable->QueryFullProcessImageNameA)
			iErrCode = 115;

		BetaFunctionTable->GetThreadId = (lpGetThreadId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("GetThreadId"));
		if (!BetaFunctionTable->GetThreadId)
			iErrCode = 121;

		BetaFunctionTable->CsrGetProcessId = (lpCsrGetProcessId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("CsrGetProcessId"));
		if (!BetaFunctionTable->CsrGetProcessId)
			iErrCode = 155;

		BetaFunctionTable->NtGetNextThread = (lpNtGetNextThread)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtGetNextThread"));
		if (!BetaFunctionTable->NtGetNextThread)
			iErrCode = 238;

		BetaFunctionTable->NtGetNextProcess = (lpNtGetNextProcess)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtGetNextProcess"));
		if (!BetaFunctionTable->NtGetNextProcess)
			iErrCode = 239;

		BetaFunctionTable->ProcessIdToSessionId = (lpProcessIdToSessionId)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("ProcessIdToSessionId"));
		if (!BetaFunctionTable->ProcessIdToSessionId)
			iErrCode = 240;

		BetaFunctionTable->QueryWorkingSetEx = (lpQueryWorkingSetEx)BetaFunctionTable->GetProcAddress(BetaModuleTable->hPsapi, XOR("QueryWorkingSetEx"));
		if (!BetaFunctionTable->QueryWorkingSetEx)
			iErrCode = 253;

		BetaFunctionTable->EvtCreateRenderContext = (lpEvtCreateRenderContext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtCreateRenderContext"));
		if (!BetaFunctionTable->EvtCreateRenderContext)
			iErrCode = 261;

		BetaFunctionTable->EvtQuery = (lpEvtQuery)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtQuery"));
		if (!BetaFunctionTable->EvtQuery)
			iErrCode = 262;

		BetaFunctionTable->EvtNext = (lpEvtNext)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtNext"));
		if (!BetaFunctionTable->EvtNext)
			iErrCode = 263;

		BetaFunctionTable->EvtRender = (lpEvtRender)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtRender"));
		if (!BetaFunctionTable->EvtRender)
			iErrCode = 264;

		BetaFunctionTable->EvtOpenPublisherMetadata = (lpEvtOpenPublisherMetadata)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtOpenPublisherMetadata"));
		if (!BetaFunctionTable->EvtOpenPublisherMetadata)
			iErrCode = 265;

		BetaFunctionTable->EvtFormatMessage = (lpEvtFormatMessage)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtFormatMessage"));
		if (!BetaFunctionTable->EvtFormatMessage)
			iErrCode = 266;

		BetaFunctionTable->EvtClose = (lpEvtClose)BetaFunctionTable->GetProcAddress(BetaModuleTable->hEvtApi, XOR("EvtClose"));
		if (!BetaFunctionTable->EvtClose)
			iErrCode = 267;

	}

	if (IsWindows8OrGreater())
	{
		BetaFunctionTable->SetProcessMitigationPolicy = (lpSetProcessMitigationPolicy)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("SetProcessMitigationPolicy"));
		if (!BetaFunctionTable->SetProcessMitigationPolicy)
			iErrCode = 215;
	}

	if (IsWindows8Point1OrGreater())
	{
		BetaFunctionTable->LdrGetDllFullName = (lpLdrGetDllFullName)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("LdrGetDllFullName"));
		if (!BetaFunctionTable->LdrGetDllFullName)
			iErrCode = 139;
	}
	

	if (iErrCode) {
		CHAR __warn[] = { 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'A', 'P', 'I', ' ', 'c', 'a', 'l', 'l', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Windows API call failed! Error Code: %d

		char cTmpStr[1024];
		sprintf(cTmpStr, __warn, iErrCode);
		lpFuncs.CloseProcess(cTmpStr, false, "");
	}
	__PROTECTOR_END__("dw-")

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic Windows APIs binded to struct!");
#endif
}

void CWinapi::InitDynamicWinapis()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic WinAPI initialization has been started!");
#endif
	CMain lpMain;
	KARMA_MACRO_1

	BindBaseAPIs();
	KARMA_MACRO_2

	__PROTECTOR_START__("dm+")
	BindModules();
	__PROTECTOR_END__("dm-")
	KARMA_MACRO_2

	BindAPIs();
	KARMA_MACRO_1

	CheckModulesPaths();
	KARMA_MACRO_2

	LPData->SetDynamicAPIsInitialized();
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "Dynamic WinAPI initialization completed!");
#endif
}

#pragma optimize("", on )
