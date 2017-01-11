#include "ProjectMain.h"
#include "AntiDebug.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "XOR.h"
#include "VersionHelpers.h"
#include "CLog.h"


#pragma region GeneralEmulationCheck
inline std::string randomStrGen(int iLength)
{
	CHAR __alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 0x0 }; // abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
	static std::string charset = __alphabet;
	std::string result;
	result.resize(iLength);

	for (int i = 0; i < iLength; i++)
		result[i] = charset[rand() % charset.length()];

	return result;
}

__forceinline void RandomApiCheck()
{
	KARMA_MACRO_1
	auto uTime = (unsigned int)time(NULL);
	srand(uTime);
	std::string szFakeFunctionName = randomStrGen(6);
	KARMA_MACRO_2

	if (BetaFunctionTable->_GetProcAddress(BetaModuleTable->hKernel32, szFakeFunctionName.c_str())) {
		CHAR __warn[] = { 'E', 'm', 'u', 'l', 'a', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '1', 0x0 }; // Emulator detected! Error code: 1
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2
}

__forceinline void CheckErrorMode()
{
	KARMA_MACRO_2
	DWORD dwRealCode = BetaFunctionTable->SetErrorMode(0);
	DWORD dwCode = 1024;

	KARMA_MACRO_1
	BetaFunctionTable->SetErrorMode(1024);
	KARMA_MACRO_2
	if (BetaFunctionTable->SetErrorMode(0) != 1024)
	{
		CHAR __warn[] = { 'E', 'm', 'u', 'l', 'a', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '2', 0x0 }; // Emulator detected! Error code: 2
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

	BetaFunctionTable->SetErrorMode(dwRealCode);
	KARMA_MACRO_1
}

__forceinline void LoadNtOsKrnl()
{
	KARMA_MACRO_1
	if (IsWindows8OrGreater() == true)
		return;

	KARMA_MACRO_2
	CHAR __ntoskrnlexe[] = { 'n', 't', 'o', 's', 'k', 'r', 'n', 'l', '.', 'e', 'x', 'e', 0x0 }; // ntoskrnl.exe

	KARMA_MACRO_1
	HMODULE hProc = BetaFunctionTable->LoadLibraryA(__ntoskrnlexe);
	KARMA_MACRO_1
	if (hProc == NULL)
	{
		CHAR __warn[] = { 'E', 'm', 'u', 'l', 'a', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '3', 0x0 }; // Emulator detected! Error code: 3
		LPFunctions->CloseProcess(__warn, false, "");
	}
	
	KARMA_MACRO_2
	BetaFunctionTable->FreeLibrary(hProc);
}


void CheckRegistry_SandboxProductIDs()
{
	char RegKey[_MAX_PATH] = { 0 };
	DWORD BufSize = _MAX_PATH;
	DWORD dataType = REG_SZ;

	HKEY hKey;
	CHAR __regpath[] = { 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'V', 'e', 'r', 's', 'i', 'o', 'n', '\\', 'P', 'r', 'o', 'd', 'u', 'c', 't', 'I', 'D', 0x0 }; // Software\Microsoft\Windows NT\CurrentVersion\ProductID
	long lError = BetaFunctionTable->RegOpenKeyExA(HKEY_LOCAL_MACHINE, __regpath, NULL, KEY_QUERY_VALUE, &hKey);
	if (lError == ERROR_SUCCESS)
	{
		long lVal = BetaFunctionTable->RegQueryValueExA(hKey, "0" /* column */, NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
		if (lVal == ERROR_SUCCESS)
		{
			std::string szRegKey = RegKey;
			char szRealWarn[4096];
			CHAR __warn[] = { 'S', 'a', 'n', 'd', 'b', 'o', 'x', ' ', 'e', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'Y', 'o', 'u', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'r', 'u', 'n', ' ', 't', 'h', 'e', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', ' ', 's', 'a', 'n', 'd', 'b', 'o', 'x', '!', ' ', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', 0x0 }; // Sandbox environment detected! You can not run the process in sandbox! Error: %d



			CHAR __key1[] = { '7', '6', '4', '8', '7', '-', '6', '4', '0', '-', '1', '4', '5', '7', '2', '3', '6', '-', '2', '3', '8', '3', '7', 0x0 }; // 76487-640-1457236-23837
			CHAR __key2[] = { '7', '6', '4', '8', '7', '-', '3', '3', '7', '-', '8', '4', '2', '9', '9', '5', '5', '-', '2', '2', '6', '1', '4', 0x0 }; // 76487-337-8429955-22614
			CHAR __key3[] = { '7', '6', '4', '8', '7', '-', '6', '4', '4', '-', '3', '1', '7', '7', '0', '3', '7', '-', '2', '3', '5', '1', '0', 0x0 }; // 76487-644-3177037-23510
			CHAR __key4[] = { '7', '6', '4', '9', '7', '-', '6', '4', '0', '-', '6', '3', '0', '8', '8', '7', '3', '-', '2', '3', '8', '3', '5', 0x0 }; // 76497-640-6308873-23835
			CHAR __key5[] = { '5', '5', '2', '7', '4', '-', '6', '4', '0', '-', '2', '6', '7', '3', '0', '6', '4', '-', '2', '3', '9', '5', '0', 0x0 }; // 55274-640-2673064-23950
			CHAR __key6[] = { '7', '6', '4', '8', '7', '-', '6', '4', '0', '-', '8', '8', '3', '4', '0', '0', '5', '-', '2', '3', '1', '9', '5', 0x0 }; // 76487-640-8834005-23195
			CHAR __key7[] = { '7', '6', '4', '8', '7', '-', '6', '4', '0', '-', '0', '7', '1', '6', '6', '6', '2', '-', '2', '3', '5', '3', '5', 0x0 }; // 76487-640-0716662-23535
			CHAR __key8[] = { '7', '6', '4', '8', '7', '-', '6', '4', '4', '-', '8', '6', '4', '8', '4', '6', '6', '-', '2', '3', '1', '0', '6', 0x0 }; // 76487-644-8648466-23106
			CHAR __key9[] = { '0', '0', '4', '2', '6', '-', '2', '9', '3', '-', '8', '1', '7', '0', '0', '3', '2', '-', '8', '5', '1', '4', '6', 0x0 }; // 00426-293-8170032-85146
			CHAR __key10[] = { '7', '6', '4', '8', '7', '-', '3', '4', '1', '-', '5', '8', '8', '3', '8', '1', '2', '-', '2', '2', '4', '2', '0', 0x0 }; // 76487-341-5883812-22420
			CHAR __key11[] = { '7', '6', '4', '8', '7', '-', 'O', 'E', 'M', '-', '0', '0', '2', '7', '4', '5', '3', '-', '6', '3', '7', '9', '6', 0x0 }; // 76487-OEM-0027453-63796


			if (szRegKey == __key1) {
				sprintf(szRealWarn, __warn, 1);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key2) {
				sprintf(szRealWarn, __warn, 2);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key3) {
				sprintf(szRealWarn, __warn, 3);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key4) {
				sprintf(szRealWarn, __warn, 4);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key5) {
				sprintf(szRealWarn, __warn, 5);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key6) {
				sprintf(szRealWarn, __warn, 6);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key7) {
				sprintf(szRealWarn, __warn, 7);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key8) {
				sprintf(szRealWarn, __warn, 8);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key9) {
				sprintf(szRealWarn, __warn, 9);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key10) {
				sprintf(szRealWarn, __warn, 10);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
			if (szRegKey == __key11) {
				sprintf(szRealWarn, __warn, 11);
				LPFunctions->CloseProcess(szRealWarn, true, "");
			}
		}
		BetaFunctionTable->RegCloseKey(hKey);
	}
}
#pragma endregion GeneralEmulationCheck

#pragma region TimeDurationCheck
int iManipulationType = 99;
int CAntiDebug::GetManipulationType() { return iManipulationType; }

inline void Check_GetTickCount()
{	
	KARMA_MACRO_1
	DWORD tStart = BetaFunctionTable->GetTickCount();
	KARMA_MACRO_2

	BetaFunctionTable->Sleep(1000);
	KARMA_MACRO_1

	__try {
		int* p = 0; // access violation
		*p = 0;
	}
	__except (1) {

	}
	BetaFunctionTable->Sleep(1000);
	KARMA_MACRO_2

	DWORD tEnd = BetaFunctionTable->GetTickCount();
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Check_GetTickCount | Start: %u End: %u Diff: %u", tStart, tEnd, tEnd - tStart);
#endif

	if ((tEnd - tStart) > 3000) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Check_GetTickCount diff is bigger than 3sec, Possibly emulator detected! Diff: %u", tEnd - tStart);
#endif
		iManipulationType = 1;
	}


	KARMA_MACRO_1
}

inline void Check_StdChrono()
{
	KARMA_MACRO_2
	auto tStart = std::chrono::high_resolution_clock::now();
	KARMA_MACRO_1

	BetaFunctionTable->Sleep(1000);
	KARMA_MACRO_2
	__try {
		int* p = 0; // access violation
		*p = 0;
	}
	__except (1) {

	}
	BetaFunctionTable->Sleep(1000);
	KARMA_MACRO_2

	auto tDiff = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - tStart).count();
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "Check_StdChrono | Diff: %lld", tDiff);
#endif

	if (tDiff > 3000) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Check_StdChrono diff is bigger than 3sec, Possibly emulator detected! Diff: %u", tDiff);
#endif
		iManipulationType = 2;
	}

	KARMA_MACRO_1
}
#pragma endregion TimeDurationCheck

void CAntiDebug::InitTimeChecks()
{
	#ifdef _DEBUG
	LPLog->AddLog(0, "Anti emulation InitTimeChecks has been started");
#endif
	KARMA_MACRO_2

	Check_GetTickCount();
	Check_StdChrono();

	KARMA_MACRO_1
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti emulation InitTimeChecks completed");
#endif
}

void CAntiDebug::AntiEmulation()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti emulation has been started");
#endif
	KARMA_MACRO_1

	RandomApiCheck();
	CheckErrorMode();
	LoadNtOsKrnl();
	CheckRegistry_SandboxProductIDs();

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti emulation completed");
#endif
}

