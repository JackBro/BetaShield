#include "ProjectMain.h"
#include "AntiDebug.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "XOR.h"
#include "Access.h"
#include "VersionHelpers.h"
#include "DirFuncs.h"
#include "CLog.h"


CAntiDebug* LPAntiDebug;
CAntiDebug::CAntiDebug()
{
}

CAntiDebug::~CAntiDebug()
{
}


#pragma optimize("", off )
inline void IsDebugInit()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug IsDebug initialization has been started!");
#endif
	KARMA_MACRO_1

	CHAR __warn1[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '2', '1', 0x0 }; // Debugger Detected; Err Code: 0x90000021
	if (BetaFunctionTable->IsDebuggerPresent())
		LPFunctions->CloseProcess(__warn1, true, "");

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug IsDebug step1 completed!");
#endif

	CHAR __warn2[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '2', '2', 0x0 }; // Debugger Detected; Err Code: 0x90000022
	PROCESS_BASIC_INFORMATION pPBI;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(NtCurrentProcess, ProcessBasicInformation, &pPBI, sizeof(PROCESS_BASIC_INFORMATION), 0)))
		if (pPBI.PebBaseAddress->BeingDebugged == 1)
			LPFunctions->CloseProcess(__warn2, true, "");
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug IsDebug step2 completed!");
#endif

	CHAR __warn3[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '2', '3', 0x0 }; // Debugger Detected; Err Code: 0x90000023
	DWORD dwResult = 1;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(NtCurrentProcess, ProcessDebugFlags, &dwResult, sizeof(dwResult), NULL)))
		if (dwResult == 0)
			LPFunctions->CloseProcess(__warn3, true, "");
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug IsDebug initialization completed!");
#endif
}

// ---------------------------------------------------------------------------------

void CAntiDebug::RemoteDebugCheck()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug RemoteDebugCheck initialization has been started!");
#endif
	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '6', 0x0 }; // Debugger Detected; Err Code: 0x90000006

	BOOL b_IsRmotedbgPresent = FALSE;
	BetaFunctionTable->CheckRemoteDebuggerPresent(NtCurrentProcess, &b_IsRmotedbgPresent);
	if (b_IsRmotedbgPresent)
		LPFunctions->CloseProcess(__warn, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug RemoteDebugCheck initialization completed!");
#endif
}

inline int CheckPEBBeingDebuggedFromWow64()
{
	unsigned long IsWow64 = 0;
	unsigned char BeingDebugged32 = 0;
	unsigned char BeingDebugged64 = 0;

	__asm
	{
		pushad
			mov eax, dword ptr fs : [0xC0]
			mov IsWow64, eax
			mov eax, dword ptr fs : [0x30]
			mov al, byte ptr[eax + 0x2]
			mov BeingDebugged32, al
			popad
	}

	if (BeingDebugged32)
		return 1;

	if (IsWow64)
	{
		__asm
		{
			pushad
				mov eax, dword ptr fs : [0x18]
				sub eax, 0x2000
				mov eax, dword ptr[eax + 0x60];
				mov al, byte ptr[eax + 0x2]
				mov BeingDebugged64, al
				popad
		}

		if (BeingDebugged64)
			return 2;
	}

	return 0;
}

void CAntiDebug::PebCheck() {
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug PebCheck initialization has been started!");
#endif

	KARMA_MACRO_1
	char PEBdbgTrue = 0;

	__asm
	{
		xor eax, eax;
		mov eax, fs:[30h]
			mov al, [eax + 2h]
			mov PEBdbgTrue, al
	}

	CHAR __warn1[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '1', 0x0 }; // Debugger Detected; Err Code: 0x90000001
	CHAR __warn2[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '1', '-', '1', 0x0 }; // Debugger Detected; Err Code: 0x90000001-1
	CHAR __warn3[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '1', '-', '2', 0x0 }; // Debugger Detected; Err Code: 0x90000001-2


	KARMA_MACRO_2
	if (PEBdbgTrue)
		LPFunctions->CloseProcess(__warn1, true, "");

	KARMA_MACRO_2
	int wow64pebcheck = CheckPEBBeingDebuggedFromWow64();
	if (wow64pebcheck == 1)
		LPFunctions->CloseProcess(__warn2, true, "");

	KARMA_MACRO_1
	if (wow64pebcheck == 2)
		LPFunctions->CloseProcess(__warn3, true, "");

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug PebCheck initialization completed!");
#endif
}

void CAntiDebug::IsDebugger() {
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug IsDebugger initialization has been started!");
#endif
	KARMA_MACRO_1

	IsDebugInit();

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug IsDebugger initialization completed!");
#endif
}

void CAntiDebug::SetFakeImageSize() {
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug SetFakeImageSize initialization has been started!");
#endif
	KARMA_MACRO_1

	__asm
	{
		mov eax, fs:[0x30]				// PEB
		mov eax, [eax + 0x0c]			 // PEB_LDR_DATA
			mov eax, [eax + 0x0c]			// InOrderModuleList
			mov dword ptr[eax + 20h], 20000h // SizeOfImage
	}

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug SetFakeImageSize initialization completed!");
#endif
}

void CAntiDebug::CrashDebugger() {
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CrashDebugger initialization has been started!");
#endif
	KARMA_MACRO_2

	CHAR OLLY_CRASH_TEXT[] = { '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', '%', 's', 0x0 }; //%s%s%s%s%s%s%s%s%s%s%s
	BetaFunctionTable->OutputDebugStringA(TEXT(OLLY_CRASH_TEXT));

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CrashDebugger initialization completed!");
#endif
}

void CAntiDebug::DebugPort()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug AntiDebugDebugPort initialization has been started!");
#endif
	KARMA_MACRO_1
	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '4', 0x0 }; // Debugger Detected; Err Code: 0x90000004

	HANDLE port = 0;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(NtCurrentProcess, ProcessDebugPort, &port, sizeof(HANDLE), 0)))
		if (port != 0)
			LPFunctions->CloseProcess(__warn, true, "");

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug AntiDebugDebugPort initialization completed!");
#endif
}

inline bool CloseHandleExCheck() {
	__try {
		CloseHandle((HANDLE)0x3333);
	}
	__except (1) {
		return true;
	}
	return false;
}

void CAntiDebug::CheckCloseHandle()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CloseHandle initialization has been started!");
#endif
	KARMA_MACRO_1
	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '5', 0x0 }; // Debugger Detected; Err Code: 0x90000005

	if (CloseHandleExCheck())
		LPFunctions->CloseProcess(__warn, true, "");

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CloseHandle initialization completed!");
#endif
}

void CAntiDebug::DetachFromDebuggerProcess()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug DetachFromDebuggerProcess initialization has been started!");
#endif
	KARMA_MACRO_1

	int iErrorCode = 0;
	ULONG dwFlags = 0;
	HANDLE hDebugObject = 0;

	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(NtCurrentProcess, ProcessDebugObjectHandle, &hDebugObject, sizeof(HANDLE), NULL)))
	{
		if (!NT_SUCCESS(BetaFunctionTable->NtSetInformationDebugObject(hDebugObject, DebugObjectFlags, &dwFlags, sizeof(ULONG), NULL)))
			iErrorCode = 2;

		if (!NT_SUCCESS(BetaFunctionTable->NtRemoveProcessDebug(NtCurrentProcess, hDebugObject)))
			iErrorCode = 3;

		if (!NT_SUCCESS(BetaFunctionTable->NtClose(hDebugObject)))
			iErrorCode = 4;
	}
	else
		iErrorCode = 1;

	// TODO: if iErrorCode > die

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug DetachFromDebuggerProcess initialization completed!");
#endif
}

inline DWORD getParentPIDasForced(DWORD dwProcessId)
{
	PROCESS_BASIC_INFORMATION pPBI;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(NtCurrentProcess, ProcessBasicInformation, &pPBI, sizeof(PROCESS_BASIC_INFORMATION), 0)))
		return (DWORD)pPBI.InheritedFromUniqueProcessId;
	return 0;
}

inline DWORD GetExplorerPIDbyShellWindow()
{
	DWORD PID = 0;
	BetaFunctionTable->GetWindowThreadProcessId(BetaFunctionTable->GetShellWindow(), &PID);
	return PID;
}

__forceinline void CheckParentOfParentProcessId(DWORD dwProcessId)
{
	CFunctions lpFuncs;
	CDirFunctions lpDirFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug ParentOfParentProcessId check initialization has been started!");
#endif
	KARMA_MACRO_1

	DWORD dwParentPid = LPFunctions->GetProcessParentProcessId(dwProcessId);
	if (!dwParentPid) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Parent of parent pid is null!");
#endif
		CHAR opwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '4', 0x0 }; // Fatal Error on process initilization! Error code: 4
		LPFunctions->CloseProcess(opwarn, false, "");
	}

	// Parent of parent informations
	HANDLE hProc = BetaFunctionTable->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParentPid);
	DWORD dwLastErr = LPWinapi->LastError();
	if (!hProc && LPFunctions->ProcessIsItAlive(dwParentPid)) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Parent of parent : %u is not opened Error code: %u", dwParentPid, dwLastErr);
#endif
		CHAR opwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '2', 0x0 }; // Fatal Error on process initilization! Error code: 2
		LPFunctions->CloseProcess(opwarn, false, "");
	}


	std::string szDosName = LPFunctions->GetProcessFullName(hProc);
	std::string szParentOfParentName = LPFunctions->DosDevicePath2LogicalPath(szDosName.c_str());
	std::transform(szParentOfParentName.begin(), szParentOfParentName.end(), szParentOfParentName.begin(), tolower);
	
	BetaFunctionTable->CloseHandle(hProc);

#ifdef _DEBUG
	LPLog->AddLog(0, "Parent of parent process: %s(%u)", szParentOfParentName.c_str(), dwParentPid);
#endif

	KARMA_MACRO_2

	// Windows informations
	CHAR __explorer[] = { 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', 0x0 };
	std::string szWindowsPath = lpDirFuncs.WinPath();
	std::transform(szWindowsPath.begin(), szWindowsPath.end(), szWindowsPath.begin(), tolower);

	KARMA_MACRO_1

	// If launcher's parent process(parent of parent) is not explorer and launcher's parent name succesfully detected
	if ((szParentOfParentName.empty() == false) && (!strstr(szParentOfParentName.c_str(), szWindowsPath.c_str()) || !strstr(szParentOfParentName.c_str(), __explorer))) { /* If have a result and If not parent == explorer.exe */
#ifdef _DEBUG
		LPLog->AddLog(0,"CheckParentOfParentProcessId Parent of parent name: %s Size of parent of parent: %d", szParentOfParentName.c_str(), szParentOfParentName.size());
#endif
		CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', 0x0 }; // Anticheat Initilization failed!

		LPFunctions->CloseProcess(__warn, true, "");
		KARMA_MACRO_2
	}
	else {
		// If not launcher's parent name succesfully detected
		KARMA_MACRO_1
		if (GetExplorerPIDbyShellWindow() != dwParentPid || !BetaFunctionTable->GetShellWindow() || !GetExplorerPIDbyShellWindow())
		{
#ifdef _DEBUG
			LPLog->AddLog(0,"CheckParentOfParentProcessId Shell pid: %u Parent of parent pid: %u", GetExplorerPIDbyShellWindow(), dwParentPid);
#endif
			CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '9', '9', 0x0 }; // Anticheat Initilization failed! Error code: 99

			LPFunctions->CloseProcess(__warn, true, "");
		}
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug ParentOfParentProcessId check initialization completed!");
#endif
}


void CAntiDebug::ParentCheck(const char* c_szPatcherName)
{
	CFunctions lpFuncs;
	CDirFunctions lpDirFuncs;
	CAccess lpAccess;

#ifdef _DEBUG
	LPLog->AddLog(0, "Antidebug ParentCheck initialization has been started!");
#endif
	KARMA_MACRO_1

	//lpAccess.EnableDebugPrivileges();

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	BetaFunctionTable->GetStartupInfoA(&si);

	KARMA_MACRO_1

	if (si.dwFlags & STARTF_FORCEOFFFEEDBACK /* Trick for OllyDbg v1.10 and v2.x*/)
	{
		KARMA_MACRO_2
#ifdef _DEBUG
		LPLog->AddLog(0, "si.dwFlags: %u", si.dwFlags);
#endif
		CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '8', 0x0 }; // Anticheat Initilization failed! Error code: 8

		LPFunctions->CloseProcess(__warn, true, "");
	}

	KARMA_MACRO_2

	std::string szLowerPatcherName(c_szPatcherName, strnlen(c_szPatcherName, MAX_PATH));
	transform(szLowerPatcherName.begin(), szLowerPatcherName.end(), szLowerPatcherName.begin(), tolower);

	KARMA_MACRO_2

	DWORD dwParentPid = LPFunctions->GetProcessParentProcessId(BetaFunctionTable->GetCurrentProcessId());
	DWORD dwForcedParentPid = getParentPIDasForced(BetaFunctionTable->GetCurrentProcessId());
	HANDLE hProc = BetaFunctionTable->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParentPid);
	if (!hProc && LPFunctions->ProcessIsItAlive(dwParentPid)) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Parent process %u can not opened! Error code: %u", dwParentPid, LPWinapi->LastError());
#endif
		CHAR opwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '3', 0x0 }; // Fatal Error on process initilization! Error code: 3
		LPFunctions->CloseProcess(opwarn, false, "");
	}

	std::string szDosName = LPFunctions->GetProcessFullName(hProc);
	std::string szParentName = LPFunctions->DosDevicePath2LogicalPath(szDosName.c_str());
	std::transform(szParentName.begin(), szParentName.end(), szParentName.begin(), tolower);

#ifdef _DEBUG
	LPLog->AddLog(0, "Parent process: %s(%u-%u)", szParentName.c_str(), dwParentPid, dwForcedParentPid);
#endif

	KARMA_MACRO_1

	CHAR __explorer[] = { 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', 0x0 };
	std::string szWindowsPath = lpDirFuncs.WinPath();
	transform(szWindowsPath.begin(), szWindowsPath.end(), szWindowsPath.begin(), tolower);

	KARMA_MACRO_2

	std::string szExePath = lpDirFuncs.ExePath();
	transform(szExePath.begin(), szExePath.end(), szExePath.begin(), tolower);

	KARMA_MACRO_2


	if (dwParentPid != dwForcedParentPid) { /* Anti Parent pid manipulation */
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CAntiDebug::ParentCheck - IsVista/+: %d Parent pid: %u Forced parent pid: %u", IsWindowsVistaOrGreater(), dwParentPid, dwForcedParentPid);
#endif
		CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '2', 0x0 }; // Anticheat Initilization failed! Error code: 2

		LPFunctions->CloseProcess(__warn, true, "");
	}

	KARMA_MACRO_1
#if 0
	if (szParentName.empty() /* if is NOT succesfuly received parent informations */ || !strlen(c_szPatcherName) /* OR if not have patcher */)
	{
		KARMA_MACRO_1
		if (!BetaFunctionTable->GetShellWindow() /* Is not get shell window */ || !GetExplorerPIDbyShellWindow() /* Is not get shell windows's pid */ ||
			GetExplorerPIDbyShellWindow() != dwParentPid /* Explorer's PID is NOT same with shell window's pid */)
		{
#ifdef _DEBUG
			LPLog->AddLog(0, "Shell pid: %u Parent pid: %u", GetExplorerPIDbyShellWindow(), dwParentPid);
#endif
			CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '6', 0x0 }; // Anticheat Initilization failed! Error code: 6

			LPFunctions->CloseProcess(__warn, true, "");
		}
	}
#endif

	if (szParentName.empty() == false && !strlen(c_szPatcherName))
	{ /* if is succesfuly received parent informations and not have patcher */
		KARMA_MACRO_1
		if (!strstr(szParentName.c_str(), szWindowsPath.c_str()) || !strstr(szParentName.c_str(), __explorer)) /* explorer path is NOT in windows */
		{
#ifdef _DEBUG
			LPLog->AddLog(0, "Parent Name: %s Win path: %s", szParentName.c_str(), lpDirFuncs.WinPath().c_str());
#endif
			CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '5', 0x0 }; // Anticheat Initilization failed! Error code: 5

			LPFunctions->CloseProcess(__warn, true, "");
		}
	}

	if (szParentName.empty() == false && strlen(c_szPatcherName))
	{ /* if is succesfuly received parent informations and have patcher */
		KARMA_MACRO_2
		if (!strstr(szParentName.c_str(), szLowerPatcherName.c_str()) /* If not patcher name == parent */ ||
			!strstr(szParentName.c_str(), szExePath.c_str()) /* OR If patcher is NOT in same path -or not in same subpath- with game */)
		{ 
#ifdef _DEBUG
			LPLog->AddLog(0, "Parent Name: %s Patcher name: %s", szParentName.c_str(), szLowerPatcherName.c_str());
#endif

			CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'I', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '3', 0x0 }; // Anticheat Initilization failed! Error code: 3

			LPFunctions->CloseProcess(__warn, true, "");
		}

		// If process opened from another process(autopatcher or other) check launcher process's parent pid,
		// If launcher is not opened from explorer.exe kill it.
		CheckParentOfParentProcessId(dwParentPid);

		KARMA_MACRO_1

		/* If parent process(autopatcher or launcher) is still in alive, kill it */
		if (LPFunctions->ProcessIsItAlive(dwParentPid)) 
		{
			BetaFunctionTable->WinStationTerminateProcess(NULL, dwParentPid, DBG_TERMINATE_PROCESS);

			if (LPFunctions->ProcessIsItAlive(dwParentPid)) {
				HWND hwTargetWindow = LPFunctions->FindWindowFromProcessId(dwParentPid);
				BetaFunctionTable->EndTask(hwTargetWindow, FALSE, TRUE);
			}
		}
	}

	KARMA_MACRO_2

	//lpAccess.DisableDebugPrivileges();

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Antidebug ParentCheck initialization completed!");
#endif
}


void CAntiDebug::CheckKernelDebugInformation()
{
	CFunctions lpFuncs;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	if (NT_SUCCESS(BetaFunctionTable->NtQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL))) {
		if (Info.KernelDebuggerEnabled && !Info.KernelDebuggerNotPresent) {
			CHAR __warn[] = { 'K', 'e', 'r', 'n', 'e', 'l', ' ', 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'd', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 's', ' ', 'a', 'n', 'd', ' ', 'A', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', 0x0 }; // Kernel Debugger detected! Please disable debuggers and Antivirus
			LPFunctions->CloseProcess(__warn, true, "");
		}
	}
}


void CAntiDebug::AntiSoftice()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug AntiSoftice initialization has been started!");
#endif

	CHAR __Softice[] = { '/', '/', '/', '/', '.', '/', '/', 'S', 'I', 'C', 'E', 0x0 }; // ////.//SICE
	CHAR __Softice2[] = { '/', '/', '/', '/', '.', '/', '/', 'S', 'I', 'W', 'V', 'I', 'D', 'S', 'T', 'A', 'R', 'T', 0x0 }; // ////.//SIWVIDSTART"
	CHAR __NTIce[] = { '/', '/', '/', '/', '.', '/', '/', 'N', 'T', 'I', 'C', 'E', 0x0 }; // ////.//NTICE"

	bool bSoftICE = (BetaFunctionTable->CreateFileA(__Softice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE); // \\.\SICE
	bool bSoftICE2 = (BetaFunctionTable->CreateFileA(__Softice2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE); // \\.\SIWVIDSTART
	bool bNTICE = (BetaFunctionTable->CreateFileA(__NTIce, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE); // \\.\NTICE

	if (bSoftICE || bSoftICE2 || bNTICE) {
		CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '8', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, true, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug AntiSoftice initialization completed!");
#endif
}

void CAntiDebug::Antisyser()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug Antisyser initialization has been started!");
#endif

	CHAR __Syser[] = { '\\', '\\', '.', '\\', 'S', 'y', 's', 'e', 'r',	 0x0 }; // \\.\Syser
	CHAR __SyserBoot[] = { '\\', '\\', '.', '\\', 'S', 'y', 's', 'e', 'r', 'B', 'o', 'o', 't', 0x0 }; // \\.\SyserBoot
	CHAR __SyserDbgMsg[] = { '\\', '\\', '.', '\\', 'S', 'y', 's', 'e', 'r', 'D', 'b', 'g', 'M', 's', 'g', 0x0 }; // \\.\SyserDbgMsg

	bool bSyser = (BetaFunctionTable->CreateFileA(__Syser, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE);
	bool bSyserBoot = (BetaFunctionTable->CreateFileA(__SyserBoot, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE);
	bool bSyserDebugMsg = (BetaFunctionTable->CreateFileA(__SyserDbgMsg, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE);

	if (bSyser || bSyserBoot || bSyserDebugMsg) {
		CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '8', '-', '2', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, true, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug Antisyser initialization completed!");
#endif
}

inline BOOL NtGlobalFlag()
{
	/* FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK(0x20), and FLG_HEAP_VALIDATE_PARAMETERS(0x40) */

	unsigned long NtGlobalFlags = 0;
	__asm
	{
		mov eax, fs:[30h]
			mov eax, [eax + 68h]
			mov NtGlobalFlags, eax
	}

	// 0x70 =  FLG_HEAP_ENABLE_TAIL_CHECK |
	//         FLG_HEAP_ENABLE_FREE_CHECK |
	//         FLG_HEAP_VALIDATE_PARAMETERS

	if (NtGlobalFlags & 0x70)
		return TRUE;
	else
		return FALSE;
}

inline BOOL HeapFlags()
{
	char IsBeingDbg = FALSE;

	__asm {
		mov eax, FS:[0x30]
			mov eax, [eax + 0x18]; PEB.ProcessHeap
			mov eax, [eax + 0x44]
			cmp eax, 0
			je DebuggerNotFound
			mov IsBeingDbg, 1
		DebuggerNotFound:
	}

	return IsBeingDbg;
}

inline BOOL ForceFlags()
{
	char IsBeingDbg = 0;

	__asm {
		mov eax, FS:[0x30]
			mov eax, [eax + 0x18]; PEB.ProcessHeap
			mov eax, [eax + 0x40]
			dec eax
			dec eax
			jne DebuggerFound
			jmp ExitMe
		DebuggerFound :
		mov IsBeingDbg, 1
		ExitMe :
	}

	return IsBeingDbg;
}

void CAntiDebug::FlagsCheck()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug FlagsCheck initialization has been started!");
#endif

	CHAR __warn1[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '7', 0x0 }; // Debugger Detected; Err Code: 0x90000007

	if (NtGlobalFlag())
		LPFunctions->CloseProcess(__warn1, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug FlagsCheck step2 completed!");
#endif

	CHAR __warn2[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '8', 0x0 }; // Debugger Detected; Err Code: 0x90000008

	//if (HeapFlags())
	//	LPFunctions->CloseProcess(__warn2, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug FlagsCheck step3 completed!");
#endif
	
	CHAR __warn3[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '0', '9', 0x0 }; // Debugger Detected; Err Code: 0x90000009

	//if (ForceFlags())
	//	LPFunctions->CloseProcess(__warn3, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug FlagsCheck initialization completed!");
#endif
}

inline bool __PrefixCheck()
{
	__try
	{
		__asm __emit 0xF3 // 0xF3 0x64 disassembles as PREFIX REP:
		__asm __emit 0x64
		__asm __emit 0xF1 // One byte INT 1
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}

	return true;
}

void CAntiDebug::PrefixCheck()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug PrefixCheck initialization has been started!");
#endif
	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '0', 0x0 }; // Debugger Detected; Err Code: 0x90000010

	if (__PrefixCheck())
		LPFunctions->CloseProcess(__warn, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug PrefixCheck initialization completed!");
#endif
}

/*
__declspec(naked) int CheckInt2D(void)
{
	__asm
	{
		push offset notDebugger
			push DWORD ptr FS : [0]
			mov DWORD ptr FS : [0], esp   // Install SEH!
			INT 2Dh
			NOP      // Breakpoint it here!
			// SoftIce Driver must crash in here!

			//IsDebugger:
			pop DWORD ptr FS : [0]
			add esp, 4
			mov eax, 1
			retn

		notDebugger :
		push edi
			mov edi, [esp + 10h] // pContext
			mov dword ptr[edi + 0B8h], offset Cleanup // eip
			pop edi
			xor eax, eax
			retn
		Cleanup :
		pop DWORD ptr FS : [0]   // Cleanup SEH!
			add esp, 4
			xor eax, eax
			retn
	}
}
*/

inline BOOL IsInt2d()
{
    __try
    {
        __asm
        {
            int 2dh;
            inc eax;//any opcode of singlebyte
            //;or u can put some junkcode,"0xc8"..."0xc2"..."0xe8"..."0xe9"
        }
        return TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

int CheckInt3(){
	int DebuggerEnabled = 1;

	__try {
		__asm {
			// INT3
			__emit 0xcc
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		DebuggerEnabled = 0;
	}

	return DebuggerEnabled;
}


void CAntiDebug::Int2DCheck(){
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug Int2Check initialization has been started!");
#endif

	CHAR __warn2[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '1', '2', 0x0 }; // Debugger Detected; Err Code: 0x900000112

	/*Debugger Detected; Err Code: 0x90000011*/
	/* if (CheckInt2D())
		LPFunctions->CloseProcess(XorStr<0xC8, 40, 0x67C0174C>("\x8C\xAC\xA8\xBE\xAB\xAA\xAB\xBD\xF0\x95\xB7\xA7\xB1\xB6\xA2\xB2\xBC\xE2\xFA\x9E\xAE\xAF\xFE\x9C\x8F\x85\x87\xD9\xC4\xD5\x9E\xDE\xD8\xD9\xDA\xDB\xDC\xDC\xDF" + 0x67C0174C).s, true, "");
	
	else */ if (IsInt2d())
		LPFunctions->CloseProcess(__warn2, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug Int2Check initialization completed!");
#endif
}

void CAntiDebug::Int3Check(){
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug Int3Check initialization has been started!");
#endif

	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '2', 0x0 }; // Debugger Detected; Err Code: 0x90000012

	if (CheckInt3())
		LPFunctions->CloseProcess(__warn, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug Int3Check initialization completed!");
#endif
}

void CAntiDebug::CheckGlobalFlagsClearInProcess()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CheckGlobalFlags initialization has been started!");
#endif

	PBYTE pImageBase = (PBYTE)BetaModuleTable->hBaseModule;
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pImageDosHeader->e_lfanew);

	PIMAGE_LOAD_CONFIG_DIRECTORY pImageLoadConfigDirectory = (PIMAGE_LOAD_CONFIG_DIRECTORY)
		(pImageBase + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
	
	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '4', 0x0 }; // Debugger Detected; Err Code: 0x90000014

	if (pImageLoadConfigDirectory->GlobalFlagsClear)
		LPFunctions->CloseProcess(__warn, true, "");

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CheckGlobalFlags initialization completed!");
#endif
}

void CAntiDebug::CheckDebugObjects()
{
	if (IsWindows7OrGreater() == false)
		return;

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CheckDebugObjects initialization has been started!");
#endif


	POBJECT_TYPES_INFORMATION pTypesInfo = NULL;
	ULONG dwSize = 0;

	NTSTATUS Status = BetaFunctionTable->NtQueryObject(NULL, ObjectTypesInformation, NULL, 0, &dwSize);

	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		pTypesInfo = (POBJECT_TYPES_INFORMATION)BetaFunctionTable->VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (!pTypesInfo)
			return;

		Status = BetaFunctionTable->NtQueryObject(NULL, ObjectTypesInformation, pTypesInfo, dwSize, &dwSize);
		if (!NT_SUCCESS(Status))
			BetaFunctionTable->VirtualFree(pTypesInfo, 0, MEM_RELEASE);
	}

	if (Status == STATUS_SUCCESS)
	{
		for (UINT i = 0; i < pTypesInfo->NumberOfTypes; i++)
		{
			if (pTypesInfo->TypeInformation[i].TypeName.Length && pTypesInfo->TypeInformation[i].TypeName.Buffer)
			{
				CHAR c_DebugObject[] = { 'D', 'e', 'b', 'u', 'g', 'O', 'b', 'j', 'e', 'c', 't', 0x0 };
				std::string szTypeName = LPFunctions->WstringToUTF8(pTypesInfo->TypeInformation[i].TypeName.Buffer);
				if (!strcmp(szTypeName.c_str(), c_DebugObject))
				{
					CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '5', 0x0 }; // Debugger Detected; Err Code: 0x90000015

					LPFunctions->CloseProcess(__warn, true, "");
					BetaFunctionTable->VirtualFree(pTypesInfo, 0, MEM_RELEASE);
					return;
				}
			}
		}

		BetaFunctionTable->VirtualFree(pTypesInfo, 0, MEM_RELEASE);
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CheckDebugObjects initialization completed!");
#endif
}

void CAntiDebug::ThreadBreakOnTerminationCheck()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug ThreadBreakOnTerminationCheck initialization has been started!");
#endif

	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '6', 0x0 }; // Debugger Detected; Err Code: 0x90000016

	ULONG ulResult = 0;
	KARMA_MACRO_2
	if (NT_SUCCESS(BetaFunctionTable->ZwSetInformationThread(NtCurrentProcess, ThreadBreakOnTermination, &ulResult, sizeof(ULONG))))
		if (ulResult)
			LPFunctions->CloseProcess(__warn, true, "");
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug ThreadBreakOnTerminationCheck initialization completed!");
#endif
}

__forceinline bool CheckHypervisor()
{
	bool x = false;
	__asm
	{
		pushad
			pushfd
			pop eax
			or eax, 0x00200000
			push eax
			popfd
			pushfd
			pop eax
			and eax, 0x00200000
			jz CPUID_NOT_SUPPORTED
			xor eax, eax
			xor edx, edx
			xor ecx, ecx
			xor ebx, ebx
			inc eax
			cpuid
			test ecx, 0x80000000
			jnz Hypervisor
			mov x, 0
			jmp bye
		Hypervisor :
		mov x, 1
			jmp bye
		CPUID_NOT_SUPPORTED :
		mov x, 2
		bye :
			popad
	}

	return (x == 1);
}

void CAntiDebug::AntiHyperVisor()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug AntiHyperVisor initialization has been started!");
#endif

	CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '7', 0x0 }; // Debugger Detected; Err Code: 0x90000017

	if (CheckHypervisor()) {
		LPFunctions->CloseProcess(__warn, true, "");
		KARMA_MACRO_1
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug AntiHyperVisor initialization completed!");
#endif
}


unsigned long GetCurrentEIP()
{
	unsigned long x_eip = 0;
	__asm
	{
		call x
		x :
		pop eax
			mov x_eip, eax
	}
	return x_eip;
}

void CAntiDebug::CheckShareCount()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Antidebug CheckShareCount initialization has been started!");
#endif

	KARMA_MACRO_2

	PSAPI_WORKING_SET_INFORMATION* pWSI = (PSAPI_WORKING_SET_INFORMATION*)BetaFunctionTable->VirtualAlloc(0, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pWSI)
		return;

	KARMA_MACRO_1
	BOOL ret = BetaFunctionTable->QueryWorkingSet(NtCurrentProcess, pWSI, 0x10000);
	if (!ret)
	{
		BetaFunctionTable->VirtualFree(pWSI, 0, MEM_RELEASE);
		return;
	}

	KARMA_MACRO_2
	unsigned long Num = pWSI->NumberOfEntries;
	if (!Num)
	{
		BetaFunctionTable->VirtualFree(pWSI, 0, MEM_RELEASE);
		return;
	}

	KARMA_MACRO_2
	bool debugger_present = false;
	for (unsigned long i = 0; i < Num; i++)
	{
		unsigned long Addr = ((pWSI->WorkingSetInfo[i].VirtualPage)) << 0x0C;

		if (Addr == (GetCurrentEIP() & 0xFFFFF000))
		{
			KARMA_MACRO_1
			if ((pWSI->WorkingSetInfo[i].Shared == 0) || (pWSI->WorkingSetInfo[i].ShareCount == 0))
			{
				KARMA_MACRO_1
				debugger_present = true;
				break;
			}
		}
	}

	KARMA_MACRO_1
	if (debugger_present) {
		CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '8', 0x0 }; // Debugger Detected; Err Code: 0x90000018

		KARMA_MACRO_2
		LPFunctions->CloseProcess(__warn, true, "");
		KARMA_MACRO_1
	}
	KARMA_MACRO_2

	BetaFunctionTable->VirtualFree(pWSI, 0, MEM_RELEASE);

#ifdef _DEBUG
	LPLog->AddLog(0, "Antidebug CheckShareCount initialization completed!");
#endif
}



DWORD IsEnumProcess()
{
	DWORD dwPidTemp = 0;

	HANDLE procSnap = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (procSnap == INVALID_HANDLE_VALUE)
		return -1;

	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	BOOL bRet = BetaFunctionTable->Process32First(procSnap, &procEntry);
	while (bRet)
	{
		if (0 == strcmp(procEntry.szExeFile, XOR("csrss.exe")))
		{
			dwPidTemp = procEntry.th32ProcessID;
			return TRUE;
		}

		bRet = BetaFunctionTable->Process32Next(procSnap, &procEntry);
	}

	BetaFunctionTable->CloseHandle(procSnap);
	return dwPidTemp;
}

typedef struct TAGSTRONGOD
{
	DWORD m_dwFlag;
	DWORD m_dwCressPID;
	DWORD m_dwReserver1;
	DWORD m_dwReserver2;
	DWORD m_dwReserver3;
	DWORD m_dwReserver4;
	DWORD m_dwReserver5;
	DWORD m_dwReserver6;
	DWORD m_dwReserver7;
	WORD  m_wMePid;
	WORD  m_wReserver8;
}tagSTRONGOD;

void CAntiDebug::CheckStrongOD()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Antidebug CheckStrongOD initialization has been started!");
#endif

	KARMA_MACRO_2

	UNICODE_STRING     strDirName;
	OBJECT_ATTRIBUTES  oba;
	NTSTATUS           ntStatus;
	HANDLE             hDirectory;

	WCHAR __global[] = { L'\\', L'\\', L'g', L'l', L'o', L'b', L'a', L'l', L'?', L'?', L'\0' };
	BetaFunctionTable->RtlInitUnicodeString(&strDirName, __global);
	InitializeObjectAttributes(&oba, &strDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntStatus = BetaFunctionTable->ZwOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oba);
	if (ntStatus != STATUS_SUCCESS)
	{
		if (hDirectory != NULL)
			BetaFunctionTable->ZwClose(hDirectory);

		return;
	}

	UNICODE_STRING symbolicLink;
	BYTE           buffer[2048] = { 0 };
	ULONG          ulLength = 2048;
	ULONG          ulContext = 0;
	ULONG          ulRet = 0;
	int			   i = 0;

	WCHAR __symboliclink[] = { L'S', L'y', L'm', L'b', L'o', L'l', L'i', L'c', L'k', L'L', 'i', 'n', 'k', L'\0' };
	BetaFunctionTable->RtlInitUnicodeString(&symbolicLink, __symboliclink);

	tagSTRONGOD tagStrongOD = { 0 };
	tagStrongOD.m_dwFlag = 123456789;
	tagStrongOD.m_dwCressPID = IsEnumProcess();
	tagStrongOD.m_wMePid = (WORD)BetaFunctionTable->GetCurrentProcessId();

	KARMA_MACRO_2
	do {
		ntStatus = BetaFunctionTable->ZwQueryDirectoryObject(hDirectory, buffer, ulLength, TRUE, FALSE, &ulContext, &ulRet);
		if ((ntStatus != STATUS_SUCCESS) && (ntStatus != STATUS_NO_MORE_ENTRIES))
		{
			if (hDirectory != NULL)
				BetaFunctionTable->ZwClose(hDirectory);
		}

		else if (STATUS_NO_MORE_ENTRIES == ntStatus)
		{
			if (hDirectory != NULL)
				BetaFunctionTable->ZwClose(hDirectory);

			return;
		}


		PDIRECTORY_BASIC_INFORMATION  directoryInfo = (PDIRECTORY_BASIC_INFORMATION)buffer;

		WCHAR __link[] = { L'\\', L'\\', L'\\', L'\\', L'.', L'\\', L'\\', L'\0' };
		wcscat(__link, directoryInfo->ObjectName.Buffer);

		KARMA_MACRO_1

		int nLen = wcslen(__link);
		if (nLen > 0xc)
			continue;

		BYTE szControlCode1[MAXBYTE] = { 0 };
		DWORD dwBytesReturned = 0;

		//LPLog->AddLog(0, "Symbol: %ls", szSymbolicLink);

		HANDLE hFile = CreateFileW(__link, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			continue;

		*(PDWORD)&szControlCode1[0] = tagStrongOD.m_dwFlag;
		*(PDWORD)&szControlCode1[4] = tagStrongOD.m_dwCressPID;
		*(PDWORD)&szControlCode1[8] = 1;
		*(PDWORD)&szControlCode1[0xc] = 1;
		*(PDWORD)&szControlCode1[0x10] = 1;
		*(PDWORD)&szControlCode1[0x14] = 1;
		*(PDWORD)&szControlCode1[0x18] = 1;
		*(PDWORD)&szControlCode1[0x1c] = 0;
		*(PWORD)&szControlCode1[0x20] = tagStrongOD.m_wMePid;
		*(PWORD)&szControlCode1[0x22] = 0;

		KARMA_MACRO_2

		BYTE szControlCode2[0x24] = {
			0x42, 0xa3, 0x53, 0x04, 0x4D, 0x4B, 0xA3, 0xC4, 0xEC, 0xF8,
			0xE5, 0x41, 0x9D, 0xEF, 0xAE, 0x46, 0x95, 0x59, 0x7D, 0xF3,
			0x98, 0xBD, 0xDC, 0xD4, 0x1F, 0xE9, 0xC1, 0xD9, 0xFB, 0xF1,
			0xE9, 0x8D, 0x85, 0x0B, 0x7B, 0x14 };

		KARMA_MACRO_2

		BYTE szOutBuffer[0x4] = { 0xff, 0xff, 0xff, 0xff };
		for (int i = 0; i < 0x24; i++)
			szControlCode1[i] ^= szControlCode2[i];


		if (FALSE == DeviceIoControl(hFile, 0x22215c, szControlCode2, 0x24, NULL, 0, &dwBytesReturned, NULL))
		{
			BetaFunctionTable->CloseHandle(hFile);
			continue;
		}

		*(PDWORD)&szControlCode1[0] = tagStrongOD.m_dwFlag;
		*(PDWORD)&szControlCode1[4] = 0;
		*(PDWORD)&szControlCode1[8] = 0;
		*(PDWORD)&szControlCode1[0xc] = 0;
		*(PDWORD)&szControlCode1[0x10] = 0;
		*(PDWORD)&szControlCode1[0x14] = 0;
		*(PDWORD)&szControlCode1[0x18] = 0;
		*(PDWORD)&szControlCode1[0x1c] = 0;
		*(PWORD)&szControlCode1[0x20] = 0;
		*(PWORD)&szControlCode1[0x22] = 0;

		for (i = 0; i < 0x24; i++)
			szControlCode1[i] ^= szControlCode2[i];

		KARMA_MACRO_1

		if (0 != BetaFunctionTable->DeviceIoControl(hFile, 0x222178, szControlCode1, 0x24, NULL, 0, &dwBytesReturned, NULL))
		{
			BetaFunctionTable->CloseHandle(hFile);
			continue;
		}

		*(PDWORD)&szControlCode1[0] = tagStrongOD.m_dwFlag;
		*(PDWORD)&szControlCode1[4] = 0;
		*(PDWORD)&szControlCode1[8] = 0;
		*(PDWORD)&szControlCode1[0xc] = 0;
		*(PDWORD)&szControlCode1[0x10] = 0;
		*(PDWORD)&szControlCode1[0x14] = 0;
		*(PDWORD)&szControlCode1[0x18] = 0;
		*(PDWORD)&szControlCode1[0x1c] = 0;
		*(PWORD)&szControlCode1[0x20] = tagStrongOD.m_wMePid;
		*(PWORD)&szControlCode1[0x22] = 0;

		for (i = 0; i < 0x24; i++)
			szControlCode1[i] ^= szControlCode2[i];

		KARMA_MACRO_2

		if (TRUE == BetaFunctionTable->DeviceIoControl(hFile, 0x222160, szControlCode2, 0x24, szOutBuffer, 0x4, &dwBytesReturned, NULL))
		{
			CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '1', '9', 0x0 }; // Debugger Detected; Err Code: 0x90000019
			LPFunctions->CloseProcess(__warn, true, "");
		}
		else
		{
			BetaFunctionTable->CloseHandle(hFile);
			continue;
		}

	} while (TRUE);


	if (hDirectory)
		BetaFunctionTable->ZwClose(hDirectory);

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0, "Antidebug CheckStrongOD initialization completed!");
#endif
}

void CAntiDebug::CheckSeDebugPriv()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CheckSeDebugPriv initialization has been started!");
#endif

	CHAR __csrssexe[] = { 'c', 's', 'r', 's', 's', '.', 'e', 'x', 'e', 0x0 }; // csrss.exe
	auto dwCsrssPid = LPFunctions->GetProcessIdFromProcessName(__csrssexe);
	if (IsWindowsVistaOrGreater())
		dwCsrssPid = BetaFunctionTable->CsrGetProcessId();

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwCsrssPid);
	if (hProcess) {
		CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '2', '0', 0x0 }; // Debugger Detected; Err Code: 0x90000020
		KARMA_MACRO_2
		LPFunctions->CloseProcess(__warn, true, "");
		KARMA_MACRO_1
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CheckSeDebugPriv initialization completed!");
#endif
}

void CAntiDebug::CloseProtectedHandle()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CloseProtectedHandle initialization has been started!");
#endif

	KARMA_MACRO_1
	CHAR __kernel3[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3',  0x0 }; // kernel3
	KARMA_MACRO_2
	HANDLE hMutex = BetaFunctionTable->CreateMutexA(NULL, FALSE, __kernel3);
	if (hMutex && hMutex != INVALID_HANDLE_VALUE)
	{
		KARMA_MACRO_1
		if (BetaFunctionTable->SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE))
		{
			KARMA_MACRO_2
			__try {
				BetaFunctionTable->CloseHandle(hMutex);
			}

			__except (HANDLE_FLAG_PROTECT_FROM_CLOSE) {
				CHAR __warn[] = { 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', ';', ' ', 'E', 'r', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '0', 'x', '9', '0', '0', '0', '0', '0', '2', '1', 0x0 }; // Debugger Detected; Err Code: 0x90000021
				KARMA_MACRO_2
				LPFunctions->CloseProcess(__warn, true, "");
				KARMA_MACRO_1
			}
		}
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug CloseProtectedHandle initialization completed!");
#endif
}

#pragma data_seg(".bdata1")
DWORD VehintoAddr = 0;
#pragma data_seg()
#pragma comment(linker, "/section:.bdata1,RWS")


LONG NTAPI VehIntoExceptionFilter( PEXCEPTION_POINTERS ExceptionInfo )
{
	ExceptionInfo->ContextRecord->Eip = VehintoAddr;

	return EXCEPTION_CONTINUE_EXECUTION;
}

__forceinline void IsVehIntoBreak()
{
	PVOID VEHandle = ::BetaFunctionTable->AddVectoredExceptionHandler(1, VehIntoExceptionFilter);

	_asm
	{
		mov VehintoAddr, offset Intosafe;
		mov ecx, 1;
	}
here:
	_asm
	{
		rol ecx, 1;
		into;
		jmp here;
	}
Intosafe:

	if (VEHandle != NULL)
		BetaFunctionTable->RemoveVectoredExceptionHandler(VEHandle);
}


void CAntiDebug::VehIntoBreak()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug VehIntoBreak initialization has been started!");
#endif

	KARMA_MACRO_2

	IsVehIntoBreak();

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0,"Antidebug VehIntoBreak initialization completed!");
#endif
}




void CAntiDebug::InitAntiDebug()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anticheat Anti debug initialization has been started!");
#endif

	KARMA_MACRO_1

	DetachFromDebuggerProcess();
	CrashDebugger();
	PebCheck();
	IsDebugger();
	DebugPort();
	AntiSoftice();
	Antisyser();
	CheckCloseHandle();
	RemoteDebugCheck();
	FlagsCheck();
	PrefixCheck();
	Int2DCheck();
	Int3Check();
//#if USE_SHIELDEN_SDK == 0
//	if (LPData->IsPackedProcess() == false)
//		CheckGlobalFlagsClearInProcess();
//#endif
	CheckDebugObjects();
	ThreadBreakOnTerminationCheck();
	//AntiHyperVisor(); // TESTME
	//CheckShareCount(); // does not works correctly
	CloseProtectedHandle();
	VehIntoBreak();

	if (IsWindowsVistaOrGreater())
		SetFakeImageSize();

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Anticheat Anti debug initialization completed!");
#endif
}

#pragma optimize("", on )
