#include "ProjectMain.h"
#include "XOR.h"
#include "Access.h"
#include "DynamicWinapi.h"
#include "Threads.h"
#include "Functions.h"
#include "DirFuncs.h"
#include "CLog.h"
#include "VersionHelpers.h"


BOOLEAN SetTokenPrivilege(HANDLE TokenHandle, PWSTR PrivilegeName, PLUID PrivilegeLuid, ULONG Attributes)
{
	TOKEN_PRIVILEGES privileges;
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Attributes = Attributes;
	privileges.Privileges[0].Luid = *PrivilegeLuid;

	NTSTATUS ntStat = BetaFunctionTable->NtAdjustPrivilegesToken(TokenHandle, FALSE, &privileges, 0, NULL, NULL);

	if (!NT_SUCCESS(ntStat))
		return FALSE;

	if (ntStat == STATUS_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

__forceinline bool DecreasePrivilege(HANDLE hProcess)
{
	__try {
		HANDLE hToken;
		if (!NT_SUCCESS(BetaFunctionTable->NtOpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)))
			return false;

		LUID luid;
		if (!BetaFunctionTable->LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
			BetaFunctionTable->CloseHandle(hToken);
			return false;
		}

		if (SetTokenPrivilege(hToken, NULL, &luid, SE_PRIVILEGE_REMOVED)) {
			BetaFunctionTable->CloseHandle(hToken);
			return true;
		}

		BetaFunctionTable->CloseHandle(hToken);
	}
	__except(1){
	}
	return true;
}

std::vector<DWORD> vBlockedProcesses;
std::vector<DWORD> vUnopenedProcesses;
void DenyAccessLoopedProcess(DWORD dwProcessId, HANDLE hProcess)
{
	if (std::find(vUnopenedProcesses.begin(), vUnopenedProcesses.end(), dwProcessId) != vUnopenedProcesses.end())
		return;

	if (std::find(vBlockedProcesses.begin(), vBlockedProcesses.end(), dwProcessId) != vBlockedProcesses.end())
		return;

	std::string szProcessName = LPFunctions->GetProcessFullName(hProcess);
	if (szProcessName.empty() == false)
	{
		std::string szRealProcessName = LPFunctions->DosDevicePath2LogicalPath(szProcessName.c_str());
		std::string szLowerProcessName = LPFunctions->szLower(szRealProcessName);

		std::string szExeNameWithPath = LPDirFunctions->ExeNameWithPath();
		std::string szLowerExeNameWithPath = LPFunctions->szLower(szExeNameWithPath);

		if (!strcmp(szLowerProcessName.c_str(), szLowerExeNameWithPath.c_str())) {
#ifdef _DEBUG
			LPLog->AddLog(0, "Itself access adjust passed! %u", dwProcessId);
#endif
			vBlockedProcesses.push_back(dwProcessId);
			return;
		}

#ifdef _DEBUG
		if (strstr(szProcessName.c_str(), "conhost.exe") && LPData->GetGameCode() == TEST_CONSOLE) {
			LPLog->AddLog(0, "Console access adjust passed! %u", dwProcessId);
			vBlockedProcesses.push_back(dwProcessId);
			return;
		}
#endif
	}

	if (DecreasePrivilege(hProcess) == false) {
//		printf("Access adjust fail: %u\n", dwProcessId);
		vUnopenedProcesses.push_back(dwProcessId);
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Access rules adjusted on: %u", dwProcessId);
#endif
	vBlockedProcesses.push_back(dwProcessId);
}



std::vector<HANDLE> vHandleList;
void CloseHandles()
{
	for (size_t iLoop = 0; iLoop < vHandleList.size(); iLoop++)
	{
		__try { BetaFunctionTable->CloseHandle(vHandleList[iLoop]); }
		__except (1) { }
	}
	vHandleList.clear();
}
void NativeProcessEnumerator()
{
	if (!IsWindowsVistaOrGreater() || !BetaFunctionTable->NtGetNextProcess)
	{
		DWORD aProcesses[1024], cbNeeded;
		if (!BetaFunctionTable->EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
			CHAR enumwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '5', 0x0 }; // Fatal Error on process initilization! Error code: 5
			LPFunctions->CloseProcess(enumwarn, false, "");
		}

		for (unsigned int i = 0; i < cbNeeded / sizeof(DWORD); i++)
		{
			if (aProcesses[i] != 0 && aProcesses[i] != BetaFunctionTable->GetCurrentProcessId())
			{
				HANDLE hProcess = BetaFunctionTable->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, aProcesses[i]);
				if (!hProcess) 
					continue;

				DenyAccessLoopedProcess(aProcesses[i], hProcess);
				vHandleList.push_back(hProcess);
			}
		}
	}
	else {
		HANDLE hCurr = nullptr;
		while (BetaFunctionTable->NtGetNextProcess(hCurr, MAXIMUM_ALLOWED, 0, 0, &hCurr) == STATUS_SUCCESS)
		{
			DWORD dwPid = LPFunctions->GetProcessIdNative(hCurr);
			DenyAccessLoopedProcess(dwPid, hCurr);
			vHandleList.push_back(hCurr);
		}

		CloseHandles();
	}
}

DWORD WINAPI AdjustPrivilegeWorkerThread(LPVOID)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Process Worker started!");
#endif
	while (1)
	{
		if (LPAccess->EnableDebugPrivileges() == false) {
			char szWarn[1024];
			sprintf(szWarn, XOR("Process access adjustion2 failed! Error: %u"), LPWinapi->LastError());
			LPFunctions->CloseProcess(szWarn, false, "");
		}

		NativeProcessEnumerator();

#ifdef _DEBUG
		LPLog->AddLog(0, "Adjust privileges checked!");
#endif

		LPThreads->IncreaseThreadTick(2);
		BetaFunctionTable->Sleep(5000);
	}

	return 0;
}

HANDLE CAccess::InitAdjustPrivThread()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Adjust Privilege thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)AdjustPrivilegeWorkerThread, 0, 2);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '2', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x2! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Adjust Privilege thread creation completed!");
#endif
	return hThread;
}
