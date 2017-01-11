#include "ProjectMain.h"
#include "XOR.h"
#include "Access.h"
#include "DynamicWinapi.h"
#include "Threads.h"
#include "Functions.h"
#include "VersionHelpers.h"

#include "DirFuncs.h"
#include "CLog.h"
#include "Scan.h"


#pragma optimize("", off )
__forceinline bool IsItBadClassName(std::string szLowerClassName)
{
	if (szLowerClassName.empty())
		return false;

	CHAR __edward[] = { 'w', 'i', 'n', 'd', 'o', 'w', 's', 'f', 'o', 'r', 'm', 's', '1', '0', '.', 'w', 'i', 'n', 'd', 'o', 'w', '.', '8', '.', 'a', 'p', 'p', 0x0 }; // WindowsForms10.Window.8.app
	CHAR __treelist[] = { 't', 'r', 'e', 'e', 'l', 'i', 's', 't', 0x0 }; // treelist
	CHAR __eter[] = { 'e', 't', 'e', 'r', ' ', '-', 0x0 }; // eter -
	CHAR __syslistview[] = { 's', 'y', 's', 'l', 'i', 's', 't', 'v', 'i', 'e', 'w', 0x0 }; // syslistview
	CHAR __injector[] = { 'i', 'n', 'j', 'e', 'c', 't', 'o', 'r', 0x0 }; // injector
	CHAR __autoIt[] = { 'a', 'u', 't', 'o', 'I', 't', 0x0 }; // autoIt
	CHAR __njector[] = { 'n', '-', 'j', 'e', 'c', 't', 'o', 'r', 0x0 }; // n-jector
	CHAR __ollydbg[] = { 'o', 'l', 'l', 'y', 'd', 'b', 'g', 0x0 }; // ollydbg
	CHAR __procmon[] = { 'p', 'r', 'o', 'c', 'm', 'o', 'n', 0x0 }; // procmon
	CHAR __processhacker[] = { 'p', 'r', 'o', 'c', 'e', 's', 's', 'h', 'a', 'c', 'k', 'e', 'r', 0x0 }; // processhacker
	CHAR __unhooker[] = { 'u', 'n', 'h', 'o', 'o', 'k', 'e', 'r', 0x0 }; // unhooker
	CHAR __windbg[] = { 'w', 'i', 'n', 'd', 'b', 'g', 0x0 }; // windbg
	CHAR __debugger[] = { 'd', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 0x0 }; // debugger
	CHAR __idawindow[] = { 'i', 'd', 'a', 'w', 'i', 'n', 'd', 'o', 'w', 0x0 }; // idawindow
	CHAR __autohotkeygui[] = { 'a', 'u', 't', 'o', 'h', 'o', 't', 'k', 'e', 'y', 'g', 'u', 'i', 0x0 }; // autohotkeygui
	CHAR __TSearchClientClass[] = { 'T', 'S', 'e', 'a', 'r', 'c', 'h', '.', 'C', 'l', 'i', 'e', 'n', 't', 'C', 'l', 'a', 's', 's', 0x0 }; // TSearch.ClientClass
	CHAR __DDEMLMom[] = { 'D', 'D', 'E', 'M', 'L', 'M', 'o', 'm', 0x0 }; // DDEMLMom
	CHAR __Calc[] = { 'C', 'a', 'l', 'c', 0x0 }; // Calc - aka. MHS Memory editor

	return (
		strstr(szLowerClassName.c_str(), __edward) || strstr(szLowerClassName.c_str(), __treelist) || /* strstr(szLowerClassName.c_str(), __eter) ||  */
		strstr(szLowerClassName.c_str(), __syslistview) || strstr(szLowerClassName.c_str(), __injector) || strstr(szLowerClassName.c_str(), __autoIt) ||
		strstr(szLowerClassName.c_str(), __njector) || strstr(szLowerClassName.c_str(), __ollydbg) || strstr(szLowerClassName.c_str(), __procmon) ||
		strstr(szLowerClassName.c_str(), __processhacker) || strstr(szLowerClassName.c_str(), __unhooker) || strstr(szLowerClassName.c_str(), __windbg) ||
		strstr(szLowerClassName.c_str(), __debugger) || strstr(szLowerClassName.c_str(), __idawindow) || strstr(szLowerClassName.c_str(), __autohotkeygui) ||
		strstr(szLowerClassName.c_str(), __TSearchClientClass) || strstr(szLowerClassName.c_str(), __DDEMLMom) || strstr(szLowerClassName.c_str(), __Calc)
	);
}

inline void CheckClassNames(DWORD dwProcessId)
{
	HWND hWnd = 0;

	KARMA_MACRO_2
	do
	{
		KARMA_MACRO_1
		hWnd = BetaFunctionTable->FindWindowExA(NULL, hWnd, NULL, NULL);

		DWORD dwPID = 0;
		BetaFunctionTable->GetWindowThreadProcessId(hWnd, &dwPID);
		KARMA_MACRO_1

		if (dwPID == dwProcessId)
		{
			char szClass[MAX_PATH] = { 0x0 };
			BetaFunctionTable->GetClassNameA(hWnd, szClass, MAX_PATH);

			std::string szLowerClassName = szClass;
			transform(szLowerClassName.begin(), szLowerClassName.end(), szLowerClassName.begin(), tolower);

			if (IsItBadClassName(szLowerClassName))
			{
				char szTitle[MAX_PATH] = { 0x0 };
				BetaFunctionTable->GetWindowTextA(hWnd, szTitle, MAX_PATH);

				char szRealWarn[1024];
				CHAR __warn[] = { 'I', 'n', 'c', 'o', 'm', 'p', 'a', 't', 'i', 'b', 'l', 'e', ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'o', 's', 'e', ' ', '%', 's', '[', 'P', 'i', 'd', ':', ' ', '%', 'u', ']', 0x0 }; // Incompatible applications detected. Please close %s[Pid: %u]
				sprintf(szRealWarn, __warn, szTitle, dwProcessId);

				CFunctions lpFuncs;
				lpFuncs.CloseProcess(szRealWarn, false, "");
			}
		}
	} while (hWnd);
}


std::vector<DWORD> vWhiteList;
inline void BlockOpenedHandles()
{
	KARMA_MACRO_2
	ULONG handleInfoSize = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = 0;
	HANDLE processHandle = 0;
	NTSTATUS status = 0;

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	ZeroMemory(handleInfo, handleInfoSize);

	while ((status = BetaFunctionTable->NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		handleInfoSize *= 2;
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
	}

	if (!NT_SUCCESS(status)) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "BlockOpenedHandles; NtQuerySystemInformation failed! Error code: %u Ntstatus: %u", LPWinapi->LastError(), status);
#endif
		free(handleInfo);
		return;
	}

	for (ULONG i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		
		if (handle.ProcessId == BetaFunctionTable->GetCurrentProcessId()) /* Itself */
			continue;


		//todo: check duplicated handles(0x32)
		//todo: file handles
		//todo: thread handles
		if (handle.ObjectTypeNumber == 0x7 /* Process handle type in XP+ */ || handle.ObjectTypeNumber == 0x5 /* Process handle type in XP */)
		{

			if (handle.ProcessId < 5) /* System */
				continue;

			if (processHandle)
				BetaFunctionTable->CloseHandle(processHandle); // If have a handle before than last loop, clear it.


			processHandle = BetaFunctionTable->OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);
			if (!processHandle)
			{
				//#ifdef _DEBUG
				//			LPLog->ErrorLog(0, "BlockOpenedHandles; OpenProcess failed! Error code: %u Target: %u", LPWinapi->LastError(), handle.ProcessId);
				//#endif
				continue;
			}

			status = BetaFunctionTable->NtDuplicateObject(processHandle, (HANDLE)handle.Handle, NtCurrentProcess, &dupHandle, PROCESS_QUERY_INFORMATION, 0, 0);
			if (!NT_SUCCESS(status))
			{
				//#ifdef _DEBUG
				//			LPLog->ErrorLog(0, "BlockOpenedHandles; NtDuplicateObject failed! Error code: %u Target: %u", LPWinapi->LastError(), handle.ProcessId);
				//#endif
				if (processHandle)
					BetaFunctionTable->CloseHandle(processHandle);

				continue;
			}

			if (IsWindowsXPSP1OrGreater() && BetaFunctionTable->GetProcessId(dupHandle) == BetaFunctionTable->GetCurrentProcessId()) /* If handle target is game process */
			{
				if (std::find(vWhiteList.begin(), vWhiteList.end(), handle.ProcessId) != vWhiteList.end()) { /* If whitelisted target process */
					if (processHandle)
						BetaFunctionTable->CloseHandle(processHandle);

					continue;
				}

#ifdef _DEBUG
				LPLog->AddLog(0, "Access detected to game! Checking... [%u]", (DWORD)handle.ProcessId);
#endif


				auto hTargetProc = BetaFunctionTable->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)handle.ProcessId);
				if (!hTargetProc) {
					char szWarn[2048];
					sprintf(szWarn, XOR("Unknown access to process from: %u"), (DWORD)handle.ProcessId);
					LPFunctions->CloseProcess(szWarn, false, "");
				}

				auto dosName = LPFunctions->GetProcessFullName(hTargetProc);
				auto szLowerTargetProcess = LPFunctions->DosDevicePath2LogicalPath(dosName.c_str());
				if (szLowerTargetProcess.empty()) {
#ifdef _DEBUG
					LPLog->ErrorLog(0, "BlockOpenedHandles; DosDevicePath2LogicalPath dosName: %s", dosName.c_str());
#endif
					continue;
					//	szLowerTargetProcess = LPFunctions->GetProcessFileName((DWORD)handle.ProcessId);
				}
				transform(szLowerTargetProcess.begin(), szLowerTargetProcess.end(), szLowerTargetProcess.begin(), tolower);
				auto wszLowerTargetProcess = LPFunctions->UTF8ToWstring(szLowerTargetProcess);

				BetaFunctionTable->CloseHandle(hTargetProc);

#ifdef _DEBUG
				LPLog->AddLog(0, "Access owner: %s [%u]...", szLowerTargetProcess.c_str(), (DWORD)handle.ProcessId);
#endif

				auto bConsoleAllowed = false;
#ifdef _DEBUG
				CHAR __conhostexe[] = { 'c', 'o', 'n', 'h', 'o', 's', 't', '.', 'e', 'x', 'e', 0x0 }; // conhost.exe
				if (strstr(szLowerTargetProcess.c_str(), __conhostexe))
					bConsoleAllowed = true;
#else
				if (LPData->GetGameCode() == TEST_CONSOLE)
					bConsoleAllowed = true;
#endif
				if (bConsoleAllowed) {
#ifdef _DEBUG
					LPLog->AddLog(0, XOR("Console access passed... [%u]"), (DWORD)handle.ProcessId);
#endif
					vWhiteList.push_back((DWORD)handle.ProcessId);

					if (processHandle)
						BetaFunctionTable->CloseHandle(processHandle);

					continue;
				}


				auto szWinPath = LPDirFunctions->WinPath();
				auto szLowerWinPath = LPFunctions->szLower(szWinPath);

				auto szExeNameWithPath = LPDirFunctions->ExeNameWithPath();
				transform(szExeNameWithPath.begin(), szExeNameWithPath.end(), szExeNameWithPath.begin(), tolower);


				auto bIsCsrssPid = IsWindowsVistaOrGreater() ? BetaFunctionTable->CsrGetProcessId() == (DWORD)handle.ProcessId : false;
				auto bIsFromWindows = LPDirFunctions->IsFromWindowsPath(szLowerTargetProcess);
				auto bIsCsrss = (!IsWindowsVistaOrGreater() && strstr(szLowerTargetProcess.c_str(), XOR("csrss.exe")));

				/// System applications
				auto bParentIsServices = LPFunctions->GetProcessIdFromProcessName(XOR("services.exe")) == LPFunctions->GetProcessParentProcessId((DWORD)handle.ProcessId);
				/// Lsass
				auto bParentIsWinInit = LPFunctions->GetProcessIdFromProcessName(XOR("wininit.exe")) == LPFunctions->GetProcessParentProcessId((DWORD)handle.ProcessId);
				/// Conhost(bsod problem in win7)
				auto bParentIsCsrss = LPFunctions->GetProcessIdFromProcessName(XOR("csrss.exe")) == LPFunctions->GetProcessParentProcessId((DWORD)handle.ProcessId);


				if (bParentIsServices || bParentIsWinInit || bParentIsCsrss || bIsCsrssPid || bIsCsrss)
				{
#ifdef _DEBUG
					LPLog->AddLog(0, "High level access passed... %s[%u]", szLowerTargetProcess.c_str(), (DWORD)handle.ProcessId);
#endif
					vWhiteList.push_back((DWORD)handle.ProcessId);

					if (processHandle)
						BetaFunctionTable->CloseHandle(processHandle);

					continue;
				}

				CHAR __svchostexe[] = { 's', 'v', 'c', 'h', 'o', 's', 't', '.', 'e', 'x', 'e', 0x0 }; // svchost.exe
				CHAR __lsassexe[] = { 'l', 's', 'a', 's', 's', '.', 'e', 'x', 'e', 0x0 }; // lsass.exe
				if (bIsFromWindows &&
					(strstr(szLowerTargetProcess.c_str(), __lsassexe) || strstr(szLowerTargetProcess.c_str(), __svchostexe))
					)
				{
#ifdef _DEBUG
					LPLog->AddLog(0, "High level access2 passed... %s[%u]", szLowerTargetProcess.c_str(), (DWORD)handle.ProcessId);
#endif
					vWhiteList.push_back((DWORD)handle.ProcessId);

					if (processHandle)
						BetaFunctionTable->CloseHandle(processHandle);

					continue;
				}


				CHAR __sndvolexe[] = { 's', 'n', 'd', 'v', 'o', 'l', '.', 'e', 'x', 'e', 0x0 }; // sndvol.exe
				CHAR __audiodgexe[] = { 'a', 'u', 'd', 'i', 'o', 'd', 'g', '.', 'e', 'x', 'e', 0x0 }; // audiodg.exe
				if (strstr(szLowerTargetProcess.c_str(), szLowerWinPath.c_str()))
				{
					if (strstr(szLowerTargetProcess.c_str(), __sndvolexe) || strstr(szLowerTargetProcess.c_str(), __audiodgexe))
					{
#ifdef _DEBUG
						LPLog->AddLog(0, "Sound access passed... %s[%u]", szLowerTargetProcess.c_str(), (DWORD)handle.ProcessId);
#endif
						vWhiteList.push_back((DWORD)handle.ProcessId);

						if (processHandle)
							BetaFunctionTable->CloseHandle(processHandle);

						continue;
					}
				}


				if (!strcmp(szLowerTargetProcess.c_str(), szExeNameWithPath.c_str())) {
#ifdef _DEBUG
					LPLog->AddLog(0, "Himself access from another game client passed... [%u]", (DWORD)handle.ProcessId);
#endif
					vWhiteList.push_back((DWORD)handle.ProcessId);

					if (processHandle)
						BetaFunctionTable->CloseHandle(processHandle);

					continue;
				}

#ifdef _DEBUG
				if (strstr(szLowerTargetProcess.c_str(), "devenv.exe")) {
					LPLog->AddLog(0, "Visual studio debugger access passed... [%u]", (DWORD)handle.ProcessId);
					vWhiteList.push_back((DWORD)handle.ProcessId);

					if (processHandle)
						BetaFunctionTable->CloseHandle(processHandle);

					continue;
				}
#endif

#ifdef _DEBUG
				LPLog->AddLog(0, "ERROR! Remote Access Detected. Process %s(%u) TYPE[0x%X] HANDLE[0x%X]", szLowerTargetProcess.c_str(), (DWORD)handle.ProcessId, handle.ObjectTypeNumber, handle.Handle);
#endif

				CHAR __warnwname[] = { 'I', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'a', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 't', 'o', ' ', 'g', 'a', 'm', 'e', '!', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', ':', ' ', '%', 's', '[', '%', 'u', ']', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'd', '!', 0x0 }; // Illegal access detected to game! Process: %s[%u] terminated!
				LPLog->ErrorLog(0, XOR(__warnwname), szLowerTargetProcess.c_str(), (DWORD)handle.ProcessId);


				BetaFunctionTable->NtDuplicateObject(processHandle, (HANDLE)handle.Handle, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);

#ifdef _DEBUG
				LPLog->AddLog(0, "Remote handle terminated!");
#endif

				CheckClassNames((DWORD)handle.ProcessId);


				BetaFunctionTable->WinStationTerminateProcess(NULL, (DWORD)handle.ProcessId, DBG_TERMINATE_PROCESS);
				if (LPFunctions->ProcessIsItAlive((DWORD)handle.ProcessId)) {
					HWND hwTargetWindow = LPFunctions->FindWindowFromProcessId((DWORD)handle.ProcessId);
					BetaFunctionTable->EndTask(hwTargetWindow, FALSE, TRUE);
				}
			}
		}

		BetaFunctionTable->CloseHandle(dupHandle);
		// BetaFunctionTable->Sleep(3);
	}

	free(handleInfo);
	BetaFunctionTable->CloseHandle(processHandle);

	KARMA_MACRO_1
#ifdef _DEBUG
	LPLog->AddLog(0, "Handle Access control checked!");
#endif
}


DWORD WINAPI InitializeBlockHandles(LPVOID)
{
	KARMA_MACRO_1
	while (1)
	{
		if (LPAccess->EnableDebugPrivileges() == false) {
			char szWarn[1024];
			sprintf(szWarn, XOR("Process access adjustion failed! Error: %u"), LPWinapi->LastError());
			LPFunctions->CloseProcess(szWarn, false, "");
		}

		BlockOpenedHandles();
		KARMA_MACRO_1

		LPThreads->IncreaseThreadTick(1);
		BetaFunctionTable->Sleep(5000);
	}

	return 0;
}

HANDLE CAccess::InitBlockHandles()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Access blocker thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)InitializeBlockHandles, 0, 1);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x1! */
		LPFunctions->CloseProcess(__warn, false, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Access blocker thread creation completed!");
#endif
	KARMA_MACRO_2

	return hThread;
}

