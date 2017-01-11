#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "CLog.h"
#include "VersionHelpers.h"



struct ProcInfo {
	HWND hWnd;
	DWORD dwProcId;
	CHAR szTitle[255];
	CHAR szClass[255];
};
void CScan::CheckHiddenProcesses()
{
	HWND hWnd;
	DWORD dwProcId;

	ProcInfo mProc[255];
	int mIdList[255];

	int nCount = 0;
	int nPID = 0;
	int i = 0;

	hWnd = FindWindowA(0, 0);
	while (hWnd > 0)
	{
		if (GetParent(hWnd) == 0)
		{
			GetWindowThreadProcessId(hWnd, &dwProcId);


			if (!OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcId))
			{
				mProc[nCount].hWnd = hWnd;
				mProc[nCount].dwProcId = dwProcId;

				GetWindowTextA(hWnd, mProc[nCount].szTitle, 255);
				GetClassNameA(hWnd, mProc[nCount].szClass, 255);
				nCount++;

				for (i = 0; i < nPID; i++)
					if (dwProcId == mIdList[i])
						break;

				if (i == nPID)
					mIdList[nPID++] = dwProcId;
			}
		}
		hWnd = GetWindow(hWnd, GW_HWNDNEXT);
	}


	if (nCount <= 0)
		return;
	
	for (i = 0; i < nCount; i++)
	{
		if (IsWindow(mProc[i].hWnd) == FALSE)
			continue;
		
		if (IsWindowVisible(mProc[i].hWnd) == FALSE)
			continue;

		if (mProc[i].dwProcId != GetCurrentProcessId())
		{
			CHAR __closestart[] = { 'H', 'i', 'd', 'd', 'e', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ':', ' ', '%', 's', '|', '%', 's', '(', '%', 'u', ')', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'i', 'n', 'g', '!', 0x0 }; // Hidden process: %s|%s(%u) terminating!
			CHAR __notclosed[] = { 'H', 'i', 'd', 'd', 'e', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'd', '!', 0x0 }; // Hidden process can not terminated!

			LPLog->ErrorLog(0, __closestart,
				mProc[i].szClass, mProc[i].szTitle, mProc[i].dwProcId);

			BetaFunctionTable->WinStationTerminateProcess(NULL, mProc[i].dwProcId, DBG_TERMINATE_PROCESS);
			BetaFunctionTable->EndTask(mProc[i].hWnd, FALSE, TRUE);
			BetaFunctionTable->Sleep(100);

			if (LPFunctions->ProcessIsItAlive(mProc[i].dwProcId))
				LPFunctions->CloseProcess(__notclosed, false, "");
		}
	}
}



#if 0
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004
BOOL IsProcessFound(DWORD dwProcessId, PSYSTEM_PROCESS_INFORMATION pInfos)
{
	PSYSTEM_PROCESS_INFORMATION pCurrent = pInfos;

	while (TRUE) {
		if ((DWORD)pCurrent->UniqueProcessId == dwProcessId)
			return TRUE;

		if (pCurrent->NextEntryOffset == 0)
			break;
		pCurrent = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pCurrent + pCurrent->NextEntryOffset);
	}

	return FALSE;
}

void CScan::CheckHiddenProcesses()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Check hidden process event has been started");
#endif

	DWORD dwLen = sizeof(SYSTEM_PROCESS_INFORMATION);
	PSYSTEM_PROCESS_INFORMATION pProcessInfos = (PSYSTEM_PROCESS_INFORMATION)malloc(dwLen);

	while (pProcessInfos) {
		NTSTATUS status = BetaFunctionTable->NtQuerySystemInformation(SystemProcessInformation, pProcessInfos, dwLen, &dwLen);
		if (NT_SUCCESS(status))
			break;

		else if (status != STATUS_INFO_LENGTH_MISMATCH) {
			free(pProcessInfos);
			return;
		}

		free(pProcessInfos);
		pProcessInfos = (PSYSTEM_PROCESS_INFORMATION)malloc(dwLen);
	}

	if (!pProcessInfos)
		return;


	dwLen = sizeof(SYSTEM_HANDLE_INFORMATION);
	PSYSTEM_HANDLE_INFORMATION pHandleInfos = (PSYSTEM_HANDLE_INFORMATION)malloc(dwLen);

	while (pHandleInfos) {
		NTSTATUS status = BetaFunctionTable->NtQuerySystemInformation(SystemHandleInformation, pHandleInfos, dwLen, &dwLen);
		if (NT_SUCCESS(status))
			break;

		else if (status != STATUS_INFO_LENGTH_MISMATCH) {
			free(pHandleInfos);
			return;
		}

		free(pHandleInfos);
		pHandleInfos = (PSYSTEM_HANDLE_INFORMATION)malloc(dwLen);
	}

	if (!pHandleInfos)
		return;


	POBJECT_TYPE_INFORMATION pType = (POBJECT_TYPE_INFORMATION)malloc(4096);
	if (!pType) {
		free(pHandleInfos);
		free(pProcessInfos);
		return;
	}

	for (ULONG i = 0; i < pHandleInfos->HandleCount; i++) {
		DWORD dwOwner = pHandleInfos->Handles[i].ProcessId;
		HANDLE hHandle = (HANDLE)pHandleInfos->Handles[i].Handle;

		HANDLE hOwner = BetaFunctionTable->OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwOwner);
		if (hOwner == NULL)
			continue;

		// we duplicate the handle so we can query it 
		HANDLE hHandleLocal = NULL;
		NTSTATUS status = BetaFunctionTable->NtDuplicateObject(hOwner, hHandle, GetCurrentProcess(), &hHandleLocal, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES);
		if (!NT_SUCCESS(status))
			continue;

		status = BetaFunctionTable->NtQueryObject(hHandleLocal, ObjectTypeInformation, pType, 4096, NULL);
		if (!NT_SUCCESS(status))
			continue;

		WCHAR __process[] = { L'P', L'r', L'o', L'c', L'e', L's', L's', L'\0' }; // Process
		if (pType->TypeName.Buffer && wcscmp(pType->TypeName.Buffer, __process) == 0)
		{
			DWORD dwProcessId = LPFunctions->GetProcessIdNative(hHandleLocal);
			if (!IsProcessFound(dwProcessId, pProcessInfos))
			{
				std::string szProcessName = LPFunctions->GetProcessFullName(hHandleLocal);
				std::string szRealName = LPFunctions->DosDevicePath2LogicalPath(szProcessName.c_str());
				HWND hwTargetWindow = LPFunctions->FindWindowFromProcessId(dwProcessId);

				//CHAR __conhostexe[] = { 'c', 'o', 'n', 'h', 'o', 's', 't', '.', 'e', 'x', 'e', 0x0 }; // conhost.exe
				//if (LPData->GetGameCode() == TEST_CONSOLE && strstr(szRealName.c_str(), __conhostexe))
				//	continue;

				CHAR __closestart[] = { 'H', 'i', 'd', 'd', 'e', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ':', ' ', '%', 's', '(', '%', 'u', ')', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'i', 'n', 'g', '!', 0x0 }; // Hidden process: %s(%u) terminating!
				//CHAR __notclosed[] = { 'H', 'i', 'd', 'd', 'e', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'd', '!', 0x0 }; // Hidden process can not terminated!

				LPLog->ErrorLog(0, __closestart, szRealName.empty() ? "None" : szRealName.c_str(), dwProcessId);
				//BetaFunctionTable->WinStationTerminateProcess(NULL, dwProcessId, DBG_TERMINATE_PROCESS);
				//BetaFunctionTable->EndTask(hwTargetWindow, FALSE, TRUE);
				//BetaFunctionTable->NtTerminateProcess(hHandleLocal, 0);
				//BetaFunctionTable->Sleep(100);

				//if (LPFunctions->ProcessIsItAlive(dwProcessId))
				//	LPFunctions->CloseProcess(__notclosed, false, "");
			}
		}
		BetaFunctionTable->CloseHandle(hOwner);
	}

	free(pType);
	free(pHandleInfos);
	free(pProcessInfos);

	LPLog->AddLog(0, "Check hidden process event completed!");
}
#endif
