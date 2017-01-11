#include "ProjectMain.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "XOR.h"
#include "ApiHooks.h"
#include "CLog.h"
#include "Scan.h"
#include "DirFuncs.h"
#include "Threads.h"


void WINAPI ClientThreadSetupCallbackChecker()
{
	DWORD dwThreadId = LPThreads->__GetThreadId(NtCurrentThread);
	if (LPThreads->IsSelfThread(dwThreadId))
		return;

	if (LPThreads->IsSuspendedThread(dwThreadId)) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Suspended thread is resumed! TID: %u", LPThreads->__GetThreadId(NtCurrentThread));
#endif
		BetaFunctionTable->ResumeThread(NtCurrentThread);
	}

	DWORD dwCurrentThreadAddress = 0;
	if (!NT_SUCCESS(BetaFunctionTable->NtQueryInformationThread(NtCurrentThread, ThreadQuerySetWin32StartAddress, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), NULL)))
		return;


	char szDosName[2048] = { 0 };
	BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwCurrentThreadAddress, szDosName, 2048);
	auto szFileName = LPFunctions->DosDevicePath2LogicalPath(szDosName);

	auto szLowerFileName = LPFunctions->szLower(szFileName);
	auto wszFileName = LPFunctions->UTF8ToWstring(szLowerFileName);

	auto szProcessName = LPDirFunctions->ExeNameWithPath();
	auto szLowerProcessName = LPFunctions->szLower(szProcessName);

	if (szLowerFileName == szLowerProcessName)
		return;

	char cWarning[4096] = { 0x0 };
	CHAR __warn[] = { 'T', 'h', 'r', 'e', 'a', 'd', ':', ' ', '%', 's', '(', '%', 'u', ')', ' ', '-', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'a', 'd', 'd', 'r', 'e', 's', 's', ':', ' ', '%', 'p', ' ', '-', ' ', 'D', 'e', 't', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', ' ', '-', ' ', 'T', 'y', 'p', 'e', ' ', '2', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!', 0x0 }; // Thread: %s(%u) - Thread address: %p - Detection Type: %d - Type 2 Thread initilization blocked!
	int iBadAddress = CheckCallerAddress(dwCurrentThreadAddress, 1, "");
	if (iBadAddress) {
		sprintf(cWarning, __warn, szFileName.c_str(), dwThreadId, dwCurrentThreadAddress, iBadAddress);
		LPLog->ErrorLog(0, cWarning);
#ifdef SCRENSHOT_FEATURE
		LPFunctions->SendScreenshotToServer();
#endif
		goto block;
	}

	DWORD dwStartAddress2 = LPThreads->GetThreadStartAddress(NtCurrentThread);
	if (dwStartAddress2 && dwStartAddress2 != dwCurrentThreadAddress) { /* spoofed address? */
		sprintf(cWarning, __warn, szFileName.c_str(), dwThreadId, dwCurrentThreadAddress, iBadAddress);
		LPLog->ErrorLog(0, cWarning);
		goto block;
	}

	THREAD_BASIC_INFORMATION ThreadInfo;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationThread(NtCurrentThread, 0, &ThreadInfo, sizeof(ThreadInfo), NULL)))
	{
		DWORD hThreadOwnerPID = (DWORD)ThreadInfo.ClientId.UniqueProcess;
		if (hThreadOwnerPID != BetaFunctionTable->GetCurrentProcessId())
		{
			sprintf(cWarning, __warn, szFileName.c_str(), dwThreadId, dwCurrentThreadAddress, 9997);
			LPLog->ErrorLog(0, cWarning);
			goto block;
		}
	}

	static BOOL bSignRet = FALSE;
	LPScan->IsSignedFile(wszFileName.c_str(), &bSignRet);
	if (bSignRet == FALSE)
	{ /* If not signed module and whitelisted block */
		CHAR __betacoredll[] = { 'b', 'e', 't', 'a', 'c', 'o', 'r', 'e', '.', 'd', 'l', 'l', 0x0 }; // betacore.dll
		CHAR __dinput[] = { 'd', 'i', 'n', 'p', 'u', 't', 0x0 }; // dinput

		if (!strstr(szLowerFileName.c_str(), __betacoredll) && !strstr(szLowerFileName.c_str(), __dinput) &&
			!LPDirFunctions->IsFromWindowsPath(szLowerFileName)) {
			sprintf(cWarning, __warn, szFileName.c_str(), dwThreadId, dwCurrentThreadAddress, 9998);
			LPLog->ErrorLog(0, cWarning);
			goto block;
		}
	}

	return;

block:
#if _DEBUG
	LPLog->AddLog(0, "%s's thread init is blocked. Sign ret: %d Thread id: %u", szLowerFileName.c_str(), bSignRet, LPThreads->__GetThreadId(NtCurrentThread));
	LPFunctions->fMessageBox(0, 0, "", "%s is blocked", szLowerFileName.c_str());
#endif
	BetaFunctionTable->Sleep(INFINITE);
}

// FIXME: Params
void WINAPI ClientLoadLibraryCallbackChecker()
{
	// UNIMPLEMENTED;
}



enum ECallbackTypes {
	ClientThreadSetup,
	ClientLoadLibrary
};

DWORD dwClientThreadSetupOldAddress = 0;
DWORD dwClientLoadLibraryOldAddress = 0;

DWORD* GetCallbackTable()
{
	DWORD * KernelCallbackTable = NULL;
	_asm
	{
		push eax
		mov eax, dword ptr fs : [0x18]
		mov eax, dword ptr ds : [eax + 0x30]
		mov eax, dword ptr ds : [eax + 0x2C]
		mov KernelCallbackTable, eax
		pop eax
	}
	return KernelCallbackTable;
}


DWORD InitHook(int iType, int iCallbackNumber, void* lpCallBack)
{
	auto dwKernelCallbackTable = GetCallbackTable();

	DWORD dwOldProtect = 0;
	if (!BetaFunctionTable->VirtualProtect(&dwKernelCallbackTable[iCallbackNumber], sizeof(PVOID), PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return 0;

	if (iType == ClientThreadSetup)
		dwClientThreadSetupOldAddress = dwKernelCallbackTable[iCallbackNumber];
	else if (iType == ClientLoadLibrary)
		dwClientLoadLibraryOldAddress = dwKernelCallbackTable[iCallbackNumber];

	dwKernelCallbackTable[iCallbackNumber] = (DWORD)lpCallBack;
	return 1;
}


void CSelfApiHooks::InitApfnHooks()
{
	auto KernelCallbackTable = GetCallbackTable();

	auto iClientThreadSetupIndex = 0;
	auto dwClientThreadSetupPattern = 1337;
	auto bCheckedSetupThread = false;

#if 0
	auto iClientLoadLibraryIndex = 0;
	auto dwClientLoadLibraryPattern = 1337;
	auto bCheckedLoadLibrary = false;
#endif

	auto dwMaxNumberAddress = 0;
	auto iMaxNumber = 120;
research:
	for (int i = 0; i < iMaxNumber; i++)
	{
		if (bCheckedSetupThread == true && dwClientThreadSetupPattern != 1337 && dwClientThreadSetupPattern == (DWORD)KernelCallbackTable[i])
			iClientThreadSetupIndex = i;
#if 0
		if (bCheckedLoadLibrary == true && dwClientLoadLibraryPattern != 1337 && dwClientLoadLibraryPattern == (DWORD)KernelCallbackTable[i])
			iClientLoadLibraryIndex = i;
#endif

		if (KernelCallbackTable[i] && i == iMaxNumber)
			dwMaxNumberAddress = KernelCallbackTable[i];

		else if (!dwMaxNumberAddress && i == iMaxNumber)
		{
			for (int x = 0; x < 30; x++)
			{
				if (KernelCallbackTable[i + x]) {
					dwMaxNumberAddress = KernelCallbackTable[i + x];
					break;
				}
			}
			if (iMaxNumber && !dwMaxNumberAddress) {
				iMaxNumber -= 5;
				goto research;
			}
		}
	}
	if (!iMaxNumber)
		return;

	auto dwSize = dwMaxNumberAddress - (DWORD)KernelCallbackTable;


	BYTE byClientThreadSetup[] = { 0xe8, 0xff, 0xff, 0xff, 0xff, 0xf7, 0xd8, 0x1b, 0xc0, 0x25 };
	dwClientThreadSetupPattern = LPFunctions->FindPattern((DWORD)KernelCallbackTable, dwSize, byClientThreadSetup, sizeof(byClientThreadSetup));
	if (dwClientThreadSetupPattern && bCheckedSetupThread == false) {
		bCheckedSetupThread = true;
		goto research;
	}

#if 0
	BYTE byClientLoadLibrary[] = { 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x81, 0xec, 0x24, 0x1, 0x0, 0x0, 0xa1, 0x48, 0xd4 };
	dwClientLoadLibraryPattern = LPFunctions->FindPattern((DWORD)KernelCallbackTable, dwSize, byClientLoadLibrary, sizeof(byClientLoadLibrary));
	if (dwClientLoadLibraryPattern && bCheckedLoadLibrary == false) {
		bCheckedLoadLibrary = true;
		goto research;
	}
#endif

	if (iClientThreadSetupIndex && dwClientThreadSetupPattern)
		InitHook(ClientThreadSetup, iClientThreadSetupIndex, &ClientThreadSetupCallbackChecker);

#if 0
	if (iClientLoadLibraryIndex && dwClientLoadLibraryPattern)
		InitHook(ClientLoadLibrary, iClientLoadLibraryIndex, &ClientLoadLibraryCallbackChecker);
#endif
}

