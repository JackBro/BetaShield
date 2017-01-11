#include "ProjectMain.h"
#include "AntiBreakpoint.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "AntiDebug.h"
#include "Threads.h"
#include "Scan.h"
#include "DirFuncs.h"


DWORD WINAPI AntiThreadEx(LPVOID)
{
#ifndef _DEBUG
	LPAntiDebug->CheckStrongOD();
#endif
	KARMA_MACRO_1
	LPAntiDebug->InitTimeChecks();

	KARMA_MACRO_2
	LPScan->InitializeEventLogCheck();

	while (1)
	{
#ifndef _DEBUG
		LPAntiDebug->DetachFromDebuggerProcess();
		BetaFunctionTable->Sleep(200);

		LPAntiDebug->CheckKernelDebugInformation();
		BetaFunctionTable->Sleep(200);

		LPAntiDebug->CheckCloseHandle();
		BetaFunctionTable->Sleep(200);
#endif

		KARMA_MACRO_2
		CHAR __pchunter[] = { 'P', 'C', ' ', 'H', 'u', 'n', 't', 'e', 'r', ' ', 'S', 't', 'a', 'n', 'd', 'a', 'r', 'd', 'M', 'a', 'd', 'e', 'B', 'y', 'E', 'p', 'o', 'o', 'l', 's', 'o', 'f', 't', 0x0 }; // PC Hunter StandardMadeByEpoolsoft
		CHAR __pchunterwarn[] = { 'I', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ':', ' ', 'P', 'C', ' ', 'H', 'u', 'n', 't', 'e', 'r', 0x0 }; // Illegal process detected: PC Hunter
		HANDLE hEventPCHunter = BetaFunctionTable->OpenEventA(SYNCHRONIZE, FALSE, __pchunter);
		if (hEventPCHunter)
			LPFunctions->CloseProcess(__pchunterwarn, false, "");

		KARMA_MACRO_2
			
		CHAR __BlackBone[] = { '\\', '\\', '.', '\\', 'B', 'l', 'a', 'c', 'k', 'B', 'o', 'n', 'e', 0x0 }; // \.\BlackBone
		CHAR __blackbonewarn[] = { 'I', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ':', ' ', 'B', 'l', 'a', 'c', 'k', 'B', 'o', 'n', 'e', 0x0 }; // Illegal process detected: BlackBone
		if (BetaFunctionTable->CreateFileA(__BlackBone, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0) != INVALID_HANDLE_VALUE)
			LPFunctions->CloseProcess(__blackbonewarn, false, "");


		BetaFunctionTable->Sleep(500);

		KARMA_MACRO_1

#ifndef _DEBUG
		LPAntiBreakpoint->Anti_HardwareBreakpoint();
		BetaFunctionTable->Sleep(200);
		LPAntiBreakpoint->Anti_EntrypointBreakpoint();
		BetaFunctionTable->Sleep(500);
#endif

		LPScan->CheckMemoryWatchdog();
		BetaFunctionTable->Sleep(500);

		LPScan->AntiWow32ReservedHook();
		BetaFunctionTable->Sleep(300);


		LPDirFunctions->MainFolderCheck();
		LPDirFunctions->PackCheck();
		BetaFunctionTable->Sleep(1000);


		LPScan->CheckWindowCount();
		BetaFunctionTable->Sleep(1000);


		LPScan->ScanDNSHistory();
		BetaFunctionTable->Sleep(1000);


		//LPScan->CheckHiddenProcesses(); //revise

		LPThreads->IncreaseThreadTick(8);
		BetaFunctionTable->Sleep(10000);
	}

	return 0;
}


HANDLE CAntiBreakpoint::InitAntiThread()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)AntiThreadEx, 0, 8);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '8', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x8! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti thread creation completed!");
#endif
	return hThread;
}
#pragma optimize("", on )
