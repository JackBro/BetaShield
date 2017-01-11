#include "ProjectMain.h"
#include "WatchDog.h"
#include "DynamicWinapi.h"

#include "Timer.h"
#include "Functions.h"
#include "Threads.h"
#include "Main.h"
#include "XOR.h"
#include "Utils.h"
#include "DirFuncs.h"
#include "ApiHooks.h"
#include "XOR.h"
#include "Data.h"
#include "CLog.h"
#include <map>


#pragma optimize("", off )
bool bInitialized = false;
CTimer<std::chrono::milliseconds> watchdogTimer;
CTimer<std::chrono::milliseconds> tickCheckTimer;
std::map<HWND, WNDPROC> mWindowBackupMap;

#ifdef _DEBUG
int iWatchDogCheckCount = 0;
#endif
#pragma optimize("", on )

CWatchdog* LPWatchdog;
CWatchdog::CWatchdog()
{
}

CWatchdog::~CWatchdog()
{
}

size_t CWatchdog::GetWatchdogCount() {
	return mWindowBackupMap.size();
}
bool CWatchdog::IsWatchdogWindow(HWND hWnd) {
	return mWindowBackupMap.find(hWnd) != mWindowBackupMap.end();
}

LRESULT CALLBACK HookWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (watchdogTimer.diff() > 5000)
	{
#ifdef _DEBUG
		char cTmpString1[512];
		sprintf(cTmpString1, "Watchdog event called [%d] - Window: 0x%X Proc: 0x%X", iWatchDogCheckCount, hWnd, mWindowBackupMap[hWnd]);
		LPLog->AddLog(0, cTmpString1);
#endif

		KARMA_MACRO_1
		__try {
			LPThreads->AntiThreadSuspend(LPThreads->GetThreadCheckThreadHandle());
			LPThreads->AntiThreadKill(LPThreads->GetThreadCheckThreadHandle());
			LPThreads->CheckThreadPriority(LPThreads->GetThreadCheckThreadHandle());

			LPThreads->CheckThreadStates(true);
		}
		__except (1) {
		}
		KARMA_MACRO_1

#ifdef _DEBUG
		char cTmpString2[512];
		sprintf(cTmpString2, "Watchdog event succesfully completed [%d] - Window: 0x%X Proc: 0x%X", iWatchDogCheckCount, hWnd, mWindowBackupMap[hWnd]);
		LPLog->AddLog(0,cTmpString2);

		iWatchDogCheckCount++;
#endif

		CUtils lpUtils;
		if (lpUtils.IsFlaggedForExit()) {
			CHAR __warnflg[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 's', 'e', 'l', 'f', ' ', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '.', 0x0 }; // ERROR! Anticheat self integrity failed.

			LPLog->AddLog(0,__warnflg);
			lpUtils.Close();
			while (1); while (1);
		}
		KARMA_MACRO_2

		// Reset timer
		watchdogTimer.reset();

		KARMA_MACRO_1
		if (tickCheckTimer.diff() > 60000)
		{
			LPThreads->CheckTickCheckerThreadIntegrity();

			tickCheckTimer.reset();
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "Watchdog timer cleaned.");
#endif
	}
	return BetaFunctionTable->CallWindowProcA(mWindowBackupMap[hWnd], hWnd, uMsg, wParam, lParam);
}

bool bFirstLoadWatchdog = true;
inline void LoadWatchdog()
{
	int iAttemptCount = 0;

	HWND hWnd = NULL;
	LONG_PTR lptrResult;
	LONG_PTR lptrResult2;
	WNDPROC lpOldProc;
	char szLastClass[MAX_PATH] = { 0x0 };

	if (LPData->GetGameCode() == TEST_CONSOLE)
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "Watchdog creation has been passed on test console!");
#endif
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Watchdog creation has been started!");
#endif

	watchdogTimer.reset();
	tickCheckTimer.reset();

research:
	KARMA_MACRO_1
	do
	{
		hWnd = BetaFunctionTable->FindWindowExA(NULL, hWnd, NULL, NULL);
		KARMA_MACRO_2

		DWORD dwPID = 0;
		DWORD dwThreadId = BetaFunctionTable->GetWindowThreadProcessId(hWnd, &dwPID);

		if (dwPID != BetaFunctionTable->GetCurrentProcessId())
			continue;

		if (dwThreadId == BetaFunctionTable->GetCurrentThreadId())
			continue;

		if (BetaFunctionTable->IsWindowVisible(hWnd) == FALSE)
			continue;

#ifdef _DEBUG
		char szTitle[MAX_PATH] = { 0 };
		BetaFunctionTable->GetWindowTextA(hWnd, szTitle, MAX_PATH);
		if (strstr(szTitle, "Debug console"))
			continue;
#endif

		lptrResult = BetaFunctionTable->GetWindowLongA(hWnd, GWL_WNDPROC);
		if (lptrResult && mWindowBackupMap.find(hWnd) != mWindowBackupMap.end() && mWindowBackupMap[hWnd] == HookWndProc)
			continue;

		if (lptrResult && lptrResult != (LONG_PTR)HookWndProc)
		{
			lpOldProc = (WNDPROC)BetaFunctionTable->SetWindowLongA(hWnd, GWL_WNDPROC, (LONG_PTR)HookWndProc);
			mWindowBackupMap.insert({ hWnd, lpOldProc });

#ifdef _DEBUG
			char szTitle[MAX_PATH] = { 0 };
			BetaFunctionTable->GetWindowTextA(hWnd, szTitle, MAX_PATH);
			LPLog->AddLog(0,"Watchdog successfully created on: %s|%p", szTitle, hWnd);
#endif
		}

		lptrResult2 = BetaFunctionTable->GetWindowLongA(hWnd, GWL_WNDPROC);
		if (lptrResult2 && lptrResult2 != (LONG_PTR)HookWndProc)
		{
#ifdef _DEBUG
			DWORD dwLastError = LPWinapi->LastError();
			char szTitle[MAX_PATH] = { 0 };
			BetaFunctionTable->GetWindowTextA(hWnd, szTitle, MAX_PATH);
			LPLog->ErrorLog(0, "Watchdog can NOT created on: %s|%p Error: %u", szTitle, hWnd, dwLastError);
#endif
		}

	} while (hWnd != NULL);

	if (!bFirstLoadWatchdog && mWindowBackupMap.empty() && iAttemptCount > 3) {
		CHAR __warn[] = { 'F', 'A', 'T', 'A', 'L', ' ', 'E', 'R', 'R', 'O', 'R', '!', ' ', 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'r', 'e', 't', 'u', 'r', 'n', 'e', 'd', ' ', 'a', 's', ' ', 'u', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'e', 'r', 'r', 'o', 'r', '!', 0x0 }; // FATAL ERROR! Anticheat returned as unknown Windows error!
		LPFunctions->CloseProcess(__warn, true, "");
	}
	else if (!bFirstLoadWatchdog && mWindowBackupMap.empty() && iAttemptCount < 3) {
		iAttemptCount++;
		BetaFunctionTable->Sleep(2000);
		goto research;
	}
	
	if (bFirstLoadWatchdog)
		bFirstLoadWatchdog = false;

#ifdef _DEBUG
	LPLog->AddLog(0,"Watchdog creation completed!");
#endif

	KARMA_MACRO_2
}

DWORD WINAPI InitializeWatchdogEx(LPVOID)
{
	// BetaFunctionTable->Sleep(5000);
	while (1) {
		LoadWatchdog();

		LPThreads->IncreaseThreadTick(5);
		BetaFunctionTable->Sleep(45000);
	}
	return 0;
}

HANDLE CWatchdog::InitializeWatchdog()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Watchdog thread creation has been started!");
#endif
	KARMA_MACRO_2

	LoadWatchdog();
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)InitializeWatchdogEx, 0, 5);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '5', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x5! */
		LPFunctions->CloseProcess(__warn, false, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Watchdog thread creation completed!");
#endif
	KARMA_MACRO_1
	return hThread;
}
