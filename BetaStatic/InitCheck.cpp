#include "ProjectMain.h"
#include "WatchDog.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "XOR.h"
#include "CLog.h"
#include "AntiDebug.h"


BOOL bProcessed = FALSE;
VOID CALLBACK TimerProc(HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
	KARMA_MACRO_1
	if (LPData->GetGameCode() == TEST_CONSOLE) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Watchdog init check skipped on test console!");
#endif
		goto skip;
	}

	KARMA_MACRO_2
	CHAR __warn[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 'w', 'a', 't', 'c', 'h', 'e', 'r', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'd', '!', 0x0 }; // Process watcher can not initialized!
	if (LPWatchdog->GetWatchdogCount() < 1)
		LPFunctions->CloseProcess(__warn, false, "");

skip:
#ifdef _DEBUG
	LPLog->AddLog(0, "Watchdog init check processed! Adjusted watchdog count: %d", LPWatchdog->GetWatchdogCount());
#endif

	KARMA_MACRO_1
	if (LPAntiDebug->GetManipulationType() == 1)
	{
		CHAR __warn[] = { 'E', 'm', 'u', 'l', 'a', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '4', 0x0 }; // Emulator detected! Error code: 4
		LPFunctions->CloseProcess(__warn, false, "");
	}
	else if (LPAntiDebug->GetManipulationType() == 2)
	{
		CHAR __warn[] = { 'E', 'm', 'u', 'l', 'a', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '5', 0x0 }; // Emulator detected! Error code: 5
		LPFunctions->CloseProcess(__warn, false, "");
	}
	else if (LPAntiDebug->GetManipulationType() != 99)
	{
		CHAR __warn[] = { 'E', 'm', 'u', 'l', 'a', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '6', 0x0 }; // Emulator detected! Error code: 6
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_1

	bProcessed = TRUE;

	KARMA_MACRO_2
}
void InitCheckThread(LPVOID lpArgs)
{
	MSG Msg;
	UINT_PTR iTimerID;

	iTimerID = BetaFunctionTable->SetTimer(NULL, 0, 15000, TimerProc);

	while (BetaFunctionTable->GetMessageA(&Msg, NULL, 0, 0) & !bProcessed)
	{
		BetaFunctionTable->TranslateMessage(&Msg);
		BetaFunctionTable->DispatchMessageA(&Msg);
	}

	BetaFunctionTable->KillTimer(NULL, iTimerID);

#ifdef _DEBUG
	LPLog->AddLog(0, "Watchdog init check event completed!");
#endif
}


VOID CWatchdog::SetInitCheckTimer()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Watchdog Init Check event thread initilization has been started!");
#endif

	_beginthread(InitCheckThread, 0, nullptr);

#ifdef _DEBUG
	LPLog->AddLog(0, "Watchdog Init Check event thread initilization completed!");
#endif
}

