#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "XOR.h"
#include "CLog.h"
#include "Data.h"
#include "Threads.h"

enum Etypes {
	XUETR,
	PCHUNTER,
	PCHUNTER_2,
};

__forceinline void Kill(int iType, HWND hwnd, const char* c_szTitle, const char* c_szClass, DWORD dwProcessId)
{
	if (!dwProcessId)
		return;

	auto szProcessName = LPFunctions->GetProcessNameFromProcessId(dwProcessId);

	CHAR __warn[] = { 'B', 'a', 'd', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', ':', ' ', '%', 's', '(', '%', 's', '|', '%', 's', ')', ' ', 'i', 's', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'd', '!', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Bad Process: %s(%s|%s) is terminated! Type: %d
	LPLog->ErrorLog(0, __warn, szProcessName.c_str(), c_szTitle, c_szClass, iType);

#ifdef SCRENSHOT_FEATURE
	LPFunctions->SendScreenshotToServer();
#endif

	BetaFunctionTable->SendMessageA(hwnd, WM_CLOSE, 0, 0);
	BetaFunctionTable->SendMessageA(hwnd, WM_QUIT, 0, 0);
	BetaFunctionTable->SendMessageA(hwnd, WM_DESTROY, 0, 0);

	if (LPFunctions->ProcessIsItAlive(dwProcessId))
		BetaFunctionTable->EndTask(hwnd, FALSE, TRUE);

	if (LPFunctions->ProcessIsItAlive(dwProcessId))
		BetaFunctionTable->WinStationTerminateProcess(NULL, dwProcessId, DBG_TERMINATE_PROCESS);
}

// #define DUMP_INFO
void CALLBACK HandleWinEvent(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime)
{
	if (hwnd)
	{
#pragma region WindowScanInfos
		DWORD dwProcessId = 0;
		BetaFunctionTable->GetWindowThreadProcessId(hwnd, &dwProcessId);

		WINDOWINFO wndfo;
		BetaFunctionTable->GetWindowInfo(hwnd, &wndfo);

		char szName[MAX_PATH];
		BetaFunctionTable->GetWindowTextA(hwnd, szName, MAX_PATH);

		char szClass[MAX_PATH] = { 0x0 };
		BetaFunctionTable->GetClassNameA(hwnd, szClass, MAX_PATH);
#pragma endregion WindowScanInfos

#pragma region DumpInfo
#ifdef DUMP_INFO
		if (dwProcessId != BetaFunctionTable->GetCurrentProcessId())
		{
			LPLog->AddLog(0,
				"\nName: %s|%s Owner: %u Window: %p Object: %ld Child: %ld\n"
				"wndfo.rcWindow | 1: %ld 2: %ld 3: %ld 4: %ld\n"
				"wndfo.rcClient | 1: %ld 2: %ld 3: %ld 4: %ld\n"
				"wCreatorVersion: %d dwStyle: %u dwExStyle: %u\n"
				"cxWindowBorders: %u cyWindowBorders: %u Cbsize: %u\n",

				szName, szClass, dwEventThread, hwnd, idObject, idChild,
				wndfo.rcWindow.bottom, wndfo.rcWindow.left, wndfo.rcWindow.right, wndfo.rcWindow.top,
				wndfo.rcClient.bottom, wndfo.rcClient.left, wndfo.rcClient.right, wndfo.rcClient.top,
				wndfo.wCreatorVersion, wndfo.dwStyle, wndfo.dwExStyle,
				wndfo.cxWindowBorders, wndfo.cyWindowBorders, wndfo.cbSize
			);
		}
#endif
#pragma endregion DumpInfo

#pragma region CheckWindowRoutine

		/// XueTr
		if (wndfo.dwStyle == 2496331972 && wndfo.dwExStyle == 537200897)
			Kill(XUETR, hwnd, szName, szClass, dwProcessId);

		/// PCHUNTER
		if (wndfo.dwStyle == 2496331972 && wndfo.dwExStyle == 3758426369)
			Kill(PCHUNTER, hwnd, szName, szClass, dwProcessId);

		if (wndfo.dwStyle == 2227896516 && wndfo.dwExStyle == 327937)
			Kill(PCHUNTER_2, hwnd, szName, szClass, dwProcessId);

#pragma endregion CheckWindowRoutine
	}
}

DWORD WINAPI WindowScanRoutine(LPVOID)
{
	CHAR __warn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '1', '2', 0x0 }; // Fatal Error on process initilization! Error code: 12
	HWINEVENTHOOK hHook = BetaFunctionTable->SetWinEventHook(EVENT_MIN, EVENT_MAX, NULL, HandleWinEvent, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
	if (!hHook) {
		LPFunctions->CloseProcess(__warn, false, "");
		return 0;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Window scan hook succesfully created!");
#endif

	MSG message;
	while (BetaFunctionTable->GetMessageA(&message, NULL, 0, 0)) {
		BetaFunctionTable->TranslateMessage(&message);
		BetaFunctionTable->DispatchMessageA(&message);
	}

	return 0;
}

HANDLE CScan::InitWindowScan()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Window scan thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)WindowScanRoutine, 0, 15);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '5', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x15! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Window scan thread creation completed!");
#endif
	return hThread;
}

