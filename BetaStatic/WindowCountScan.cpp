#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "Access.h"
#include "DirFuncs.h"
#include "XOR.h"
#include "Utils.h"
#include "CLog.h"
#include "Data.h"
#include "Threads.h"


void CScan::CheckWindowCount()
{
	HWND hWnd = nullptr;
	std::vector<HWND>vWindowList;

	char szLastClass[MAX_PATH] = { 0 };
	char szLastTitle[MAX_PATH] = { 0 };

	KARMA_MACRO_1
	do
	{
		hWnd = BetaFunctionTable->FindWindowExA(NULL, hWnd, NULL, NULL);
		KARMA_MACRO_2

		DWORD dwPID = 0;
		BetaFunctionTable->GetWindowThreadProcessId(hWnd, &dwPID);

		if (dwPID == BetaFunctionTable->GetCurrentProcessId())
		{
			if (!BetaFunctionTable->IsWindowVisible(hWnd))
				continue;

			BetaFunctionTable->GetClassNameA(hWnd, szLastClass, MAX_PATH);
			BetaFunctionTable->GetWindowTextA(hWnd, szLastTitle, MAX_PATH);

#ifdef _DEBUG
			LPLog->AddLog(0, "Window Enumuration: '%s'|'%s' [%d]", szLastTitle, szLastClass, vWindowList.size());
#endif
			// TODO: GetWindowInfo - WINDOWINFO for verify browser window
			CHAR __ieclass[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', ' ', 'E', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '_', 'H', 'i', 'd', 'd', 'e', 'n', 0x0 }; // Internet Explorer_Hidden
			if (!strcmp(szLastClass, __ieclass) && !strlen(szLastTitle))
			{
#ifdef _DEBUG
				LPLog->AddLog(0, "Window Enumuration: '%s'|'%s' is ingame web browser, passed!", szLastTitle, szLastClass);
#endif
				continue;
			}

#ifdef _DEBUG
			CHAR __ConsoleWindowClass[] = { 'C', 'o', 'n', 's', 'o', 'l', 'e', 'W', 'i', 'n', 'd', 'o', 'w', 'C', 'l', 'a', 's', 's', 0x0 }; // ConsoleWindowClass
			CHAR __title[] = { 'D', 'e', 'b', 'u', 'g', ' ', 'C', 'o', 'n', 's', 'o', 'l', 'e', ' ', 'f', 'o', 'r', ' ', 'B', 'e', 't', 'a', 'S', 'h', 'i', 'e', 'l', 'd', 0x0 }; // Debug Console for BetaShield
			if (!strcmp(szLastTitle, __title) || !strcmp(szLastClass, __ConsoleWindowClass))
			{
				LPLog->AddLog(0, "Debug console is passed! '%s' | '%s'[%d]", szLastTitle, szLastClass, vWindowList.size());
				continue;
			}
#endif

			vWindowList.push_back(hWnd);
		}
	} while (hWnd);


	if (vWindowList.size() > 1)
	{
		BetaFunctionTable->GetClassNameA(vWindowList[1], szLastClass, MAX_PATH);
		BetaFunctionTable->GetWindowTextA(vWindowList[1], szLastTitle, MAX_PATH);

		char szRealWarn[1024];
		CHAR __warn[] = { 'I', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'w', 'i', 'n', 'd', 'o', 'w', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'g', 'a', 'm', 'e', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', '!', ' ', '%', 's', '[', '%', 's', ']', ' ', '|', ' ', '%', 'd', 0x0 }; // Illegal window detected in game process! %s[%s]
		sprintf(szRealWarn, __warn, szLastTitle, szLastClass, vWindowList.size());

		LPFunctions->CloseProcess(szRealWarn, false, "");
	}
}