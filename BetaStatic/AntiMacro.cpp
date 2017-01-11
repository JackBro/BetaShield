#include "ProjectMain.h"
#include "Main.h"
#include "ApiHooks.h"
#include "DynamicWinapi.h"
#include "Threads.h"

#include "Functions.h"
#include "VersionHelpers.h"
#include "CLog.h"

#define LLKHF_LOWER_IL_INJECTED 0x00000002
#define LLMHF_LOWER_IL_INJECTED 0x00000002
#pragma optimize("", off )
HHOOK MouseHook = 0;
HHOOK KeyboardHook = 0;

// Low level Mouse filter proc
LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION) {
		if (wParam == WM_RBUTTONDOWN || wParam == WM_LBUTTONDOWN) {
			MSLLHOOKSTRUCT* hookStruct = (MSLLHOOKSTRUCT*)lParam;

			if ((hookStruct->flags & LLMHF_INJECTED) == LLMHF_INJECTED)
				return TRUE;
			
			if ((hookStruct->flags & LLMHF_LOWER_IL_INJECTED) == LLMHF_LOWER_IL_INJECTED)
				return TRUE;
			
		}
	}
	return BetaFunctionTable->CallNextHookEx(MouseHook, nCode, wParam, lParam);
}

// Low level Keyboard filter proc
LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION) {
		if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
			KBDLLHOOKSTRUCT* hookStruct = (KBDLLHOOKSTRUCT*)lParam;

			if ((hookStruct->flags & LLKHF_INJECTED) == LLKHF_INJECTED) 
				return TRUE;
			
			if ((hookStruct->flags & LLKHF_LOWER_IL_INJECTED) == LLKHF_LOWER_IL_INJECTED)
				return TRUE;

		}
	}

	return BetaFunctionTable->CallNextHookEx(KeyboardHook, nCode, wParam, lParam);
}

__forceinline void __dieForMacro(int iErrCode)
{
	KARMA_MACRO_1
	char szRealWarn[1024];
	CHAR __warn[] = { 'M', 'a', 'c', 'r', 'o', ' ', 'c', 'h', 'e', 'c', 'k', 'e', 'r', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'd', ' ', 'o', 'r', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'e', 'd', '.', '%', 'd', 0x0 }; // Macro checker is not initialized or terminated.
	sprintf(szRealWarn, __warn, iErrCode);
	
	KARMA_MACRO_1
	LPFunctions->CloseProcess(szRealWarn, false, "");
	KARMA_MACRO_2
}

DWORD WINAPI AntiMacroEx(LPVOID)
{
	HINSTANCE hInstance = BetaModuleTable->hBaseModule;

	MouseHook		= BetaFunctionTable->SetWindowsHookExA(WH_MOUSE_LL,		MouseHookProc,		hInstance, NULL);
	KeyboardHook	= BetaFunctionTable->SetWindowsHookExA(WH_KEYBOARD_LL,	KeyboardHookProc,	hInstance, NULL);
	
	if (IsWindowsVistaOrGreater()) {
		if (!MouseHook)
			__dieForMacro(1);

		if (!KeyboardHook)
			__dieForMacro(2);
	}

	if (MouseHook || KeyboardHook) {
		MSG message;
		while (BetaFunctionTable->GetMessageA(&message, NULL, 0, 0)) {
			BetaFunctionTable->TranslateMessage(&message);
			BetaFunctionTable->DispatchMessageA(&message);
		}

		__dieForMacro(3);
	}

	BetaFunctionTable->UnhookWindowsHookEx(MouseHook);
	BetaFunctionTable->UnhookWindowsHookEx(KeyboardHook);
	return 0;
}

HANDLE CSelfApiHooks::InitAntiMacro()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti macro thread creation has been started!");
#endif

	KARMA_MACRO_1

	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)AntiMacroEx, 0, 10);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '0', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x10! */
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti Macro thread creation completed!");
#endif
	return hThread;
}

void CSelfApiHooks::DestroyAntiMacro()
{
	if (MouseHook)
		BetaFunctionTable->UnhookWindowsHookEx(MouseHook);
	if (KeyboardHook)
		BetaFunctionTable->UnhookWindowsHookEx(KeyboardHook);
}
#pragma optimize("", on )

/// TODO: other hooks
// Priority proc for mouse
// Priority proc for keyboard
// CallWindow hook
// GetMessageProc hook
// DialogMessageProc hook

