#include "ProjectMain.h"

#include "Functions.h"
#include "Utils.h"
#include "Functions.h"
#include "BasePointers.h"
#include "XOR.h"
#include "DynamicWinapi.h"

static bool bExitFlag = false;
bool CUtils::IsFlaggedForExit() { return bExitFlag; }
void CUtils::SetFlagForExit() { bExitFlag = true; }


#pragma warning(disable: 4731)
void CUtils::Close()
{
	KARMA_MACRO_1

#ifdef _DEBUG
	__asm int 3;
#endif

	bExitFlag = true;
	KARMA_MACRO_2

#ifndef _DEBUG
	exit(-1);
#else
	exit(0);
#endif

	__asm mov ESP, 0;

	BetaFunctionTable->PostQuitMessage(0);
	BetaFunctionTable->WinStationTerminateProcess(NULL, 0, DBG_TERMINATE_PROCESS);

	KARMA_MACRO_1

	BetaFunctionTable->NtTerminateProcess(NtCurrentProcess, -1);

	KARMA_MACRO_2

	int* p = 0; // crash
	*p = 0;

	__asm {
		xor eax, eax
		ret
	}

	RtlZeroMemory((void*)BetaModuleTable->hBaseModule, 4096);

	KARMA_MACRO_1
	DWORD dwRaiseExceptionAddr = (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtRaiseException"));
	__asm jmp dword ptr dwRaiseExceptionAddr;
	
	KARMA_MACRO_1
	memset(NULL, 0, 1);

	((void(*)(void))NULL)();

	KARMA_MACRO_1
	BetaFunctionTable->BlockInput(TRUE);
	while (1) while (1);
	KARMA_MACRO_2
}

