#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "CLog.h"
#include "VersionHelpers.h"


LPVOID pMemoryWatchdog;

void CScan::InitializeMemoryWatchdog()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Memory Watchdog creating..");
#endif

	__try {
		pMemoryWatchdog = BetaFunctionTable->VirtualAlloc(0, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	__except (1) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Memory Watchdog creation returned as exception");
#endif
	}

#ifdef _DEBUG
	if (pMemoryWatchdog)
		LPLog->AddLog(0, "Memory Watchdog created on: %p", pMemoryWatchdog);
	else
		LPLog->AddLog(0, "Memory Watchdog create failed!");
#endif
}

void CScan::CheckMemoryWatchdog()
{
	if (!pMemoryWatchdog)
		return;

	PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { 0 };
	pworkingSetExInformation.VirtualAddress = pMemoryWatchdog;

	if (NT_SUCCESS(BetaFunctionTable->NtQueryVirtualMemory(NtCurrentProcess, NULL, MemoryWorkingSetExInformation, &pworkingSetExInformation, sizeof(pworkingSetExInformation), NULL)))
	{
		if (pworkingSetExInformation.VirtualAttributes.Valid) {
			CHAR __warn[] = { 'G', 'a', 'm', 'e', ' ', 'm', 'e', 'm', 'o', 'r', 'y', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'c', 'o', 'r', 'r', 'e', 'c', 't', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'o', ' ', 'n', 'o', 't', ' ', 'u', 's', 'e', ' ', 'c', 'h', 'e', 'a', 't', '.', 0x0 }; // Game memory is not correct. Please do not use cheat.
			LPFunctions->CloseProcess(__warn, false, "");
		}
	}
	else
	{
		if (IsWindowsVistaOrGreater() == true)
		{
			if (BetaFunctionTable->QueryWorkingSetEx(NtCurrentProcess, &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
			{
				if (pworkingSetExInformation.VirtualAttributes.Valid) {
					CHAR __warn[] = { 'G', 'a', 'm', 'e', ' ', 'm', 'e', 'm', 'o', 'r', 'y', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'c', 'o', 'r', 'r', 'e', 'c', 't', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'o', ' ', 'n', 'o', 't', ' ', 'u', 's', 'e', ' ', 'c', 'h', 'e', 'a', 't', '.', '.', 0x0 }; // Game memory is not correct. Please do not use cheat..
					LPFunctions->CloseProcess(__warn, false, "");
				}
			}
		}
	}
}

