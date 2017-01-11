#include "ProjectMain.h"
#include "AntiBreakpoint.h"
#include "DynamicWinapi.h"
#include "Functions.h"

#include "XOR.h"
#include "CLog.h"
#include "AntiDebug.h"
#include "Threads.h"
#include "Scan.h"
#include "ApiHooks.h"
#include "DirFuncs.h"
#include "Metin2_Plugin.h"


CAntiBreakpoint* LPAntiBreakpoint;
CAntiBreakpoint::CAntiBreakpoint()
{
}

CAntiBreakpoint::~CAntiBreakpoint()
{
}

#pragma optimize("", off )
void CAntiBreakpoint::Anti_HardwareBreakpoint()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti hwbp event has been started!");
#endif

	KARMA_MACRO_1
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = 0x1008c ^ 0x9C;

	if (BetaFunctionTable->GetThreadContext(NtCurrentThread, &ctx))
	{
		if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7) {
			CHAR __warn[] = { 'H', 'a', 'r', 'd', 'w', 'a', 'r', 'e', ' ', 'b', 'r', 'e', 'a', 'k', 'p', 'o', 'i', 'n', 't', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 }; //Hardware breakpoint detected
			LPFunctions->CloseProcess(__warn, true, "");
		}
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti hwbp event completed!");
#endif
}


inline int CheckEntrypoint()
{
	PIMAGE_DOS_HEADER pdhDosHeader = (PIMAGE_DOS_HEADER)BetaModuleTable->hBaseModule;
	if (pdhDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS pndNTHeader = (PIMAGE_NT_HEADERS)((ULONG)pdhDosHeader + (ULONG)pdhDosHeader->e_lfanew);
	if (pndNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	ULONG EntryPoint = (pndNTHeader->OptionalHeader.AddressOfEntryPoint);
	PBYTE pEntryPoint = (PBYTE)(pndNTHeader->OptionalHeader.AddressOfEntryPoint + (ULONG)pdhDosHeader);

	//for (UINT index = 0; index < 20; index++) {
	//	if (pEntryPoint[index] == 0xCC)
	//		ExitProcess(0);
	// }

	return (pEntryPoint[0] == 0xCC);
}

void CAntiBreakpoint::Anti_EntrypointBreakpoint()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti entrypoint bp event has been started!");
#endif

	KARMA_MACRO_1

	if (CheckEntrypoint())
	{
		CHAR __warn[] = { 'E', 'n', 't', 'r', 'y', 'p', 'o', 'i', 'n', 't', ' ', 'b', 'r', 'e', 'a', 'k', 'p', 'o', 'i', 'n', 't', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 }; //Entrypoint breakpoint detected
		LPFunctions->CloseProcess(__warn, true, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti entrypoint bp event completed!");
#endif
}


#pragma optimize("", on )
