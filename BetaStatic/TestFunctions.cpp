#include "ProjectMain.h"
#include "Main.h"
#include "Test.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "Access.h"
#include "Scan.h"
#include "Threads.h"
#include "CLog.h"
#include <conio.h>
#include <wbemidl.h>
#include <iostream>
#include <atlbase.h>
#include "ApiHooks.h"
#include "XOR.h"
#include "AntiDebug.h"
#include "DirFuncs.h"
#include "Base64.h"
#include "Watchdog.h"


#ifdef TEST_MODE




DWORD dwNotificationThreadId;
BOOL APIENTRY ThreadAndShutdownNotify(HMODULE hMod, DWORD reason, PVOID pDynamic)
{
	if (dwNotificationThreadId == GetCurrentThreadId())
		return TRUE;


	if (reason == DLL_THREAD_ATTACH)
	{
		char cWarning[4096] = { 0x0 };
		CHAR __warn[] = { 'T', 'y', 'p', 'e', ' ', '3', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!', ' ', 'D', 'e', 't', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Type 3 Thread initilization blocked! Detection Type: %d

		auto adr = LPThreads->GetThreadStartAddress(NtCurrentThread);
		int iBadAddress = CheckCallerAddress(adr, 3, "");
		if (iBadAddress) {
			sprintf(cWarning, __warn, iBadAddress);
			LPFunctions->CloseProcess(cWarning, false, "");
		}
	}

	return TRUE;
}


void InsertIntoList(LIST_ENTRY* pOurListEntry, LIST_ENTRY* pK32ListEntry)
{
	LIST_ENTRY* pEntryToInsertAfter = pK32ListEntry->Flink;

	pOurListEntry->Flink = pEntryToInsertAfter;
	pOurListEntry->Blink = pEntryToInsertAfter->Blink;

	pEntryToInsertAfter->Blink = pOurListEntry;

	pOurListEntry->Blink->Flink = pOurListEntry;
}

int threadcallback()
{
	typedef NTSTATUS(NTAPI* lpLdrFindEntryForAddress)(HMODULE hMod, LDR_DATA_TABLE_ENTRY** ppLdrData);
	CHAR __LdrFindEntryForAddress[] = { 'L', 'd', 'r', 'F', 'i', 'n', 'd', 'E', 'n', 't', 'r', 'y', 'F', 'o', 'r', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 }; // LdrFindEntryForAddress
	auto LdrFindEntryForAddress = (lpLdrFindEntryForAddress)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, __LdrFindEntryForAddress);

	CHAR __close1[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '1', '0', 0x0 }; // Fatal Error on process initilization! Error code: 10
	if (!LdrFindEntryForAddress || LPFunctions->IsInModuleRange(BetaModuleTable->hNtdll, (DWORD)LdrFindEntryForAddress) == false)
		LPFunctions->CloseProcess(__close1, false, "");


	LDR_DATA_TABLE_ENTRY* pEntry = NULL;
	if (NT_SUCCESS(LdrFindEntryForAddress(BetaModuleTable->hBaseModule, &pEntry)))
	{
		pEntry->EntryPoint = (PVOID)&ThreadAndShutdownNotify;
		pEntry->Flags |= 0x00080000 | 0x00000004;
		pEntry->Flags &= ~(0x00040000);
		pEntry->DllBase = (PVOID)(((ULONG_PTR)pEntry->DllBase) + 2);

		LDR_DATA_TABLE_ENTRY* pK32Entry = NULL;
		LdrFindEntryForAddress(BetaModuleTable->hKernel32, &pK32Entry);

		InsertIntoList(&pEntry->InInitializationOrderLinks, &pK32Entry->InInitializationOrderLinks);
	}
	else {
		CHAR __close2[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '1', '1', 0x0 }; // Fatal Error on process initilization! Error code: 11
		LPFunctions->CloseProcess(__close2, false, "");
	}

	printf("Initialized!!!!\n");

	return 0;
}


DWORD WINAPI TestFunctionThread(LPVOID)
{
	printf("TestFunctionThread started!\n");

	while (1)
	{
		//printf("%u\n", DumpModules());
		printf("XXXXXXXXXXXXX\n");

		Sleep(10000);
	}


	return 0;
}

typedef PVOID(NTAPI *RtlImageDirectoryEntryToDataHook)(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size
	);
static struct {
	SIZE_T Id;
	RtlImageDirectoryEntryToDataHook Call;
} hRtlImageDirectoryEntryToData = { 0, 0 };

PVOID NTAPI RtlImageDirectoryEntryToDataDetour(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size
) {
	LPLog->AddLog(0, "Base: %p Size: %p AsImage: %d Directory: %ld", Base, Size, MappedAsImage, DirectoryEntry);
	return hRtlImageDirectoryEntryToData.Call(Base, MappedAsImage, DirectoryEntry, Size);
}



typedef BOOLEAN(NTAPI * PDLL_INIT_ROUTINE)(_In_ PVOID DllHandle, _In_ ULONG Reason, _In_opt_ PCONTEXT Context);
typedef BOOLEAN(NTAPI *LdrpCallInitRoutineHook)(
	IN PDLL_INIT_ROUTINE  	EntryPoint,
	IN PVOID  	BaseAddress,
	IN ULONG  	Reason,
	IN PVOID  	Context);
static struct {
	SIZE_T Id;
	LdrpCallInitRoutineHook Call;
} hLdrpCallInitRoutine = { 0, 0 };
/* WIN10 DA YOK !!!*/
BOOLEAN NTAPI LdrpCallInitRoutineDetour(IN PDLL_INIT_ROUTINE EntryPoint, IN PVOID  	BaseAddress, IN ULONG  	Reason, IN PVOID  	Context)
{
	TCHAR szName[MAX_PATH] = { 0 };
	GetModuleFileName((HMODULE)BaseAddress, szName, _countof(szName));
	cout << szName << endl;


	return hLdrpCallInitRoutine.Call(EntryPoint, BaseAddress, Reason, Context);
}




typedef HANDLE(WINAPI* CreateActCtxW_Hook)(PACTCTX);
static struct {
	SIZE_T Id;
	CreateActCtxW_Hook Call;
} hCreateActCtxW = { 0, 0 };

HANDLE WINAPI CreateActCtxWDetour(PACTCTX pActCtx)
{
	if (pActCtx)
	{
		LPLog->ErrorLog(0, "CreateActCtxW called! ProcessorArchitecture: %ld LangId: %ld Flags: %u Size: %ld", 
			pActCtx->wProcessorArchitecture, pActCtx->wLangId, pActCtx->dwFlags, pActCtx->cbSize);

		if (pActCtx->hModule) {
			char cFileName[2048] = { 0 };
			BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)pActCtx->hModule, cFileName, 2048);

			LPLog->ErrorLog(0, "CreateActCtxW module: %p Owner: %s", pActCtx->hModule, cFileName);
		}

		if (pActCtx->lpApplicationName && strlen(pActCtx->lpApplicationName)) {
			LPLog->ErrorLog(0, "CreateActCtxW ApplicationName: %s", pActCtx->lpApplicationName);
		}

		if (pActCtx->lpAssemblyDirectory && strlen(pActCtx->lpAssemblyDirectory)) {
			LPLog->ErrorLog(0, "CreateActCtxW AssemblyDirectory: %s", pActCtx->lpAssemblyDirectory);
		}

		if (pActCtx->lpResourceName && strlen(pActCtx->lpResourceName)) {
			LPLog->ErrorLog(0, "CreateActCtxW ResourceName: %s", pActCtx->lpResourceName);
		}

		if (pActCtx->lpSource && strlen(pActCtx->lpSource)) {
			LPLog->ErrorLog(0, "CreateActCtxW Source: %s", pActCtx->lpSource);
		}

	}
	return hCreateActCtxW.Call(pActCtx);
}






/*
#include <detours.h>

typedef NTSTATUS(NTAPI* RtlActivateActivationContextEx_Hook)(ULONG, PTEB, HANDLE, PULONG_PTR);
RtlActivateActivationContextEx_Hook RtlActivateActivationContextEx;

NTSTATUS NTAPI RtlActivateActivationContextExDetour(ULONG flags, PTEB tebAddress, HANDLE handle, PULONG_PTR cookie)
{
	__asm nop;

	return RtlActivateActivationContextEx(flags, tebAddress, handle, cookie);
}
*/


void EraseHeader(LPVOID lpTarget)
{
	DWORD i, protect;

	PIMAGE_DOS_HEADER pDoH = (PIMAGE_DOS_HEADER)(lpTarget);
	PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)((LONG)lpTarget + ((PIMAGE_DOS_HEADER)lpTarget)->e_lfanew);

	DWORD ersize = sizeof(IMAGE_DOS_HEADER);
	if (VirtualProtect(pDoH, ersize, PAGE_READWRITE, &protect))
	{
		for (i = 0; i < ersize; i++)
			*(BYTE*)((BYTE*)pDoH + i) = 0;
	}

	ersize = sizeof(IMAGE_NT_HEADERS);
	if (pNtH && VirtualProtect(pNtH, ersize, PAGE_READWRITE, &protect))
	{
		for (i = 0; i < ersize; i++)
			*(BYTE*)((BYTE*)pNtH + i) = 0;
	}
}

void EraseHeaders()
{
	EraseHeader(BetaModuleTable->hKernel32);
	if (BetaModuleTable->hKernelbase)
		EraseHeader(BetaModuleTable->hKernelbase);
	EraseHeader(BetaModuleTable->hNtdll);
	EraseHeader(BetaModuleTable->hUser32);
#if 0
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Current->DllBase && LPData->GetAntiModule() != Current->DllBase)
			EraseHeaders(Current->DllBase);

		CurrentEntry = CurrentEntry->Flink;
	}
#endif
}










void CTest::InitTestFunctions()
{
	LPAccess->EnableDebugPrivileges();
	// Ready for use

	// ----------------------------------------------------------


	/*
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Current->DllBase && LPData->GetAntiModule() != Current->DllBase)
			EraseHeaders(Current->DllBase);

		CurrentEntry = CurrentEntry->Flink;
	}
	*/

	/*
	auto teb = GetCurrentTeb();
	LPLog->AddLog(0, "%p", teb->Win32ThreadInfo);

	PTHREADINFO threadinfo = (PTHREADINFO)teb->Win32ThreadInfo;
	LPLog->AddLog(0, "%p", threadinfo);

	PDESKTOPINFO desktopinfo = (PDESKTOPINFO)threadinfo->pDeskInfo;
	LPLog->AddLog(0, "%p", desktopinfo);

	auto aphkHooks = desktopinfo->aphkStart[0];
	LPLog->AddLog(0, "%p", aphkHooks);
	*/
#if 0
	int iFailAttempt = 0;
	DWORD dwOsErr = 0;
	LPVOID fnAddress = 0;

	fnAddress = NktHookLibHelpers::GetProcedureAddress(GetModuleHandleA("kernelbase.dll"), "CreateActCtxW");
	dwOsErr += (cHookMgr->Hook(&(hCreateActCtxW.Id), (LPVOID*)&(hCreateActCtxW.Call), fnAddress, CreateActCtxWDetour, 0));
	if (dwOsErr) {
		LPLog->ErrorLog(0, "detour init1 fail. Addr: %p Err: %u", fnAddress, dwOsErr);
	}
	else {
		LPLog->AddLog(0, "detour init1 ok. Addr: %p", fnAddress);
	}
	fnAddress = NktHookLibHelpers::GetProcedureAddress(GetModuleHandleA("kernel32.dll"), "CreateActCtxW");
	dwOsErr += (cHookMgr->Hook(&(hCreateActCtxW.Id), (LPVOID*)&(hCreateActCtxW.Call), fnAddress, CreateActCtxWDetour, 0));
	if (dwOsErr) {
		LPLog->ErrorLog(0, "detour init1.1 fail. Addr: %p Err: %u", fnAddress, dwOsErr);
	}
	else {
		LPLog->AddLog(0, "detour init1.1 ok. Addr: %p", fnAddress);
	}
#endif


#if 0

	fnAddress = NktHookLibHelpers::GetProcedureAddress(GetModuleHandleA("ntdll.dll"), "RtlImageDirectoryEntryToData");
	dwOsErr += (cHookMgr->Hook(&(hRtlImageDirectoryEntryToData.Id), (LPVOID*)&(hRtlImageDirectoryEntryToData.Call), fnAddress, RtlImageDirectoryEntryToDataDetour, 0));
	if (dwOsErr) {
		LPLog->ErrorLog(0, "detour init fail. Addr: %p Err: %u", fnAddress, dwOsErr);
	}
	else {
		LPLog->AddLog(0, "detour init ok. Addr: %p", fnAddress);
	}
#endif

#if 0
	fnAddress = SymGetProcAddress(L"ntdll.dll", L"LdrpCallInitRoutine");
	dwOsErr += (cHookMgr->Hook(&(hLdrpCallInitRoutine.Id), (LPVOID*)&(hLdrpCallInitRoutine.Call), fnAddress, LdrpCallInitRoutineDetour, 0));
	if (dwOsErr) {
		LPLog->ErrorLog(0, "detour init fail. Addr: %p Err: %u", fnAddress, dwOsErr);
	}
	else {
		LPLog->AddLog(0, "detour init ok. Addr: %p", fnAddress);
	}
#endif

	//CreateThread(0, 0, TestFunctionThread, 0, 0, 0);



	printf("InitTestFunctions Initialization completed!\n");
}
#endif