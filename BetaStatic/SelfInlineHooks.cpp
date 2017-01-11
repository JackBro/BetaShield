#include <WinSock.h>
#include "ProjectMain.h"
#include "Main.h"
#include "ApiHooks.h"
#include "DynamicWinapi.h"
#include "VersionHelpers.h"
#include "Functions.h"
#include "DirFuncs.h"
#include "XOR.h"
#include "Threads.h"
#include "LDasm.h"
#include "Utils.h"
#include "Scan.h"
#include "CLog.h"
#include "Data.h"
#include "NktHookLib.h"
#include "DynamicWinapi.h"
#include "InternetAPI.h"
#include "File_verification.h"
#include <boost/algorithm/string/replace.hpp>
#include "Watchdog.h"


#pragma optimize("", off )
bool bAPI_Hooks_Is_Initialized = false;
#pragma optimize("", on )

typedef int(WINAPI * connectHook)(SOCKET s, const struct sockaddr* name, int namelen);
static struct {
	SIZE_T Id;
	connectHook Call;
} hconnect = { 0, 0 };

typedef NTSTATUS(NTAPI * NtMapViewOfSectionHook)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
static struct {
	SIZE_T Id;
	NtMapViewOfSectionHook Call;
} hNtMapViewOfSection = { 0, 0 };

typedef void(*LdrInitializeThunkHook)(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
static struct {
	SIZE_T Id;
	LdrInitializeThunkHook Call;
} hLdrInitializeThunk = { 0, 0 };
typedef ULONG(NTAPI* RtlGetFullPathName_UHook)(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);
static struct {
	SIZE_T Id;
	RtlGetFullPathName_UHook Call;
} hRtlGetFullPathName_U = { 0, 0 };

typedef NTSTATUS(NTAPI * LdrGetDllHandleExHook)(IN ULONG Flags, IN PWSTR DllPath OPTIONAL, IN PULONG DllCharacteristics OPTIONAL, IN PUNICODE_STRING DllName, OUT PVOID *DllHandle OPTIONAL);
static struct {
	SIZE_T Id;
	LdrGetDllHandleExHook Call;
} hLdrGetDllHandleEx = { 0, 0 };
typedef NTSTATUS(NTAPI *LdrLoadDLLHook)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
static struct {
	SIZE_T Id;
	LdrLoadDLLHook Call;
} hLdrLoadDLL = { 0, 0 };

typedef ULONG(WINAPI *pfnRtlDispatchException)(PEXCEPTION_RECORD pExcptRec, CONTEXT * pContext);
static pfnRtlDispatchException m_fnRtlDispatchException = NULL;

typedef NTSTATUS(NTAPI* NtDelayExecutionHook)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
static struct {
	SIZE_T Id;
	NtDelayExecutionHook Call;
} hNtDelayExecution = { 0, 0 };

typedef NTSTATUS(NTAPI * NtContinueHook)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
static struct {
	SIZE_T Id;
	NtContinueHook Call;
} hNtContinue = { 0, 0 };

typedef LONG(WINAPI* SetWindowLongAHook)(HWND hWnd, int nIndex, LONG dwNewLong);
static struct {
	SIZE_T Id;
	SetWindowLongAHook Call;
} hSetWindowLongA = { 0, 0 };

typedef LONG(WINAPI* SetWindowLongWHook)(HWND hWnd, int nIndex, LONG dwNewLong);
static struct {
	SIZE_T Id;
	SetWindowLongWHook Call;
} hSetWindowLongW = { 0, 0 };

#ifdef TERMINATE_HOOK
typedef NTSTATUS(NTAPI* NtTerminateProcessHook)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
static struct {
	SIZE_T Id;
	NtTerminateProcessHook Call;
} hNtTerminateProcess = { 0, 0 };
#endif


CSelfApiHooks* LPSelfApiHooks;
CSelfApiHooks::CSelfApiHooks()
{
}

CSelfApiHooks::~CSelfApiHooks()
{
}

bool CSelfApiHooks::HooksIsInitialized() { return bAPI_Hooks_Is_Initialized; }



/* ---------------------- */
#pragma optimize("", off )
enum {
	LdrLoadShellCode1 = 1,
	ManualMapShellCode1,
	ManualMapShellCode2,
	ManualMapShellCode3,
	ReflectiveShellCode1,
	ManualLoadShellCode1,
	ThreadHijackShellCode1,
	ThreadHijackShellCode2,
	ThreadHijackShellCode3,
	CreateRemoteThreadExShellCode1,
	CodeInjectionShellCode1,
	AutoInjectorLalakerShellCode,
	LalakerMetin2HackV110,
	SHELLCODEMAXITEM
};

enum {
	EaxLoadLibraryA = SHELLCODEMAXITEM,
	EaxLoadLibraryW,
	EaxLoadLibraryExA,
	EaxLoadLibraryExW,
	EaxFreeLibrary,
	EaxExitProcess,
	EaxLdrLoadDll,
	EaxLdrUnloadDll,
	EaxVirtualQuery,
	EaxVirtualAlloc,
	EaxSetWindowHookEx,
	EaxSetWindowHookEx2,
	EaxCreateRemoteThreadReal,
	EaxPython,
	EaxRtlUserThreadStart,
	EaxNtCreateThread,
	EaxNtCreateThreadEx,
	EaxRtlCreateUserThread,
	EaxCodeInjectionType,
	EaxBadPointerType,
	EaxBadAllocatedProtectType,
	QueryWorkingSetExFail,
	QueryWorkingSetExNotValid,
	EaxMainProcess,
	EaxMappedCode,
	EaxMappedCode2,
	NullCharacteristics,
	EaxMaxType
};


__forceinline int filterShellcode(DWORD dwAddr)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"Shellcode filter has been started!");

	BYTE bBytes[10] = { 0 };
	nkt_memcopy(bBytes, (PVOID)dwAddr, 10);

	LPLog->DetourLog(0,"Shellcode Info -> Address: %p Bytes: 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x",
		dwAddr, bBytes[0], bBytes[1], bBytes[2], bBytes[3], bBytes[4], bBytes[5], bBytes[6], bBytes[7], bBytes[8], bBytes[9], bBytes[10]);

	char cFileName[2048] = { 0 };
	BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwAddr, cFileName, 2048);
	LPLog->DetourLog(0,"Shellcode mapped module name: %s", cFileName);

	LPLog->DetourLog(0,"Shellcode Infos dumped!");
#endif

	BYTE* byMemory = (BYTE*)dwAddr;
	BYTE shellLdrLoad[5] = { 0x55, 0x8B, 0xEC, 0x8D, 0x5 }; KARMA_MACRO_1
	BYTE shellManualMp[6] = { 0x55, 0x8B, 0xEC, 0x51, 0x53, 0x8B }; KARMA_MACRO_1
	BYTE shellReflective[8] = { 0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x54, 0x8B }; KARMA_MACRO_1
	BYTE shellMLoad[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x53, 0x56 }; KARMA_MACRO_2
	BYTE shellhijack[10] = { 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x60, 0x9C, 0xBB, 0xCC, 0xCC }; KARMA_MACRO_1
	BYTE shellhijack2[10] = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06 }; KARMA_MACRO_2
	BYTE shellhijack3[10] = { 0x56, 0x8B, 0x35, 0x00, 0xC0, 0x27, 0x6A, 0x57, 0x8B, 0x3D }; KARMA_MACRO_2
	BYTE shellcreateremotethreadex[10] = { 0xE8, 0x1D, 0x00, 0x00, 0x00, 0x50, 0x68, 0x58, 0x58, 0xC3 }; KARMA_MACRO_2
	BYTE shellcodeinjectrosdevil[8] = { 0x68, 0xAC, 0xCE, 0xEA, 0xAC, 0x9C, 0x60, 0x68 }; KARMA_MACRO_1
	BYTE shellcodeLalakerAuto[8] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x5D, 0xFF, 0x25 }; KARMA_MACRO_2

	// LdrLoadDll, LdrpLoadDll, ManualMap1 ++
	if (nkt_memcmp((void*)(dwAddr), &shellLdrLoad, 5) == 0)
	 	return LdrLoadShellCode1;
	// LdrLoadDll, LdrpLoadDll, ManualMap1 --

	KARMA_MACRO_1
	// ManualMap2 ++
	if (nkt_memcmp((void*)(dwAddr), &shellManualMp, 6) == 0)
		return ManualMapShellCode1;
	// ManualMap2 --

	KARMA_MACRO_1
	// ManualMap3 ++
	if (*byMemory == 0x68 && *(byMemory + 5) == 0x68) {
		if (*(byMemory + 10) == 0xB8)
			return ManualMapShellCode2;
		else if (*(byMemory + 10) == 0x68)
			return ManualMapShellCode3;
	}
	// ManualMap3 --

	KARMA_MACRO_2
	// Reflective ++
	if (nkt_memcmp((void*)(dwAddr), &shellReflective, 8) == 0)
		return ReflectiveShellCode1;
	// Reflective --

	KARMA_MACRO_1
	// Manual Load ++
	if (nkt_memcmp((void*)(dwAddr), &shellMLoad, 8) == 0)
		return ManualLoadShellCode1;
	// Manual Load --

	KARMA_MACRO_2
	// Thread hijack 1 ++
	if (nkt_memcmp((void*)(dwAddr), &shellhijack, 10) == 0)
		return ThreadHijackShellCode1;
	// Thread hijack 1 --

	KARMA_MACRO_1
	// Thread hijack 2 ++
	if (nkt_memcmp((void*)(dwAddr), &shellhijack2, 10) == 0)
		return ThreadHijackShellCode2;
	// Thread hijack 2 --

	KARMA_MACRO_1
	// Thread hijack 3 ++
	if (nkt_memcmp((void*)(dwAddr), &shellhijack3, 10) == 0)
		return ThreadHijackShellCode3;
	// Thread hijack 3 --

	KARMA_MACRO_2
	// Createremotethreadex 1 ++
	if (nkt_memcmp((void*)(dwAddr), &shellcreateremotethreadex, 10) == 0)
		return CreateRemoteThreadExShellCode1;
	// Createremotethreadex 1 --

	KARMA_MACRO_1
	// Code injection 1 ++
	if (nkt_memcmp((void*)(dwAddr), &shellcodeinjectrosdevil, 8) == 0)
		return CodeInjectionShellCode1;
	// Code injection 1 --

	KARMA_MACRO_2
	// Lalaker auto injector ++
	if (nkt_memcmp((void*)(dwAddr), &shellcodeLalakerAuto, 8) == 0)
		return AutoInjectorLalakerShellCode;
	// Lalaker auto injector --
	KARMA_MACRO_2

	// Lalaker v110 external hack ++
	if (byMemory[0] == 0x68 && byMemory[1] == 0x0 && byMemory[2] == 0x0 && byMemory[5] == 0xe8 && byMemory[7] == 0xcd && byMemory[10] == 0x68)
		return LalakerMetin2HackV110;
	// Lalaker v110 external hack --
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->DetourLog(0,"Shellcode filter completed!");
#endif
	return 0;
}

enum {
	CHECK_TYPE_THREAD,
	CHECK_TYPE_THREAD2, /* ClientThreadSetup */
	CHECK_TYPE_THREAD3, /* NtContinue context based */
	CHECK_TYPE_THREAD4, /* LdrFindEntryForAddress */
	CHECK_TYPE_LDRLOAD,
	CHECK_TYPE_RtlGetFullPathName_U,
};


inline int CheckCallerAddress(DWORD dwCaller, int iType, std::string szName)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"Caller Address checker has been started! Caller: %u Type: %d", dwCaller, iType);
#endif

	DWORD dwLoadLibraryA				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LoadLibraryA"));
	DWORD dwLoadLibraryW				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LoadLibraryW"));
	DWORD dwLoadLibraryExA				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LoadLibraryExA"));
	DWORD dwLoadLibraryExW				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("LoadLibraryExW"));
	DWORD dwFreeLibrary					=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("FreeLibrary"));

	DWORD dwCreateRemoteThread			=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("CreateRemoteThread"));
	DWORD dwExitProcess					=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("ExitProcess"));

	DWORD dwLdrLoadDll					=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("LdrLoadDll"));
	DWORD dwLdrUnloadDll				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("LdrUnloadDll"));

	DWORD dwVirtualQuery				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualQuery"));
	DWORD dwVirtualAlloc				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualAlloc"));
	DWORD dwVirtualAllocEx				=	(DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, XOR("VirtualAllocEx"));


	DWORD dwRtlUserThreadStart = IsWindowsVistaOrGreater() ? (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlUserThreadStart")) : 0;
	DWORD dwNtCreateThread = IsWindowsVistaOrGreater() ? (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtCreateThread")) : 0;
	DWORD dwNtCreateThreadEx = IsWindowsVistaOrGreater() ? (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("NtCreateThreadEx")) : 0;
	DWORD dwRtlCreateUserThread = IsWindowsVistaOrGreater() ? (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("RtlCreateUserThread")) : 0;


	LPBYTE pbCaller = (LPBYTE)dwCaller;

	MODULEINFO user32ModInfo = { 0 };
	BetaFunctionTable->GetModuleInformation(NtCurrentProcess, BetaModuleTable->hUser32, &user32ModInfo, sizeof(user32ModInfo));
	DWORD dwUser32Low = (DWORD)user32ModInfo.lpBaseOfDll;
	DWORD dwUser32Hi = (DWORD)user32ModInfo.lpBaseOfDll + user32ModInfo.SizeOfImage;

	DWORD dwPythonLow = 0;
	DWORD dwPythonHi = 0;
	if (LPData->GetGameCode() == METIN2_GAME)
	{
		MODULEINFO pythonModInfo = { 0 };
		BetaFunctionTable->GetModuleInformation(NtCurrentProcess, BetaModuleTable->hPython, &pythonModInfo, sizeof(pythonModInfo));
		dwPythonLow = (DWORD)pythonModInfo.lpBaseOfDll;
		dwPythonHi = (DWORD)pythonModInfo.lpBaseOfDll + pythonModInfo.SizeOfImage;
	}

	MEMORY_BASIC_INFORMATION mbiCaller = { 0 };
	BetaFunctionTable->VirtualQuery((LPCVOID)dwCaller, &mbiCaller, sizeof(MEMORY_BASIC_INFORMATION));

	char cFileName[2048] = { 0 };
	BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwCaller, cFileName, 2048);


#ifdef _DEBUG
	LPLog->DetourLog(0,"Caller Address checker completed! Address: %p", dwCaller);
#endif

	int iIsShellInjection = filterShellcode(dwCaller);
	if (iIsShellInjection)
		return iIsShellInjection;

	if (dwCaller == dwLoadLibraryA)
		return EaxLoadLibraryA;

	else if (dwCaller == dwLoadLibraryW)
		return EaxLoadLibraryW;

	else if (dwCaller == dwLoadLibraryExA)
		return EaxLoadLibraryExA;

	else if (dwCaller == dwLoadLibraryExW)
		return EaxLoadLibraryExW;

	else if (dwCaller == dwFreeLibrary)
		return EaxFreeLibrary;

	else if (dwCaller == dwExitProcess)
		return EaxExitProcess;

	else if (dwCaller == dwLdrLoadDll)
		return EaxLdrLoadDll;

	else if (dwCaller == dwLdrUnloadDll)
		return EaxLdrUnloadDll;

	else if (dwCaller == dwVirtualQuery)
		return EaxVirtualQuery;

	else if (dwCaller == dwVirtualAlloc)
		return EaxVirtualAlloc;

	else if (dwCaller >= dwUser32Low && dwCaller <= dwUser32Hi)
		return EaxSetWindowHookEx; // SetWindowHookEx

	else if (dwCaller == dwCreateRemoteThread)
		return EaxCreateRemoteThreadReal; // CreateRemoteThreadReal

	else if (LPData->GetGameCode() == METIN2_GAME && (dwCaller >= dwPythonLow && dwCaller <= dwPythonHi))
		return EaxPython; // Python module range

	if (IsWindowsVistaOrGreater()) {
		if (dwCaller == dwRtlUserThreadStart)
			return EaxRtlUserThreadStart;
		if (dwCaller == dwNtCreateThread)
			return EaxNtCreateThread;
		if (dwCaller == dwNtCreateThreadEx)
			return EaxNtCreateThreadEx;
		if (dwCaller == dwRtlCreateUserThread)
			return EaxRtlCreateUserThread;
	}

	if (iType != CHECK_TYPE_THREAD && iType != CHECK_TYPE_RtlGetFullPathName_U)
	{
		CHAR __wintrustdll[] = { 'w', 'i', 'n', 't', 'r', 'u', 's', 't', '.', 'd', 'l', 'l', 0x0 }; // wintrust.dll
		CHAR __d3d9[] = { 'd', '3', 'd', '9', 0x0 }; // d3d9
		CHAR __kernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', 0x0 }; // kernel32
		CHAR __windowscodecsdll[] = { 'w', 'i', 'n', 'd', 'o', 'w', 's', 'c', 'o', 'd', 'e', 'c', 's', '.', 'd', 'l', 'l', 0x0 }; // windowscodecs.dll
		if (LPDirFunctions->IsFromWindowsPath(szName) == false &&
			!strstr(szName.c_str(), __wintrustdll) && !strstr(szName.c_str(), __d3d9) && !strstr(szName.c_str(), __kernel32) &&
			!strstr(szName.c_str(), __windowscodecsdll)
			)
		{
			if (*(pbCaller - 7) == 0x1C)
				return EaxSetWindowHookEx2; // SetWindowHookEx 2
		}
	}
	else
	{ /* iType == CHECK_TYPE_THREAD */

		if (mbiCaller.Type != MEM_IMAGE)
			return EaxCodeInjectionType; // Code injection
	}

	if (mbiCaller.AllocationProtect != PAGE_EXECUTE && mbiCaller.AllocationProtect != PAGE_EXECUTE_READ && mbiCaller.AllocationProtect != PAGE_EXECUTE_WRITECOPY)
		return EaxBadAllocatedProtectType;
		

	if (IsWindowsVistaOrGreater())
	{
		PSAPI_WORKING_SET_EX_INFORMATION pworkingSetExInformation = { 0 };
		pworkingSetExInformation.VirtualAddress = (PVOID)dwCaller;

		if (FALSE == BetaFunctionTable->QueryWorkingSetEx(NtCurrentProcess, &pworkingSetExInformation, sizeof(pworkingSetExInformation)))
			return QueryWorkingSetExFail;

		if (!pworkingSetExInformation.VirtualAttributes.Valid)
			return QueryWorkingSetExNotValid;
	}


	if ( (iType == CHECK_TYPE_THREAD || iType == CHECK_TYPE_THREAD2 || iType == CHECK_TYPE_THREAD3 || iType == CHECK_TYPE_THREAD4) &&
		LPData->GetGameCode() == METIN2_GAME)
	{
		std::string szFileName = cFileName;
		transform(szFileName.begin(), szFileName.end(), szFileName.begin(), tolower);

		std::string szExeName = LPDirFunctions->ExeNameWithPath();
		transform(szExeName.begin(), szExeName.end(), szExeName.begin(), tolower);


		if (szFileName == szExeName)
			return EaxMainProcess;

		if (strlen(cFileName) == 0 && mbiCaller.Type == MEM_PRIVATE && mbiCaller.RegionSize == 0x1000)
			return EaxMappedCode;

		if (strlen(cFileName) == 0 && mbiCaller.State == 0x1000)
			return EaxMappedCode2;
	}

	IMAGE_SECTION_HEADER * pCurrentSecHdr = (IMAGE_SECTION_HEADER*)dwCaller;
	if (pCurrentSecHdr)
		if (!pCurrentSecHdr->Characteristics)
			return NullCharacteristics;


#ifdef _DEBUG
	LPLog->DetourLog(0,"Caller Address checker passed! Address: %p", dwCaller);
#endif

	return 0;
}
#pragma optimize("", on )

void LdrInitializeThunkDetour(PCONTEXT NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrInitializeThunk called!");
#endif

	char cWarning[4096] = { 0x0 };
	CHAR __warn[] = { 'T', 'h', 'r', 'e', 'a', 'd', ':', ' ', '%', 'u', ' ', '-', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'a', 'd', 'd', 'r', 'e', 's', 's', ':', ' ', '%', 'p', ' ', '-', ' ', 'D', 'e', 't', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', ' ', '-', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!', 0x0 }; // Thread: %u - Thread address: %p - Detection Type: %d - Thread initilization blocked!

	DWORD currTID = BetaFunctionTable->GetCurrentThreadId();
	DWORD dwThreadStartAddress = NormalContext->Eax;

	int iBadAddress = CheckCallerAddress(dwThreadStartAddress, CHECK_TYPE_THREAD, "");
	if (iBadAddress) {
		sprintf(cWarning, __warn, currTID, dwThreadStartAddress, iBadAddress);
		LPFunctions->CloseProcess(cWarning, false, "");
	}

	DWORD dwStartAddress2 = LPThreads->GetThreadStartAddress(NtCurrentThread);
	if (dwStartAddress2 && dwStartAddress2 != dwThreadStartAddress) { /* spoofed address? */
		sprintf(cWarning, __warn, currTID, dwThreadStartAddress, iBadAddress);
		LPFunctions->CloseProcess(cWarning, false, "");
	}

	THREAD_BASIC_INFORMATION ThreadInfo;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationThread(NtCurrentThread, 0, &ThreadInfo, sizeof(ThreadInfo), NULL)))
	{
		DWORD hThreadOwnerPID = (DWORD)ThreadInfo.ClientId.UniqueProcess;
		if (hThreadOwnerPID != BetaFunctionTable->GetCurrentProcessId())
		{
			sprintf(cWarning, __warn, currTID, dwThreadStartAddress, 996);
			LPFunctions->CloseProcess(cWarning, false, "");
		}
	}

#ifndef _DEBUG
	DWORD dwThreadEIPContext = NormalContext->Eip;
	DWORD dwDbgUiRemoteBreakin = (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("DbgUiRemoteBreakin"));
	if ((DWORD)dwThreadEIPContext == dwDbgUiRemoteBreakin && dwThreadStartAddress == NULL)
	{
		sprintf(cWarning, __warn, currTID, dwThreadStartAddress, 997);
		LPFunctions->CloseProcess(cWarning, false, "");
	}

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T sizeQuery = BetaFunctionTable->VirtualQuery((LPCVOID)dwThreadStartAddress, &mbi, sizeof(mbi));
	if (sizeQuery && mbi.AllocationBase && mbi.AllocationBase == (PVOID)dwThreadStartAddress) { /* If thread started in page's allocated base aka. from page EP */
		sprintf(cWarning, __warn, currTID, dwThreadStartAddress, 998);
		LPFunctions->CloseProcess(cWarning, false, "");
	}

	MEMORY_BASIC_VLM_INFORMATION mbvi;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryVirtualMemory(NtCurrentProcess, (PVOID)dwThreadStartAddress, MemoryRegionInformation, &mbvi, sizeof(MEMORY_BASIC_VLM_INFORMATION), NULL)))
	{
		if (sizeQuery && mbi.State == 4096 && mbi.RegionSize >= 0x1000 && mbvi.Protection == 131072)
		{
			IMAGE_SECTION_HEADER * pCurrentSecHdr = (IMAGE_SECTION_HEADER*)dwThreadStartAddress;
			if (pCurrentSecHdr)
			{
				BOOL IsMonitored =
					(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_READ) &&
					(pCurrentSecHdr->Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

				// if (IsMonitored)
				if (IsMonitored || (!pCurrentSecHdr->Misc.PhysicalAddress && !pCurrentSecHdr->Misc.VirtualSize) /* not touched, allocated section */)
				{
					sprintf(cWarning, __warn, currTID, dwThreadStartAddress, 999);
					LPFunctions->CloseProcess(cWarning, false, "");
				}
			}
		}
	}

	if (NormalContext->Dr0) NormalContext->Dr0 = 0;
	if (NormalContext->Dr1) NormalContext->Dr1 = 0;
	if (NormalContext->Dr2) NormalContext->Dr2 = 0;
	if (NormalContext->Dr3) NormalContext->Dr3 = 0;
	if (NormalContext->Dr6) NormalContext->Dr6 = 0;
	if (NormalContext->Dr7) NormalContext->Dr7 = 0;
#endif

	return hLdrInitializeThunk.Call(NormalContext, SystemArgument1, SystemArgument2);
}


NTSTATUS NTAPI LdrLoadDLLDetour(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrLoadDll called!");
#endif

	std::wstring wszModuleName = ModuleFileName->Buffer;
	transform(wszModuleName.begin(), wszModuleName.end(), wszModuleName.begin(), towlower);
	std::string szModuleName(wszModuleName.begin(), wszModuleName.end());
	int iDetectCode = 0;

#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrLoadDll loaded module: %s", szModuleName.c_str());
#endif

	DWORD dwCurrentThreadAddress = LPThreads->GetThreadStartAddress(NtCurrentThread);
	if (!dwCurrentThreadAddress) {
#ifdef _DEBUG
		LPLog->DetourLog(0,"NtQueryInformationThread-GetThreadStartAddress failed! ( LdrLoadDLL Hook )");
#endif
		iDetectCode = 93;
		goto failure;
	}

	int iBadAddress = CheckCallerAddress(dwCurrentThreadAddress, CHECK_TYPE_LDRLOAD, szModuleName);
	if (iBadAddress) {
#ifdef _DEBUG
		LPLog->DetourLog(0,"Bad address(%d)! ( LdrLoadDLL Hook )", iBadAddress);
#endif
		iDetectCode = iBadAddress;

		goto failure;
	}

	if (wszModuleName.empty()) {
#ifdef _DEBUG
		LPLog->DetourLog(0,"Empty module name! ( LdrLoadDLL Hook )");
#endif
		iDetectCode = 94;
		goto failure;
	}

	/// If included path in module name
	WCHAR szSeparator[] = { L'\\', '\0' };
	if (wszModuleName.find(szSeparator, 0) != std::string::npos)
	{
		if (!LPDirFunctions->IsFromWindowsPath(wszModuleName) && !LPDirFunctions->IsFromCurrentPath(wszModuleName))
		{
			CHAR __mvs[] = { 'm', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'v', 'i', 's', 'u', 'a', 'l', ' ', 's', 't', 'u', 'd', 'i', 'o', 0x0 }; // microsoft visual studio
			CHAR __nvscpapidll[] = { 'n', 'v', 's', 'c', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0x0 }; // nvscpapi.dll
			if ( !strstr(szModuleName.c_str(), __nvscpapidll) && !strstr(szModuleName.c_str(), __mvs) )
			{
#ifdef _DEBUG
				LPLog->ErrorLog(0,"Is not from windows or current path(%s)! ( LdrLoadDLL Hook )", szModuleName.c_str());
#endif
				iDetectCode = 96;
				goto failure;
			}
		}
	}

	LPWinapi->DestroyEntrypoint((DWORD)&ModuleHandle);


#ifdef _DEBUG
	LPLog->DetourLog(0, "LdrLoadDLL passed, Clean dll(%s)!", szModuleName.c_str());
#endif
	return hLdrLoadDLL.Call(PathToFile, Flags, ModuleFileName, ModuleHandle);


failure:
	CHAR __warn[] = { 'D', 'l', 'l', ' ', 'I', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', ':', ' ', '%', 's', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Dll Injection blocked: %s Type: %d
	LPLog->ErrorLog(0,__warn, szModuleName.c_str(), iDetectCode);
	return ACCESS_DENIED;
}


NTSTATUS NTAPI LdrGetDllHandleExDetour(IN ULONG Flags, IN PWSTR DllPath OPTIONAL, IN PULONG DllCharacteristics OPTIONAL, IN PUNICODE_STRING DllName, OUT PVOID *DllHandle OPTIONAL)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrGetDllHandleEx called!");
#endif

	std::wstring wszModuleName = DllName->Buffer;
	std::string szModuleName(wszModuleName.begin(), wszModuleName.end());

	CHAR __s_format[] = { '%', 's', 0x0 };
	char cModuleName[1024];
	sprintf(cModuleName, __s_format, szModuleName.c_str());

#ifdef _DEBUG
	DWORD dwCaller = 0;
	__asm {
		push dword ptr[ebp + 4]
		pop  dword ptr[dwCaller]
	}

	char cFileName[2048] = { 0 };
	BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwCaller, cFileName, 2048);

	LPLog->DetourLog(0,"Module handle request to: %s from: %s", cModuleName, cFileName);
#endif

	if (strstr(cModuleName, XOR("python")))
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "LdrGetDllHandleEx Python module handle request blocked! From: %s", cFileName);
#endif
		return hLdrGetDllHandleEx.Call(Flags, DllPath, DllCharacteristics, DllName, 0);
	}

#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrGetDllHandleEx passed! (%s)", cFileName);
#endif
	return hLdrGetDllHandleEx.Call(Flags, DllPath, DllCharacteristics, DllName, DllHandle);
}

NTSTATUS NTAPI NtMapViewOfSectionDetour(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	if (LPMain->ManualMapIsReady() == false)
		goto skip;

#ifdef _DEBUG
	LPLog->DetourLog(0,"NtMapViewOfSection called!");
#endif

	if (IsWindowsXPSP1OrGreater())
	{
		DWORD dwFromProcessId = ::BetaFunctionTable->GetProcessId(ProcessHandle);
		if (!dwFromProcessId || dwFromProcessId != ::BetaFunctionTable->GetCurrentProcessId())
		{
#ifdef _DEBUG
			LPLog->DetourLog(0,"NtMapViewOfSection remote section! MyPid: %u Section's pid: %u", BetaFunctionTable->GetCurrentProcessId(), dwFromProcessId);
#endif

			CHAR __warnwname[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'a', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 't', 'o', ' ', 'g', 'a', 'm', 'e', '!', ' ', 'F', 'r', 'o', 'm', ' ', 'P', 'I', 'D', ':', ' ', '%', 'u', 0x0 }; // Unknown process access detected to game! From PID: %u

			char szRealWarn[2048] = { 0 };
			HANDLE hProc = BetaFunctionTable->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwFromProcessId);
			if (hProc) {
				auto szDosName = LPFunctions->GetProcessFullName(hProc);
				auto szProcessName = LPFunctions->DosDevicePath2LogicalPath(szDosName.c_str());
				sprintf(szRealWarn, __warnwname, szProcessName.c_str(), dwFromProcessId);
				BetaFunctionTable->CloseHandle(hProc);
			}
			else {
				auto szProcessName = LPFunctions->GetProcessFileName(dwFromProcessId);
				sprintf(szRealWarn, __warnwname, szProcessName.c_str(), dwFromProcessId);
			}

			LPLog->AddLog(0,szRealWarn);
			return ACCESS_DENIED;
		}
	}

	auto curTeb = GetCurrentTeb();
	auto nttib = curTeb->NtTib;
	auto arbitrary_user_pointer = nttib.ArbitraryUserPointer;
	if (arbitrary_user_pointer)
	{
		std::wstring const path {
			static_cast<PCWSTR>(arbitrary_user_pointer)
		};

#ifdef _DEBUG
		LPLog->DetourLog(0, "NtMapViewOfSection arbitrary_user_pointer detected! Path: %s", path.empty() ? "Empty" : LPFunctions->WstringToUTF8(path).c_str());
#endif

		if (path.empty() == false)
		{
			CHAR __warn[] = { 'I', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'm', 'e', 'm', 'o', 'r', 'y', ' ', 'b', 'l', 'o', 'c', 'k', ' ', 'i', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', ':', ' ', '%', 's', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Illegal memory block initialization blocked: %s Type: %d
			std::wstring wszModuleName = path;
			transform(wszModuleName.begin(), wszModuleName.end(), wszModuleName.begin(), towlower);
			std::string szModuleName(wszModuleName.begin(), wszModuleName.end());

			WCHAR wc_szPYD[] = { L'.', L'p', L'y', L'd', L'\0' };
			WCHAR wc_szMIX[] = { L'.', L'm', L'3', L'd', L'\0' };
			WCHAR wc_szM3D[] = { L'.', L'm', L'i', L'x', L'\0' };
			WCHAR wc_szFLT[] = { L'.', L'f', L'l', L't', L'\0' };
			WCHAR wc_szASI[] = { L'.', L'a', L's', L'i', L'\0' };
			if (!LPDirFunctions->IsFromWindowsPath(wszModuleName) && !LPDirFunctions->IsFromCurrentPath(wszModuleName))
			{
				if (!wcsstr(wszModuleName.c_str(), wc_szPYD) && !wcsstr(wszModuleName.c_str(), wc_szMIX) && !wcsstr(wszModuleName.c_str(), wc_szM3D) &&
					!wcsstr(wszModuleName.c_str(), wc_szFLT) && !wcsstr(wszModuleName.c_str(), wc_szASI))
				{
					CHAR __mvs[] = { 'm', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'v', 'i', 's', 'u', 'a', 'l', ' ', 's', 't', 'u', 'd', 'i', 'o', 0x0 }; // microsoft visual studio
					if ( !strstr(szModuleName.c_str(), __mvs) )
					{
	#ifdef _DEBUG
						LPLog->DetourLog(0, "Is not from windows or current path(%s)! ( NtMapViewOfSection Hook )", szModuleName.c_str());
	#endif
						LPLog->AddLog(0, __warn, szModuleName.c_str(), 2);
						return ACCESS_DENIED;
					}
				}
			}

#ifdef _DEBUG
			LPLog->DetourLog(0, "NtMapViewOfSection arbitrary_user_pointer clean! Path: %s", path.empty() ? "Empty" : LPFunctions->WstringToUTF8(path).c_str());
#endif
		}
	}


skip:
	return hNtMapViewOfSection.Call(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
}



ULONG NTAPI RtlGetFullPathName_UDetour(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName)
{
#ifdef _DEBUG
	LPLog->DetourLog(0, "RtlGetFullPathName_U called!");
#endif

	// Process source string
	_bstr_t bstrSourceString(FileName);
	const char* c_szSourceString = bstrSourceString;
	std::string szSourceString(c_szSourceString, strnlen(c_szSourceString, MAX_PATH));
	transform(szSourceString.begin(), szSourceString.end(), szSourceString.begin(), tolower);
	std::wstring wszSourceString(szSourceString.begin(), szSourceString.end());

	std::string szExeNameWithPath = LPDirFunctions->ExeNameWithPath();
	transform(szExeNameWithPath.begin(), szExeNameWithPath.end(), szExeNameWithPath.begin(), tolower);

	CHAR __BetaCoredll[] = { 'b', 'e', 't', 'a', 'c', 'o', 'r', 'e', 0x0 }; // betacore
	std::string szExePath = LPDirFunctions->ExePath();
	transform(szExePath.begin(), szExePath.end(), szExePath.begin(), tolower);

#ifdef _DEBUG
	LPLog->DetourLog(0,"RtlGetFullPathName_U called string: %s", szSourceString.c_str());
#endif

	DWORD dwCurrentThreadAddress = LPThreads->GetThreadStartAddress(NtCurrentThread);
	if (dwCurrentThreadAddress)
	{
		int iBadAddress = CheckCallerAddress(dwCurrentThreadAddress, CHECK_TYPE_RtlGetFullPathName_U, "");
		if (iBadAddress) {
#ifdef _DEBUG
			LPLog->DetourLog(0, "Bad address(%d)! ( RtlGetFullPathName_U Hook )", iBadAddress);
#endif
			CHAR __warn[] = { 'I', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', ':', ' ', '%', 's', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Injection blocked: %s Type: %d
			LPLog->ErrorLog(0, __warn, szSourceString.c_str(), iBadAddress);

			return ACCESS_DENIED;
		}
	}

	if (LPDirFunctions->is_file_exist(szSourceString) == false) {
#ifdef _DEBUG
		LPLog->DetourLog(0, "RtlGetFullPathName_U Hook: Triggered string is not a file: %s | passed...", szSourceString.c_str());
#endif
		goto skip;
	}

	// If this file is digital signed, pass it.
	static BOOL bSignRet = FALSE;
	LPScan->IsSignedFile(wszSourceString.c_str(), &bSignRet);
	if (bSignRet == FALSE && LPDirFunctions->IsFromWindowsPath(wszSourceString))
	{
#ifdef _DEBUG
		LPLog->DetourLog(0, "RtlGetFullPathName_U returned module is from windows! %s passed!", szSourceString.c_str());
#endif
		goto skip;
	}
	else if (bSignRet == TRUE && LPDirFunctions->IsFromWindowsPath(wszSourceString))
	{
#ifdef _DEBUG
		LPLog->DetourLog(0, "RtlGetFullPathName_U returned module is signed! %s passed!", szSourceString.c_str());
#endif
		goto skip;
	}

	// If in the source string have a anticheat module name pass it.
	if (strstr(szSourceString.c_str(), szExePath.c_str()))
	{
		if (strstr(szSourceString.c_str(), __BetaCoredll))
		{
#ifdef _DEBUG
			LPLog->DetourLog(0, "RtlGetFullPathName_U returned module is anticheat! %s passed!", szSourceString.c_str());
#endif
			goto skip;
		}

		WCHAR wc_szPYD[] = { L'.', L'p', L'y', L'd', L'\0' };
		WCHAR wc_szMIX[] = { L'.', L'm', L'3', L'd', L'\0' };
		WCHAR wc_szM3D[] = { L'.', L'm', L'i', L'x', L'\0' };
		WCHAR wc_szFLT[] = { L'.', L'f', L'l', L't', L'\0' };
		WCHAR wc_szASI[] = { L'.', L'a', L's', L'i', L'\0' };
		if (wcsstr(wszSourceString.c_str(), wc_szPYD) || wcsstr(wszSourceString.c_str(), wc_szMIX) || wcsstr(wszSourceString.c_str(), wc_szM3D) ||
			wcsstr(wszSourceString.c_str(), wc_szFLT) || wcsstr(wszSourceString.c_str(), wc_szASI))
		{
#ifdef _DEBUG
			LPLog->DetourLog(0, "RtlGetFullPathName_U returned with special extension, passed(%s)!", szSourceString.c_str());
#endif
			goto skip;
		}
	}

	// If in the source string have a main process name pass it (windows xp and vista generic problem).
	if (strstr(szSourceString.c_str(), szExeNameWithPath.c_str())) {
#ifdef _DEBUG
		LPLog->DetourLog(0, "RtlGetFullPathName_U returned with main process!");
#endif
		goto skip;
	}



	PVOID lpModuleBase = LPWinapi->GetModuleAddressFromName(FileName);
	if (lpModuleBase) {
#ifdef _DEBUG
		LPLog->DetourLog(0, "RtlGetFullPathName_U returned string detected as module! %s", szSourceString.c_str());
#endif

		char szRealWarn[1024];
		CHAR __warn[] = { 'D', 'L', 'L', ' ', 'L', 'o', 'a', 'd', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'a', 'n', 'd', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!', ' ', 'D', 'L', 'L', ':', ' ', '%', 's', 0x0 }; // DLL Load detected and blocked! DLL: %s
		sprintf(szRealWarn, XOR(__warn), szSourceString.c_str());
		LPLog->ErrorLog(0, szRealWarn);

		if (!NT_SUCCESS(BetaFunctionTable->NtUnmapViewOfSection(NtCurrentProcess, lpModuleBase))) {
			char szRealWarn2[1024];
			CHAR __warn2[] = { 'D', 'L', 'L', ' ', 't', 'e', 'r', 'm', 'i', 'n', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'D', 'L', 'L', ':', ' ', '%', 's', 0x0 }; // DLL termination failed! DLL: %s
			sprintf(szRealWarn2, __warn2, szSourceString.c_str());

			LPFunctions->CloseProcess(szRealWarn2, false, "");
		}

	}

skip:
	return hRtlGetFullPathName_U.Call(FileName, Size, Buffer, ShortName);
}

bool bConnectChecked = false;
int WINAPI connectDetour(SOCKET s, const struct sockaddr* name, int namelen)
{
	KARMA_MACRO_2
	CUtils lpUtils;
	if (lpUtils.IsFlaggedForExit())
		return 0;

#ifdef BLOCK_CONNECTIONS
	return 0;
#endif

#ifdef LICENSE_CHECK
	KARMA_MACRO_1
	sockaddr_in sockInfo = *(sockaddr_in*)name;

	if (bConnectChecked) {
		KARMA_MACRO_1
		LPFile_Verification->CheckFileVerification(BetaFunctionTable->inet_ntoa(sockInfo.sin_addr));
		return hconnect.Call(s, name, namelen);
	}
	KARMA_MACRO_2

	const char* c_szConnectedTo = BetaFunctionTable->inet_ntoa(sockInfo.sin_addr);
	CHAR __localhost[] = { '1', '2', '7', '.', '0', '.', '0', '.', '1', 0x0 }; // crashreport pls

#ifdef _DEBUG
	LPLog->DetourLog(0,"Connection: %s detected!", c_szConnectedTo);
#endif

	KARMA_MACRO_1
	if (false == LPInternetAPI->IsLicensedIp(c_szConnectedTo) && strcmp(c_szConnectedTo, __localhost))
	{
#ifdef _DEBUG
		LPLog->DetourLog(0, "Unknown Connection: %s blocked!", c_szConnectedTo);
#endif
		return 0;
	}

#ifdef _DEBUG
	LPLog->DetourLog(0,"Connected to: %s", c_szConnectedTo);
#endif

	bConnectChecked = true;

	KARMA_MACRO_2
	LPFile_Verification->CheckFileVerification(BetaFunctionTable->inet_ntoa(sockInfo.sin_addr));
#endif

	return hconnect.Call(s, name, namelen);
}


ULONG WINAPI _RtlDispatchException(PEXCEPTION_RECORD ExceptionInfo, CONTEXT * pContext)
{
	CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', ' ', 'o', 'c', 'c', 'u', 'r', 'e', 'd', ' ', '(', '%', 'd', ')', 0x0 }; // Unknown exception occured (%d)
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		LPLog->ErrorLog(0, __warn, 5);
		abort();
	}
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		LPLog->ErrorLog(0, __warn, 6);
		abort();
	}

	return m_fnRtlDispatchException(ExceptionInfo, pContext);
}
BOOL InitKiUserExceptionDispatcherHook()
{
	BOOL bResult = FALSE;

	CHAR __KiUserExceptionDispatcher[] = { 'K', 'i', 'U', 's', 'e', 'r', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'D', 'i', 's', 'p', 'a', 't', 'c', 'h', 'e', 'r', 0x0 }; // KiUserExceptionDispatcher
	BYTE *pAddr = (BYTE *)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, __KiUserExceptionDispatcher);
	if (pAddr)
	{
		while (*pAddr != 0xE8)
			pAddr++;

		m_fnRtlDispatchException = (pfnRtlDispatchException)((*(DWORD *)(pAddr + 1)) + 5 + (DWORD)pAddr);
		DWORD dwNewAddr = (DWORD)_RtlDispatchException - (DWORD)pAddr - 5;
		DWORD dwOld;
		BetaFunctionTable->VirtualProtect((LPVOID)pAddr, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld);
		nkt_memcopy((PVOID)((DWORD)pAddr + 1), (PVOID)&dwNewAddr, 4);
		bResult = TRUE;
	}

	return bResult;
}

NTSTATUS NTAPI NtDelayExecutionRoutine(BOOL Alertable, PLARGE_INTEGER DelayInterval)
{
	DWORD dwCaller = 0;
	__asm {
		push dword ptr[ebp + 4]
		pop  dword ptr[dwCaller]
	}
	CHAR __SleepEx[] = { 'S', 'l', 'e', 'e', 'p', 'E', 'x', 0x0 }; // SleepEx
	CHAR __Sleep[] = { 'S', 'l', 'e', 'e', 'p', 0x0 }; // Sleep


	if (BetaModuleTable->hKernelbase)
	{
		auto kernelbaseSleepEx = (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernelbase, __SleepEx);
		auto dif1 = dwCaller - kernelbaseSleepEx;
		auto dif11 = kernelbaseSleepEx - dwCaller;
		if (dif1 < 0xFF || dif11 < 0xFF)
			goto skip;

		auto kernelbaseSleep = (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernelbase, __Sleep);
		auto dif2 = dwCaller - kernelbaseSleep;
		auto dif21 = kernelbaseSleep - dwCaller;
		if (dif2 < 0xFF || dif21 < 0xFF)
			goto skip;
	}

	auto kernelSleep = (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, __Sleep);
	auto dif3 = dwCaller - kernelSleep;
	auto dif31 = kernelSleep - dwCaller;
	if (dif3 < 0xFF || dif31 < 0xFF)
		goto skip;

	auto kernelSleepEx = (DWORD)BetaFunctionTable->GetProcAddress(BetaModuleTable->hKernel32, __SleepEx);
	auto dif4 = dwCaller - kernelSleepEx;
	auto dif41 = kernelSleepEx - dwCaller;
	if (dif4 < 0xFF || dif41 < 0xFF)
		goto skip;


	char cFileName[2048] = { 0 };
	if (BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwCaller, cFileName, 2048))
	{
		CHAR __kernel32dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // kernel32.dll
		CHAR __kernelbasedll[] = { 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l', 0x0 }; // kernelbase.dll

		if (LPDirFunctions->IsFromWindowsPath(cFileName))
			if (strstr(cFileName, __kernel32dll) || strstr(cFileName, __kernelbasedll))
				goto skip;
	}

	LPLog->ErrorLog(0, XOR("Wait request coming from unknown target! %s:%p Skipped!"), cFileName, dwCaller);
	return 0;
skip:
	return hNtDelayExecution.Call(Alertable, DelayInterval);
}

NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert)
{
	if (ThreadContext)
	{
		auto dwThreadEax = ThreadContext->Eax;
		auto dwThreadEIP = ThreadContext->Eip;
		if (dwThreadEax || dwThreadEIP)
		{
			char cWarning[4096] = { 0x0 };
			CHAR __warn[] = { 'T', 'h', 'r', 'e', 'a', 'd', ':', ' ', '%', 'u', ' ', '-', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'a', 'd', 'd', 'r', 'e', 's', 's', ':', ' ', '%', 'p', ' ', '-', ' ', 'D', 'e', 't', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', ' ', '-', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!', 0x0 }; // Thread: %u - Thread address: %p - Detection Type: %d - Thread initilization blocked!

#ifdef _DEBUG
			LPLog->DetourLog(0, "NtContinue Called: Eax: %p Eip: %p", dwThreadEax, dwThreadEIP);
#endif

			auto dwThreadId = LPThreads->GetThreadIdFromAddress(dwThreadEax);
			if (dwThreadId) {
#ifdef _DEBUG
				LPLog->DetourLog(0, "NtContinue Called eax is a thread! Thread ID: %u Checking..." , dwThreadId);
#endif
				LPScan->CheckThread(dwThreadId, true);

				int iBadAddress = CheckCallerAddress(dwThreadEax, CHECK_TYPE_THREAD3, "");
				if (iBadAddress) {
					sprintf(cWarning, __warn, dwThreadId, dwThreadEax, iBadAddress);
					LPFunctions->CloseProcess(cWarning, false, "");
				}
			}
			auto dwThreadId2 = LPThreads->GetThreadIdFromAddress(dwThreadEIP);
			if (dwThreadId2) {
#ifdef _DEBUG
				LPLog->DetourLog(0, "NtContinue Called eip is a thread! Thread ID: %u Checking...", dwThreadId2);
#endif
				LPScan->CheckThread(dwThreadId2, true);

				int iBadAddress = CheckCallerAddress(dwThreadEIP, CHECK_TYPE_THREAD3, "");
				if (iBadAddress) {
					sprintf(cWarning, __warn, dwThreadId2, dwThreadEIP, iBadAddress);
					LPFunctions->CloseProcess(cWarning, false, "");
				}
			}
		}
	}

	return hNtContinue.Call(ThreadContext, RaiseAlert);
}


inline void CheckWindowForAccess(const char* c_szFileName, int iType)
{
	if (!strstr(c_szFileName, LPFunctions->GetAnticheatFilename().c_str()))
	{
		char szRealWarn[2048];
		CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'a', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 't', 'e', 'c', 't', ' ', 't', 'o', ' ', 'g', 'a', 'm', 'e', ' ', 'w', 'i', 'n', 'd', 'o', 'w', '!', ' ', 'F', 'r', 'o', 'm', ':', ' ', '%', 's', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Unknown access detect to game window! From: %s Type: %d
		sprintf(szRealWarn, __warn, c_szFileName, iType);
		LPFunctions->CloseProcess(szRealWarn, false, "");
	}
}

LONG WINAPI SetWindowLongADetour(HWND hWnd, int nIndex, LONG dwNewLong)
{
	if (dwNewLong)
	{
		__try {
#ifdef _DEBUG
			LPLog->DetourLog(0, "SetWindowLongA called for: %p Index: %u NewValue: %s", hWnd, nIndex, dwNewLong);
#endif

			if (LPWatchdog->IsWatchdogWindow(hWnd) && nIndex == GWL_WNDPROC) {
				char cFileName[2048] = { 0 };
				BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwNewLong, cFileName, 2048);
#ifdef _DEBUG
				LPLog->ErrorLog(0, "SetWindowLongA called for: %p Index: %u NewValue: %s NewValue Owner: %s", hWnd, nIndex, dwNewLong, cFileName);
#endif

				CheckWindowForAccess(cFileName, 1);
			}
		}
		__except (1)
		{
		}
	}

	return hSetWindowLongA.Call(hWnd, nIndex, dwNewLong);
}

LONG WINAPI SetWindowLongWDetour(HWND hWnd, int nIndex, LONG dwNewLong)
{
	if (dwNewLong)
	{
		__try {
#ifdef _DEBUG
			LPLog->DetourLog(0, "SetWindowLongW called for: %p Index: %u NewValue: %s", hWnd, nIndex, dwNewLong);
#endif

			if (LPWatchdog->IsWatchdogWindow(hWnd) && nIndex == GWL_WNDPROC) {
				char cFileName[2048] = { 0 };
				BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwNewLong, cFileName, 2048);
#ifdef _DEBUG
				LPLog->ErrorLog(0, "SetWindowLongW called for: %p Index: %u NewValue: %s NewValue Owner: %s", hWnd, nIndex, dwNewLong, cFileName);
#endif

				CheckWindowForAccess(cFileName, 2);
			}
		}
		__except (1)
		{
		}
	}

	return hSetWindowLongW.Call(hWnd, nIndex, dwNewLong);
}


#ifdef TERMINATE_HOOK
NTSTATUS NTAPI HookedNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	LPLog->ErrorLog(0, "!!! Terminate called !!!! Process suspended!!");
	LPFunctions->CsrssMessageBox(L"!!! Terminate called !!!! Process suspended!!", L"!ERROR!");
	BetaFunctionTable->NtSuspendProcess(NtCurrentProcess);

	return hNtTerminateProcess.Call(ProcessHandle, ExitStatus);
}
#endif


enum {
	RET_HOOK = 1,
	NOP_HOOK,
};
inline void CSelfApiHooks::BlockAPI(LPCTSTR lpModule, LPCSTR lpFuncName, int iType)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"%s!%s api block initilization has been start!", lpModule, lpFuncName);
#endif

	DWORD pPrevious, pPrevious2;

	DWORD dwAddr = 0;
	if (!__STRCMPI__(XOR("python"), lpModule))
		dwAddr = (DWORD)BetaFunctionTable->_GetProcAddress(BetaModuleTable->hPython, lpFuncName);
	else
		dwAddr = (DWORD)BetaFunctionTable->_GetProcAddress(BetaFunctionTable->_GetModuleHandle(lpModule), lpFuncName);

	CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'C', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'g', 'e', 't', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'A', 'P', 'I', ' ', 'a', 'd', 'd', 'r', 'e', 's', 's', 0x0 }; // ERROR! Can not get Windows API address
	CHAR __warn1[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'A', 'P', 'I', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', '[', '0', 'x', '1', ']', 0x0 }; // ERROR! Windows API failed! Error[0x1]
	CHAR __warn2[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'A', 'P', 'I', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', '[', '0', 'x', '2', ']', 0x0 }; // ERROR! Windows API failed! Error[0x2]

	if (!dwAddr)
		LPFunctions->CloseProcess(XOR(__warn), false, "");

	if (iType == RET_HOOK) {
		BYTE ret[6] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

		if (!BetaFunctionTable->VirtualProtect((LPVOID)dwAddr, 6, PAGE_EXECUTE_READWRITE, &pPrevious))
			LPFunctions->CloseProcess(XOR(__warn1), false, "");

		nkt_memcopy((void*)(dwAddr), &ret, 6);

		if (!BetaFunctionTable->VirtualProtect((LPVOID)dwAddr, 6, pPrevious, &pPrevious2))
			LPFunctions->CloseProcess(XOR(__warn2), false, "");
	}
	else if (iType == NOP_HOOK) {
		BYTE ret[1] = { 0x90 };

		if (!BetaFunctionTable->VirtualProtect((LPVOID)dwAddr, 1, PAGE_EXECUTE_READWRITE, &pPrevious))
			LPFunctions->CloseProcess(XOR(__warn1), false, "");

		nkt_memcopy((void*)(dwAddr), &ret, 1);

		if (!BetaFunctionTable->VirtualProtect((LPVOID)dwAddr, 1, pPrevious, &pPrevious2))
			LPFunctions->CloseProcess(XOR(__warn2), false, "");
	}

#ifdef _DEBUG
	LPLog->DetourLog(0, "%s!%s succesfuly banned! Type: %d", lpModule, lpFuncName, iType);
#endif
}






inline void SelfApiHooks_InitializePatchs()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"API Patch Initilization has been started!");
#endif

#ifndef _DEBUG
	LPSelfApiHooks->BlockAPI(XOR("kernel32.dll"), XOR("AllocConsole"), NOP_HOOK);
	LPSelfApiHooks->BlockAPI(XOR("kernel32.dll"), XOR("GetConsoleWindow"), NOP_HOOK);

	LPSelfApiHooks->BlockAPI(XOR("ntdll.dll"), XOR("DbgUiIssueRemoteBreakin"), RET_HOOK);
	LPSelfApiHooks->BlockAPI(XOR("ntdll.dll"), XOR("DbgUiRemoteBreakin"), RET_HOOK);
	LPSelfApiHooks->BlockAPI(XOR("ntdll.dll"), XOR("DbgBreakPoint"), NOP_HOOK);
	LPSelfApiHooks->BlockAPI(XOR("ntdll.dll"), XOR("DbgUserBreakPoint"), NOP_HOOK);
#endif

	LPSelfApiHooks->BlockAPI(XOR("ntdll.dll"), XOR("RtlRemoteCall"), NOP_HOOK);

	//if (BetaModuleTable->hPython)
	//{
		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyRun_SimpleString"), RET_HOOK);
		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyRun_SimpleFile"), RET_HOOK);
		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyRun_SimpleFileEx"), RET_HOOK);

		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyRun_FileExFlags"), RET_HOOK);
		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyFile_FromFile"), RET_HOOK);
		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyParser_ASTFromFile"), RET_HOOK);
		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyParser_ASTFromString"), NOP_HOOK);

		//lpApiHooks.BlockAPI(XOR("python"), XOR("PyFile_FromString"), RET_HOOK);
	//}

#ifdef _DEBUG
	LPLog->AddLog(0,"API Patch Initilization completed!");
#endif
}


inline void SelfApiHooks_InitializeDetours()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Detours Initilization has been started!");
#endif

	CNktHookLib * CNktHook = new CNktHookLib();
#ifdef _DEBUG
	CNktHook->SetEnableDebugOutput(true);
#else
	CNktHook->SetEnableDebugOutput(false);
#endif


	int iFailAttempt = 0;
	DWORD dwErrCode = 0;
	LPVOID fnAddress = 0;

	CHAR __connect[] = { 'c', 'o', 'n', 'n', 'e', 'c', 't', 0x0 }; // connect
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hWs2_32, __connect);
	dwErrCode += (CNktHook->Hook(&(hconnect.Id), (LPVOID*)&(hconnect.Call), fnAddress, connectDetour, 0));
	if (dwErrCode) {
		iFailAttempt = 1;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ws2_32!connect detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}

	if (IsWindowsVistaOrGreater())
	{
		CHAR __LdrInitializeThunk[] = { 'L', 'd', 'r', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'T', 'h', 'u', 'n', 'k', 0x0 }; // LdrInitializeThunk
		fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, __LdrInitializeThunk);
		dwErrCode += (CNktHook->Hook(&(hLdrInitializeThunk.Id), (LPVOID*)&(hLdrInitializeThunk.Call), fnAddress, LdrInitializeThunkDetour, 0));
		if (dwErrCode) {
			iFailAttempt = 2;
#ifdef _DEBUG
			LPLog->ErrorLog(0, "ntdll!LdrInitializeThunk detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
			goto end;
		}

		CHAR __RtlGetFullPathName_U[] = { 'R', 't', 'l', 'G', 'e', 't', 'F', 'u', 'l', 'l', 'P', 'a', 't', 'h', 'N', 'a', 'm', 'e', '_', 'U', 0x0 }; // RtlGetFullPathName_U
		fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, __RtlGetFullPathName_U);
		dwErrCode += (CNktHook->Hook(&(hRtlGetFullPathName_U.Id), (LPVOID*)&(hRtlGetFullPathName_U.Call), fnAddress, RtlGetFullPathName_UDetour, 0));
		if (dwErrCode) {
			iFailAttempt = 3;
#ifdef _DEBUG
			LPLog->ErrorLog(0, "ntdll!RtlGetFullPathName_U detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
			goto end;
		}

	}

	if (IsWindows7OrGreater())
	{
		if (LPData->GetGameCode() != TEST_CONSOLE)
		{
			CHAR __LdrLoadDLL[] = { 'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'L', 'L', 0x0 }; // LdrLoadDLL
			fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, __LdrLoadDLL);
			dwErrCode += (CNktHook->Hook(&(hLdrLoadDLL.Id), (LPVOID*)&(hLdrLoadDLL.Call), fnAddress, LdrLoadDLLDetour, 0));
			if (dwErrCode) {
				iFailAttempt = 4;
#ifdef _DEBUG
				LPLog->ErrorLog(0, "ntdll!LdrLoadDLL detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
				goto end;
			}
		}

		CHAR ldrgetdllhandleex[] = { 'L', 'd', 'r', 'G', 'e', 't', 'D', 'l', 'l', 'H', 'a', 'n', 'd', 'l', 'e', 'E', 'x', 0x0 }; // LdrGetDllHandleEx
		fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, ldrgetdllhandleex);
		dwErrCode += (CNktHook->Hook(&(hLdrGetDllHandleEx.Id), (LPVOID*)&(hLdrGetDllHandleEx.Call), fnAddress, LdrGetDllHandleExDetour, 0));
		if (dwErrCode) {
			iFailAttempt = 5;
#ifdef _DEBUG
			LPLog->ErrorLog(0, "ntdll!LdrGetDllHandleEx detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
			goto end;
		}
		
	}


	CHAR __NtMapViewOfSection[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', 0x0 }; // NtMapViewOfSection
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, __NtMapViewOfSection);
	dwErrCode += (CNktHook->Hook(&(hNtMapViewOfSection.Id), (LPVOID*)&(hNtMapViewOfSection.Call), fnAddress, NtMapViewOfSectionDetour, 0));
	if (dwErrCode) {
		iFailAttempt = 7;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ntdll!NtMapViewOfSection detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}

	if (InitKiUserExceptionDispatcherHook() == FALSE) {
		dwErrCode++;
		iFailAttempt = 8;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ntdll!KiUserExceptionDispatcher hook init fail. Addr: %p", fnAddress);
#endif
		goto end;
	}

	CHAR __NtDelayExecution[] = { 'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', 0x0 }; // NtDelayExecution
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, __NtDelayExecution);
	dwErrCode += (CNktHook->Hook(&(hNtDelayExecution.Id), (LPVOID*)&(hNtDelayExecution.Call), fnAddress, NtDelayExecutionRoutine, 0));
	if (dwErrCode) {
		iFailAttempt = 9;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ntdll!NtDelayExecution detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}

	/*
	CHAR __NtContinue[] = { 'N', 't', 'C', 'o', 'n', 't', 'i', 'n', 'u', 'e', 0x0 }; // NtContinue
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, __NtContinue);
	dwErrCode += (CNktHook->Hook(&(hNtContinue.Id), (LPVOID*)&(hNtContinue.Call), fnAddress, HookedNtContinue, 0));
	if (dwErrCode) {
		iFailAttempt = 10;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ntdll!NtContinue detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}
	*/

	CHAR __SetWindowLongA[] = { 'S', 'e', 't', 'W', 'i', 'n', 'd', 'o', 'w', 'L', 'o', 'n', 'g', 'A', 0x0 }; // SetWindowLongA
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hUser32, __SetWindowLongA);
	dwErrCode += (CNktHook->Hook(&(hSetWindowLongA.Id), (LPVOID*)&(hSetWindowLongA.Call), fnAddress, SetWindowLongADetour, 0));
	if (dwErrCode) {
		iFailAttempt = 11;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "user32!SetWindowLongA detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}

	CHAR __SetWindowLongW[] = { 'S', 'e', 't', 'W', 'i', 'n', 'd', 'o', 'w', 'L', 'o', 'n', 'g', 'W', 0x0 }; // SetWindowLongW
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hUser32, __SetWindowLongW);
	dwErrCode += (CNktHook->Hook(&(hSetWindowLongW.Id), (LPVOID*)&(hSetWindowLongW.Call), fnAddress, SetWindowLongWDetour, 0));
	if (dwErrCode) {
		iFailAttempt = 12;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "user32!SetWindowLongW detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}

#ifdef TERMINATE_HOOK
	fnAddress = NktHookLibHelpers::GetProcedureAddress(BetaModuleTable->hNtdll, "NtTerminateProcess");
	dwErrCode += (CNktHook->Hook(&(hNtTerminateProcess.Id), (LPVOID*)&(hNtTerminateProcess.Call), fnAddress, HookedNtTerminateProcess, 0));
	if (dwErrCode) {
		iFailAttempt = 13;
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ntdll!NtTerminateProcess detour init fail. Addr: %p Err: %u", fnAddress, dwErrCode);
#endif
		goto end;
	}
#endif


end:
	if (dwErrCode) {
		char szWarn[1024];
		sprintf(szWarn, XOR("Detours can not initialized! Error code: %u Step: %d"), dwErrCode, iFailAttempt);
		LPFunctions->CloseProcess(szWarn, false, "");
	}


#ifdef _DEBUG
	LPLog->AddLog(0, "Detours Initilization completed!");
#endif
}


void CSelfApiHooks::InitializeHookAPIs()
{
	KARMA_MACRO_1
	SelfApiHooks_InitializePatchs();

	KARMA_MACRO_2
	SelfApiHooks_InitializeDetours();

	KARMA_MACRO_2
	bAPI_Hooks_Is_Initialized = true;

	KARMA_MACRO_1
}
