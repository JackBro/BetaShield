#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "DirFuncs.h"

#include "Threads.h"
#include "XOR.h"
#include "CLog.h"


CScan* LPScan;
CScan::CScan()
{
}

CScan::~CScan()
{
}

enum EThreadBlockTypes {
	THREAD_BLOCK_MODULENAME = 1,
	THREAD_BLOCK_OWNERPROC,
	THREAD_BLOCK_CONTEXT,
	THREAD_BLOCK_MODULETYPE,
	THREAD_BLOCK_ADDRESS_MODINFO,
	THREAD_BLOCK_ADDRESS_EIP
};

__forceinline void CloseThread(HANDLE hThread, DWORD dwThreadId, int iType, DWORD dwStartAddress, const char* c_szOwner)
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0, "*** Close thread event started! Thread: %p[%u] Start Address: %u Type: %d Owner: %s", hThread, dwThreadId, dwStartAddress, iType, c_szOwner);
#endif

	char szRealWarn[1024];
	CHAR __warn[] = { 'I', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'a', 'n', 'd', ' ', 'b', 'l', 'o', 'c', 'k', 'e', 'd', '!', ' ', 'O', 'w', 'n', 'e', 'r', ':', ' ', '%', 's', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Illegal Thread detected and blocked! Owner: %s Type: %d
	sprintf(szRealWarn, __warn, c_szOwner, iType);
	LPLog->ErrorLog(0, szRealWarn);

	ULONG ret = BetaFunctionTable->NtUnmapViewOfSection(NtCurrentProcess, (PVOID)dwStartAddress);
	DWORD result = BetaFunctionTable->WaitForSingleObject(hThread, 0);
	if (ret != STATUS_SUCCESS || result == WAIT_TIMEOUT) { /* So it is still alive */
		char szRealWarn2[1024];
		CHAR __warn2[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 't', 'h', 'r', 'e', 'a', 'd', ' ', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'O', 'w', 'n', 'e', 'r', ':', ' ', '%', 's', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Process thread integrity failed! Owner: %s Type: %d
		sprintf(szRealWarn2, __warn2, c_szOwner, iType);
		lpFuncs.CloseProcess(szRealWarn2, false, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "*** Thread: %u closed. Type: %d", dwThreadId, iType);
#endif
}

__forceinline void CheckThreadModuleName(HANDLE hThread, DWORD dwThreadId, DWORD dwStartAddress, const char* c_szOwner)
{
	/// Step1: Game process self process
	CDirFunctions lpDirFuncs;
	std::string szExeName = lpDirFuncs.ExeName();
	transform(szExeName.begin(), szExeName.end(), szExeName.begin(), tolower);

	if (strlen(c_szOwner) < 3 /* Allocated memory */ || strstr(c_szOwner, szExeName.c_str()) /* for without exe extensions */) {
#ifdef _DEBUG
		LPLog->AddLog(-1, "Whitelisted name '%s', passed..", c_szOwner);
#endif
		return;
	}

	/// Step2: Anticheat module
	CHAR __BetaCoredll[] = { 'b', 'e', 't', 'a', 'c', 'o', 'r', 'e', 0x0 }; // betacore
	CHAR __tmp[] = { '.', 't', 'm', 'p', 0x0 }; // .tmp - For Enigma protector, virtualized files

	if (strstr(c_szOwner, __BetaCoredll) || strstr(c_szOwner, __tmp)) {
#ifdef _DEBUG
		LPLog->AddLog(-1, "Anticheat thread! passed.. %s", c_szOwner);
#endif
		return;
	}

	/// Step3: Whitelist modules
	CHAR __kernel32dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 }; //kernel32.dll
	CHAR __ntdlldll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 }; // ntdll.dll
	CHAR __dsounddll[] = { 'd', 's', 'o', 'u', 'n', 'd', '.', 'd', 'l', 'l', 0x0 }; // dsound.dll
	CHAR __mss32dll[] = { 'm', 's', 's', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // mss32.dll
	CHAR __dinput8dll[] = { 'd', 'i', 'n', 'p', 'u', 't', '8', '.', 'd', 'l', 'l', 0x0 }; // dinput8.dll
	CHAR __crashrptdll[] = { 'c', 'r', 'a', 's', 'h', 'r', 'p', 't', '.', 'd', 'l', 'l', 0x0 }; // crashrpt.dll
	CHAR __hmipcoredll[] = { 'h', 'm', 'i', 'p', 'c', 'o', 'r', 'e', '.', 'd', 'l', 'l', 0x0 }; // hmipcore.dll
	CHAR __mswsockdll[] = { 'm', 's', 'w', 's', 'o', 'c', 'k', '.', 'd', 'l', 'l', 0x0 }; // mswsock.dll
	CHAR __ws2_32dll[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // ws2_32.dll
	CHAR __combasedll[] = { 'c', 'o', 'm', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l', 0x0 }; // combase.dll
	CHAR __wininetdll[] = { 'w', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', 0x0 }; // wininet.dll
	CHAR __crypt32[] = { 'c', 'r', 'y', 'p', 't', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // crypt32.dll
	CHAR __advapi32[] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // advapi32.dll
	CHAR __ole32[] = { 'o', 'l', 'e', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // ole32.dll
	// TODO : rasman.dll 

	char* szWhiteListThreadOwners[] = {
		__kernel32dll, __ntdlldll, __dsounddll, __mss32dll, __dinput8dll, __crashrptdll,
		__hmipcoredll, __mswsockdll, __ws2_32dll, __combasedll, __crypt32, __advapi32, __ole32 /* , __wininetdll */
	};

	bool bIsWhiteModule = false;
	for (int i = 0; i < _countof(szWhiteListThreadOwners); i++)
		if (strstr(c_szOwner, szWhiteListThreadOwners[i]))
			bIsWhiteModule = true;
	
	if (bIsWhiteModule == false)
		CloseThread(hThread, dwThreadId, THREAD_BLOCK_MODULENAME, dwStartAddress, c_szOwner);
}

__forceinline void CheckThreadOwnerProcess(HANDLE hThread, DWORD dwThreadId, DWORD dwStartAddress, const char* c_szOwner)
{
	THREAD_BASIC_INFORMATION ThreadInfo;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationThread(hThread, 0, &ThreadInfo, sizeof(ThreadInfo), NULL)))
	{
		KARMA_MACRO_1

		DWORD hThreadOwnerPID = (DWORD)ThreadInfo.ClientId.UniqueProcess;
		bool bIsRemoteThread = (hThreadOwnerPID != BetaFunctionTable->GetCurrentProcessId());

		/* Injected thread aka. remote thread */
		if (bIsRemoteThread)
			CloseThread(hThread, dwThreadId, THREAD_BLOCK_OWNERPROC, dwStartAddress, c_szOwner);
	}
}

__forceinline void CheckThreadContexts(HANDLE hThread, DWORD dwThreadId, DWORD dwStartAddress, const char* c_szOwner)
{
	int iErrorCode = 0;
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = 0x1008c ^ 0x9C;

	// If can not get thread contexts..
	if (!BetaFunctionTable->GetThreadContext(hThread, &ctx)) {
		return;
		//iErrorCode = 1;
	}

	// Check context values
	bool bChanged = false;
	int iDr0Trace = 0;
	int iDr1Trace = 0;
	int iDr2Trace = 0;
	int iDr3Trace = 0;


	if (ctx.Dr0)
		iDr0Trace = 1;
	else if (ctx.Dr1)
		iDr1Trace = 1;
	else if (ctx.Dr2)
		iDr2Trace = 1;
	else if (ctx.Dr3)
		iDr3Trace = 1;

	// Set null to contexts
	if (iDr0Trace || iDr1Trace || iDr2Trace || iDr3Trace || ctx.Dr7) {
		ctx.Dr7 = 0;
		bChanged = true;
	}

	if (iDr0Trace)
		ctx.Dr0 = 0;
	if (iDr1Trace)
		ctx.Dr1 = 0;
	if (iDr2Trace)
		ctx.Dr2 = 0;
	if (iDr3Trace)
		ctx.Dr3 = 0;


	if (bChanged && NtCurrentThread != hThread)
	{
		// If can not set modified thread contexts..
		if (!BetaFunctionTable->SuspendThread(hThread))
			iErrorCode = 2;

		if (!BetaFunctionTable->SetThreadContext(hThread, &ctx))
			iErrorCode = 3;

		if (!BetaFunctionTable->ResumeThread(hThread))
			iErrorCode = 4;
	}

	// If can not get new thread contexts..
	CONTEXT new_ctx = { 0 };
	new_ctx.ContextFlags = 0x1008c ^ 0x9C;

	if (BetaFunctionTable->GetThreadContext(hThread, &new_ctx))
	{
		// If can not same with replaced contexts..
		if (new_ctx.Dr0)
			iErrorCode = 6;
		if (new_ctx.Dr1)
			iErrorCode = 7;
		if (new_ctx.Dr2)
			iErrorCode = 8;
		if (new_ctx.Dr3)
			iErrorCode = 9;
		if (new_ctx.Dr7)
			iErrorCode = 10;
	}
	// else
	// 	iErrorCode = 5;

	if (NtCurrentThread == hThread && bChanged)
		iErrorCode = 99;

	// If have a any illegal event, gtfo
	if (iErrorCode)
		CloseThread(hThread, dwThreadId, THREAD_BLOCK_CONTEXT, dwStartAddress, c_szOwner);
}

__forceinline void CheckThreadModuleType(HANDLE hThread, DWORD dwThreadId, DWORD dwStartAddress, const char* c_szOwner)
{
	HMODULE hOwner = nullptr;
	BetaFunctionTable->GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)dwStartAddress, &hOwner);

	/* So if is from mapped module */
	if (!hOwner)
	{
		MEMORY_BASIC_INFORMATION mbi;
		NTSTATUS ntRet_mbi = BetaFunctionTable->NtQueryVirtualMemory(NtCurrentProcess, (PVOID)dwStartAddress, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(ntRet_mbi))
			return;

		CDirFunctions lpDirFuncs;
		std::string szExeName = lpDirFuncs.ExeName();
		transform(szExeName.begin(), szExeName.end(), szExeName.begin(), tolower);

		if (!strcmp(szExeName.c_str(), c_szOwner)) /* If thread owner's name equal to filename, return */
			return;

		CFunctions lpFuncs;
		BYTE bDllMain1[] = { 0x55, 0x8b, 0xec, 0x83, 0x7d, 0x0c, 0x01, 0x75, 0x00 };
		BYTE bDllMain2[] = { 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x41, 0x00, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6F, 0x78, 0x57 };
		DWORD dwDLLMain = lpFuncs.FindPattern((DWORD)dwStartAddress, mbi.RegionSize, bDllMain1, sizeof(bDllMain1));
		DWORD dwDLLMain2 = lpFuncs.FindPattern((DWORD)dwStartAddress, mbi.RegionSize, bDllMain2, sizeof(bDllMain2));
		if (dwDLLMain || dwDLLMain2 || mbi.Type == MEM_IMAGE)
			CloseThread(hThread, dwThreadId, THREAD_BLOCK_MODULETYPE, dwStartAddress, c_szOwner);
	}
}

__forceinline void CheckThreadAddress(HANDLE hThread, DWORD dwThreadId, DWORD dwStartAddress, const char* c_szOwner)
{
	DWORD dwTextBase = 0;
	DWORD dwTextSize = 0;
	auto bFindTextSection = LPFunctions->GetTextSectionInformation(&dwTextBase, &dwTextSize);
	if (bFindTextSection < 1) {
		std::string szLowerProcessName = LPDirFunctions->ExeName();
		transform(szLowerProcessName.begin(), szLowerProcessName.end(), szLowerProcessName.begin(), tolower);
		if (!strcmp(szLowerProcessName.c_str(), c_szOwner))
			return;
	}
	else {
		auto dwTextHi = dwTextBase + dwTextSize;
		if (dwStartAddress >= dwTextBase || dwStartAddress <= dwTextHi)
			return;
	}

	ANTI_MODULE_INFO* selfInfo = { 0 };
	if (LPData->GetGameCode() != TEST_CONSOLE)
	{
		auto pselfInfo = LPData->GetAntiModuleInformations();
		if (!pselfInfo)
			LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");

		selfInfo = (ANTI_MODULE_INFO*)pselfInfo;
		std::wstring wszDllName = selfInfo->BaseDllName.Buffer;
		std::string szDllName = LPFunctions->WstringToUTF8(wszDllName);

		if (strstr(c_szOwner, LPFunctions->szLower(szDllName).c_str()))
			return;
	}


	HMODULE hOwnerModule = 0;
	if (strstr(c_szOwner, XOR("python")))
		hOwnerModule = BetaModuleTable->hPython;
	else
		hOwnerModule = BetaFunctionTable->GetModuleHandleA(c_szOwner);

	if (!hOwnerModule) {
		CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'c', 'r', 'e', 'a', 't', 'e', 'd', ' ', 't', 'h', 'r', 'e', 'a', 'd', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', '!', ' ', 'O', 'w', 'n', 'e', 'r', ':', ' ', '%', 's', 0x0 }; // Unknown created thread detected in process! Owner: %s
		char szWarn[1024];
		sprintf(szWarn, __warn, c_szOwner);
		LPFunctions->CloseProcess(szWarn, false, "");
	}

	
	MODULEINFO currentModInfo = { 0 };
	if (!BetaFunctionTable->GetModuleInformation(NtCurrentProcess, hOwnerModule, &currentModInfo, sizeof(currentModInfo)))
		return;

	CHAR __d3d9[] = { 'd', '3', 'd', '9', 0x0 }; // d3d9
	if (strstr(c_szOwner, __d3d9))
		return;

	DWORD dwModuleLow = (DWORD)currentModInfo.lpBaseOfDll;
	DWORD dwModuleHi = (DWORD)currentModInfo.lpBaseOfDll + currentModInfo.SizeOfImage;


	if (dwStartAddress < dwModuleLow || dwStartAddress > dwModuleHi)
		CloseThread(hThread, dwThreadId, THREAD_BLOCK_ADDRESS_MODINFO, dwStartAddress, c_szOwner);

	
	if (NtCurrentThread != hThread)
	{
		CONTEXT ctx = { 0 };
		ctx.ContextFlags = 0x1008c ^ 0x9C;

		BetaFunctionTable->SuspendThread(hThread);
		if (BetaFunctionTable->GetThreadContext(hThread, &ctx))
		{
			if (ctx.Eip && (ctx.Eip < dwModuleLow || ctx.Eip > dwModuleHi))
				CloseThread(hThread, dwThreadId, THREAD_BLOCK_ADDRESS_EIP, dwStartAddress, c_szOwner);
		}

		BetaFunctionTable->ResumeThread(hThread);
	}
}


static std::vector<DWORD> vThreadsAddressList;
static std::vector<HMODULE> vModuleHandleList;
__forceinline void CheckThreadsModuleRange()
{
	if (vThreadsAddressList.empty())
		return;

	for (auto &iThreadAdr : vThreadsAddressList)
	{
		bool bIsLegit = false;
		for (auto &iModuleHnd : vModuleHandleList)
		{
			MODULEINFO ModInfo = { 0 };
			if (BetaFunctionTable->GetModuleInformation(NtCurrentProcess, iModuleHnd, &ModInfo, sizeof(ModInfo)))
			{
				DWORD dwModuleLow = (DWORD)ModInfo.lpBaseOfDll;
				DWORD dwModuleHi = (DWORD)ModInfo.lpBaseOfDll + ModInfo.SizeOfImage;

				if (iThreadAdr >= dwModuleLow && iThreadAdr <= dwModuleHi)
					bIsLegit = true;
			}
		}


		std::string szLowerProcessName = LPDirFunctions->ExeName();
		transform(szLowerProcessName.begin(), szLowerProcessName.end(), szLowerProcessName.begin(), tolower);

		if (bIsLegit == false) {
			char cFileName[2048] = { 0 };
			BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)iThreadAdr, cFileName, 2048);

			std::string szMappedFileNameWithPath = cFileName;
			std::string szMappedFileNameWithoutPath = LPDirFunctions->GetNameFromPath(szMappedFileNameWithPath);
			transform(szMappedFileNameWithoutPath.begin(), szMappedFileNameWithoutPath.end(), szMappedFileNameWithoutPath.begin(), tolower);

			CHAR __betacoredll[] = { 'b', 'e', 't', 'a', 'c', 'o', 'r', 'e', '.', 'd', 'l', 'l', 0x0 }; // betacore.dll

			if (strcmp(szLowerProcessName.c_str(), szMappedFileNameWithoutPath.c_str()) && /* If not thread owner is process */
				!strstr(szMappedFileNameWithoutPath.c_str(), __betacoredll)
				) 
			{
				char szRealWarn[1024];
				CHAR __warn[] = { 'H', 'i', 'd', 'd', 'e', 'n', ' ', 't', 'h', 'r', 'e', 'a', 'd', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', '!', ' ', 'O', 'w', 'n', 'e', 'r', ':', ' ', '%', 's', 0x0 }; // Hidden thread detected!! Owner: %s
				sprintf(szRealWarn, __warn, szMappedFileNameWithoutPath.c_str());
				LPFunctions->CloseProcess(szRealWarn, false, "");
			}

		}
	}

	vThreadsAddressList.clear();
	vModuleHandleList.clear();
}


void CScan::EnumModulesAndCompareThreads()
{
	KARMA_MACRO_1

	HMODULE hMods[1024];
	DWORD cbNeeded;

	KARMA_MACRO_2
	BetaFunctionTable->EnumProcessModules(NtCurrentProcess, hMods, sizeof(hMods), &cbNeeded);
	{
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			vModuleHandleList.push_back(hMods[i]);
	}

	CheckThreadsModuleRange();
	KARMA_MACRO_1
}



void CScan::CheckThread(DWORD dwThreadId, bool bSingleCheck)
{
	KARMA_MACRO_1
	if (!dwThreadId) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Check thread event failed, Null thread id requested!");
#endif
		return;
	}

	KARMA_MACRO_2
	HANDLE hThread = BetaFunctionTable->OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, dwThreadId);
	if (!hThread) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Check thread event failed, Thread(%u) can not opened!", dwThreadId);
#endif
		return;
	}

	KARMA_MACRO_2
	CThreads lpThreads;
	DWORD dwStartAddress = lpThreads.GetThreadStartAddress(hThread);
	if (!dwStartAddress) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Check thread event failed, Thread(%u) start address can not fetched!", dwThreadId);
#endif
		BetaFunctionTable->CloseHandle(hThread);
		return;
	}

	KARMA_MACRO_1
	std::string szThreadOwnerName = lpThreads.GetThreadOwner(hThread);
	if (szThreadOwnerName.empty()) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Check thread event failed, Thread(%u)'s owner can not fetched!", dwThreadId);
#endif
		BetaFunctionTable->CloseHandle(hThread);
		return;
	}
	KARMA_MACRO_2


	CheckThreadOwnerProcess(hThread, dwThreadId, dwStartAddress, szThreadOwnerName.c_str());
	CheckThreadModuleType(hThread, dwThreadId, dwStartAddress, szThreadOwnerName.c_str());
	if (bSingleCheck == false)
		CheckThreadContexts(hThread, dwThreadId, dwStartAddress, szThreadOwnerName.c_str());
	//CheckThreadModuleName(hThread, dwThreadId, dwStartAddress, szThreadOwnerName.c_str()); //FIXME: Too much unknown thread owner from windows
	if (bSingleCheck == false)
		CheckThreadAddress(hThread, dwThreadId, dwStartAddress, szThreadOwnerName.c_str());
	//LPThreads->CheckThreadPriority(hThread);
	KARMA_MACRO_1


	if (bSingleCheck == false)
		vThreadsAddressList.push_back(dwStartAddress);

	BetaFunctionTable->CloseHandle(hThread);
	KARMA_MACRO_2
}
