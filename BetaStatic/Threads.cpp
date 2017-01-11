#include "ProjectMain.h"
#include "Threads.h"
#include "DynamicWinapi.h"
#include "VersionHelpers.h"
#include "Functions.h"

#include "XOR.h"
#include "Main.h"
#include "CLog.h"
#include "DirFuncs.h"
#include "Access.h"
#include "AntiDebug.h"

CThreads* LPThreads;
CThreads::CThreads()
{
}

CThreads::~CThreads()
{
}


HANDLE CThreads::_CreateThread(LPTHREAD_START_ROUTINE lpStart, LPVOID Param, int iThreadCode)
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0, "Thread creation has been started! Thread code: %d", iThreadCode);
#endif

	KARMA_MACRO_2

	HANDLE hThread = 0;
	DWORD dwThreadId = 0;
	DWORD dwFlag = 0x00000004; /* HideFromDebugger */
#ifdef _DEBUG
	dwFlag = 0;
#endif

	if (IsWindowsVistaOrGreater())
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "Vista or Vista+ Detected! NtCreateThreadEx has been calling");
#endif
		NTSTATUS ntStatus = BetaFunctionTable->NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, NtCurrentProcess, lpStart, Param, dwFlag, 0, 0, 0, 0);
		if (NT_SUCCESS(ntStatus)) {
#ifdef _DEBUG
			LPLog->AddLog(0, "Thread creation succesfuly completed(%d)! - %u[%p]", iThreadCode, BetaFunctionTable->GetThreadId(hThread), hThread);
#endif

			LPAccess->SetDACLRulesToThread(hThread);

			return hThread;
		}
#ifdef _DEBUG
		else {
			LPLog->ErrorLog(0, "Thread %d can not created!", iThreadCode);
		}
#endif
	}
	else
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "Vista- Detected! CreateThread has been calling");
#endif
		hThread = BetaFunctionTable->CreateThread(0, 0, lpStart, Param, 0, &dwThreadId);

		if (hThread) {
#ifdef _DEBUG
			LPLog->AddLog(0, "Thread creation succesfuly completed(%d)! - %u[%p]", iThreadCode, dwThreadId, hThread);
#endif

#ifndef _DEBUG
			DWORD dwAntiTraceResult = AntiTraceThread(hThread);
			if (dwAntiTraceResult < 0) {
				CHAR __Threadcreationqueryfailed[] = { 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'q', 'u', 'e', 'r', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', 0x0 }; /* Thread creation query failed! */
				lpFuncs.CloseProcess(__Threadcreationqueryfailed, false, "");
			}
#endif

			LPAccess->SetDACLRulesToThread(hThread);

			return hThread;
		}
#ifdef _DEBUG
		else {
			LPLog->ErrorLog(0, "Thread can not created!");
		}
#endif
	}

	KARMA_MACRO_1
	return 0;
}


void CThreads::AntiThreadKill(HANDLE hThread)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti Thread Kill check event has been started!");
#endif

	if (!hThread) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Anti Thread Kill passed! Null thread!");
#endif
		return;
	}

	DWORD result = BetaFunctionTable->WaitForSingleObject(hThread, 0);
	if (result != WAIT_TIMEOUT) {
		CHAR __ThreadKill[] = { 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'K', 'i', 'l', 'l', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 }; //Thread kill detected
		
#ifdef _DEBUG
		LPLog->ErrorLog(0, "ERROR! Thread Kill detected!");
#endif
		LPFunctions->CloseProcess(__ThreadKill, false, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti Thread Kill check event completed!");
#endif
}

void CThreads::AntiThreadSuspend(HANDLE hThread)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti Thread Suspend check event has been started!");
#endif

	if (!hThread) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Anti Thread Suspend passed! Null thread!");
#endif
		return;
	}

	DWORD dwRet = BetaFunctionTable->ResumeThread(hThread);
	if (dwRet) {
		CHAR __ThreadSuspend[] = { 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'S', 'u', 's', 'p', 'e', 'n', 'd', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 }; //Thread suspend detected

#ifdef _DEBUG
		LPLog->ErrorLog(0, "ERROR! Thread Suspend detected!");
#endif
		LPFunctions->CloseProcess(__ThreadSuspend, false, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti Thread Suspend check event completed!");
#endif
}

void CThreads::CheckThreadPriority(HANDLE hThread)
{
	if (!hThread) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CheckThreadPriority passed! Null thread!");
#endif
		return;
	}

	auto result = BetaFunctionTable->GetThreadPriority(hThread);
	if (result < 0)
		BetaFunctionTable->SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL);
}

int CThreads::GetThreadCount()
{
	int iThreadCount = 0;
	auto hMemory = BetaFunctionTable->GlobalAlloc(GMEM_ZEROINIT, 0x50000);
	if (hMemory)
	{
		auto dwMemoryBuf = (DWORD)hMemory;
		if (NT_SUCCESS(BetaFunctionTable->NtQuerySystemInformation(SystemProcessInformation, (PVOID)dwMemoryBuf, 0x50000, 0)))
		{
			while (*(DWORD*)dwMemoryBuf != 0)
			{
				if (*(DWORD*)(dwMemoryBuf + 0x44) == BetaFunctionTable->GetCurrentProcessId()) {
					iThreadCount = *(DWORD*)(dwMemoryBuf + 4);
					break;
				}

				dwMemoryBuf = dwMemoryBuf + *(DWORD*)dwMemoryBuf;
			}

			if (*(DWORD*)(dwMemoryBuf + 0x44) == BetaFunctionTable->GetCurrentProcessId())
			{
			}
		}
		BetaFunctionTable->GlobalFree(hMemory);
	}
	return iThreadCount;
}



DWORD CThreads::AntiTraceThread(HANDLE hThread)
{
	KARMA_MACRO_1
	BOOL bCheckStat = FALSE;

	if (!hThread)
		return -1;

	NTSTATUS ntReturnStat = BetaFunctionTable->ZwSetInformationThread(hThread, ThreadHideFromDebugger, &bCheckStat, sizeof(ULONG));
	if (NT_SUCCESS(ntReturnStat))
		return -2;

	NTSTATUS ntFakeStat1 = BetaFunctionTable->ZwSetInformationThread(hThread, ThreadHideFromDebugger, &bCheckStat, sizeof(UINT));
	if (NT_SUCCESS(ntFakeStat1))
		return -3;

	NTSTATUS ntFakeStat2 = BetaFunctionTable->ZwSetInformationThread((HANDLE)0xFFFFF, ThreadHideFromDebugger, 0, 0);
	if (NT_SUCCESS(ntFakeStat2))
		return -4;

	KARMA_MACRO_2

	NTSTATUS ntCorrectStat = BetaFunctionTable->ZwSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
	if (!NT_SUCCESS(ntCorrectStat))
		return -5;

	NTSTATUS ntCorrectStat2 = BetaFunctionTable->NtQueryInformationThread(hThread, ThreadHideFromDebugger, &bCheckStat, sizeof(BOOLEAN), 0);
	if (!NT_SUCCESS(ntCorrectStat))
		return -6;

	if (!bCheckStat)
		return -7;

	return 0;
}

DWORD CThreads::__GetThreadId(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION ThreadInfo;
	NTSTATUS ntStat = BetaFunctionTable->NtQueryInformationThread(hThread, 0, &ThreadInfo, sizeof(ThreadInfo), NULL);
	return NT_SUCCESS(ntStat) ? (DWORD)ThreadInfo.ClientId.UniqueThread : 0;
}

DWORD CThreads::__GetThreadProcessId(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION ThreadInfo;
	NTSTATUS ntStat = BetaFunctionTable->NtQueryInformationThread(hThread, 0, &ThreadInfo, sizeof(ThreadInfo), NULL);
	return NT_SUCCESS(ntStat) ? (DWORD)ThreadInfo.ClientId.UniqueProcess : 0;
}

DWORD CThreads::GetThreadStartAddress(HANDLE hThread)
{
	DWORD dwCurrentThreadAddress = 0;
	BetaFunctionTable->NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwCurrentThreadAddress, sizeof(dwCurrentThreadAddress), NULL);
	return dwCurrentThreadAddress;
}

std::string CThreads::GetThreadOwner(HANDLE hThread)
{
	DWORD dwStartAddress = GetThreadStartAddress(hThread);
	if (!dwStartAddress)
		return "";

	char cFileName[2048] = { 0 };
	BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwStartAddress, cFileName, 2048);

	CDirFunctions lpDirFuncs;
	std::string szFileName = cFileName;
	std::string szFileNameWithoutPath = lpDirFuncs.GetNameFromPath(szFileName);
	transform(szFileNameWithoutPath.begin(), szFileNameWithoutPath.end(), szFileNameWithoutPath.begin(), tolower);

	return szFileNameWithoutPath;
}

DWORD CThreads::GetMainThreadId()
{
	HANDLE hSnap = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	IMAGE_DOS_HEADER* doshdr = (IMAGE_DOS_HEADER*)BetaModuleTable->hBaseModule;
	IMAGE_NT_HEADERS32* nthdr = (IMAGE_NT_HEADERS32*)(doshdr->e_lfanew + (DWORD)doshdr);
	auto entryPoint = nthdr->OptionalHeader.AddressOfEntryPoint + nthdr->OptionalHeader.ImageBase;

	if (BetaFunctionTable->Thread32First(hSnap, &ti))
	{
		do {
			if (ti.th32OwnerProcessID == BetaFunctionTable->GetCurrentProcessId())
			{
				HANDLE hThread = BetaFunctionTable->OpenThread(THREAD_QUERY_INFORMATION, false, ti.th32ThreadID);
				if (hThread)
				{
					auto dwStartAddress = GetThreadStartAddress(hThread);
					if (dwStartAddress == entryPoint) {
						BetaFunctionTable->CloseHandle(hThread);
						BetaFunctionTable->CloseHandle(hSnap);
						return ti.th32ThreadID;
					}
				}
				BetaFunctionTable->CloseHandle(hThread);
			}
		} while (BetaFunctionTable->Thread32Next(hSnap, &ti));
	}

	BetaFunctionTable->CloseHandle(hSnap);
	return 0;
}

DWORD CThreads::GetThreadIdFromAddress(DWORD dwAddress)
{
	HANDLE hSnap = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (BetaFunctionTable->Thread32First(hSnap, &ti))
	{
		do {
			if (ti.th32OwnerProcessID == BetaFunctionTable->GetCurrentProcessId())
			{
				HANDLE hThread = BetaFunctionTable->OpenThread(THREAD_QUERY_INFORMATION, false, ti.th32ThreadID);
				if (hThread)
				{
					auto dwStartAddress = GetThreadStartAddress(hThread);
					if (dwStartAddress == dwAddress) {
						BetaFunctionTable->CloseHandle(hThread);
						BetaFunctionTable->CloseHandle(hSnap);
						return ti.th32ThreadID;
					}
				}
				BetaFunctionTable->CloseHandle(hThread);
			}
		} while (BetaFunctionTable->Thread32Next(hSnap, &ti));
	}

	BetaFunctionTable->CloseHandle(hSnap);
	return 0;
}

DWORD CThreads::GetThreadOwnerProcessId(DWORD dwThreadID)
{
	HANDLE hSnap = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);

	if (BetaFunctionTable->Thread32First(hSnap, &ti))
	{
		do {
			if (dwThreadID == ti.th32ThreadID) {
				BetaFunctionTable->CloseHandle(hSnap);
				return ti.th32OwnerProcessID;
			}
		} while (BetaFunctionTable->Thread32Next(hSnap, &ti));
	}

	BetaFunctionTable->CloseHandle(hSnap);
	return 0;
}

