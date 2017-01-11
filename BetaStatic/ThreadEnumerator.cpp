#include "ProjectMain.h"
#include "Threads.h"
#include "DynamicWinapi.h"
#include "Scan.h"

#include "CLog.h"
#include "Functions.h"
#include "VersionHelpers.h"

enum KWAIT_REASON
{
	Suspended = 5,
};

enum THREAD_STATE
{
	Running = 2,
	Waiting = 5,
};


inline BYTE* InitializeQuery()
{
	BYTE* mp_Data;
	DWORD mu32_DataSize = 1024*1024;

	while (true)
	{
		mp_Data = (BYTE*)malloc(mu32_DataSize);
		if (!mp_Data)
			return NULL;

		ULONG u32_Needed = 0;
		NTSTATUS s32_Status = BetaFunctionTable->NtQuerySystemInformation(SystemProcessInformation, mp_Data, mu32_DataSize, &u32_Needed);

		if (s32_Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			mu32_DataSize *= 2;
			mp_Data = (BYTE*)realloc((PVOID)mp_Data, mu32_DataSize);
			continue;
		}

		// BetaFunctionTable->Sleep(1);
		return mp_Data;
	}
}

inline SYSTEM_PROCESS_INFORMATION* QueryMyPID(BYTE* mp_Data)
{
	SYSTEM_PROCESS_INFORMATION* pk_Proc = (SYSTEM_PROCESS_INFORMATION*)mp_Data;
	while (TRUE)
	{
		if ((DWORD)pk_Proc->UniqueProcessId == BetaFunctionTable->GetCurrentProcessId())
			return pk_Proc;

		if (!pk_Proc->NextEntryOffset)
			return NULL;

		pk_Proc = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
	}
	return NULL;
}

bool CThreads::IsSuspendedThread(DWORD dwThreadId)
{
	BYTE* cap = InitializeQuery();
	if (!cap)
		return false;

	SYSTEM_PROCESS_INFORMATION* pk_Proc = QueryMyPID(cap);
	if (!pk_Proc) {
		free(cap);
		return false;
	}

	KARMA_MACRO_2
	auto pk_Thread = pk_Proc->Threads;
	if (!pk_Thread) {
		free(cap);
		return false;
	}

	if ((DWORD)pk_Thread->ClientId.UniqueThread == dwThreadId) {
		if (pk_Thread->ThreadState == Waiting && pk_Thread->WaitReason == Suspended) {
			free(cap);
			return true;
		}
	}

	free(cap);
	return false;
}

__forceinline int QueryThreadSuspension(SYSTEM_PROCESS_INFORMATION* pk_Proc, bool bForceCheck)
{
	if (bForceCheck) {
		LPThreads->CheckSelfThreads();
		return 0;
	}

	auto pk_Thread = pk_Proc->Threads;
	if (!pk_Thread)
		return 0;

	int suspended = 0;
	for (DWORD i = 0; i < pk_Proc->NumberOfThreads; i++)
	{
		LPScan->CheckThread((DWORD)pk_Thread->ClientId.UniqueThread);
		if (pk_Thread->ThreadState == Waiting && pk_Thread->WaitReason == Suspended)
			suspended++;

		pk_Thread++;
	}

	LPScan->EnumModulesAndCompareThreads();

	return suspended;
}

int CheckThreads(bool bForceCheck)
{
	BYTE* cap = InitializeQuery();
	if (!cap)
		return 1;

	SYSTEM_PROCESS_INFORMATION* pk_Proc = QueryMyPID(cap);
	if (!pk_Proc) {
		free(cap);
		return 2;
	}

	KARMA_MACRO_2

	int num = QueryThreadSuspension(pk_Proc, bForceCheck);
	free(cap);

	return num;
}


void CThreads::CheckThreadStates(bool bForceCheck)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Thread State check event has been started!");
#endif
	KARMA_MACRO_1

	int susp = CheckThreads(bForceCheck);
	if (susp > 0 && IsWindowsVistaOrGreater())
	{
		char cTmpStr[1024];
		CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'I', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', 0x0 }; // Game Integrity failed
		CHAR _warn2[] = { 'T', 'r', 'y', ' ', 't', 'o', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', 'e', 's', ' ', 'a', 'n', 'd', ' ', 'r', 'e', 's', 't', 'a', 'r', 't', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '!', 0x0 }; // Try to disable antiviruses and restart computer!

		CHAR __format[] = { '%', 's', '!', '!', ' ', '[', '%', 'd', ']', '\n', '%', 's', 0x0 }; // %s!! [%d] \n%s
		sprintf(cTmpStr, __format, _warn, susp, _warn2);

		LPFunctions->CloseProcess(cTmpStr, true, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Thread State check event completed!");
#endif
}

DWORD WINAPI ThreadEnumerator(LPVOID)
{
	while (1)
	{
		LPThreads->CheckThreadStates();

		LPThreads->IncreaseThreadTick(7);
		BetaFunctionTable->Sleep(12000);
	}

	return 0;
}

HANDLE CThreads::InitThreadEnumerator()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Thread scan thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)ThreadEnumerator, 0, 7);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '7', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x7! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Thread scan thread creation completed!");
#endif
	return hThread;
}

