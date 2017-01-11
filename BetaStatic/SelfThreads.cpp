#include "ProjectMain.h"
#include "Threads.h"
#include "DynamicWinapi.h"
#include "Main.h"
#include "CLog.h"
#include "Access.h"
#include "Threads.h"
#include "Scan.h"
#include "AntiBreakpoint.h"
#include "ApiHooks.h"
#include "Watchdog.h"
#include "Metin2_Plugin.h"
#include "DirFuncs.h"
#include "InternetAPI.h"
#include <map>
#include "Functions.h"


std::map<DWORD, DWORD> mThreadTicks;
void	CThreads::IncreaseThreadTick(DWORD dwThread)	{ mThreadTicks[dwThread] += 1;		}
void	CThreads::DecreaseThreadTick(DWORD dwThread)	{ mThreadTicks[dwThread] -= 1;		}
void	CThreads::ReleaseThreadTicks(DWORD dwThread)	{ mThreadTicks[dwThread] = 0;		}
DWORD	CThreads::GetThreadTick(DWORD dwThread)			{ return mThreadTicks[dwThread];	}


DWORD WINAPI InitExThreadTickCheck(LPVOID)
{
	while (1)
	{
		BetaFunctionTable->Sleep(55000);
#ifdef _DEBUG
		LPLog->AddLog(0, "Thread tick check processing!");
#endif


		int iProtectedThreadArray[] = { 1, 2, 4, 5, /* 6, */ 7, 8, 9, 12 };
		for (int i = 0; i < _countof(iProtectedThreadArray); i++)
		{
#ifdef _DEBUG
			LPLog->AddLog(0, "%d) Thread: %d Bind'd tick count is: %u", i, iProtectedThreadArray[i], LPThreads->GetThreadTick(iProtectedThreadArray[i]));
#endif

			if (LPThreads->GetThreadTick(iProtectedThreadArray[i]) == 0)
			{
#ifdef _DEBUG
				LPLog->ErrorLog(0, "Null tick count on Thread: %d !!!", iProtectedThreadArray[i]);
#endif

				CHAR __warn[] = { 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'o', 'm', 'm', 'u', 'n', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Thread communication failed! Thread code: %d
				char szWarn[1024];
				sprintf(szWarn, __warn, iProtectedThreadArray[i]);
				LPFunctions->CloseProcess(szWarn, false, "");
			}

			LPThreads->ReleaseThreadTicks(iProtectedThreadArray[i]);
		}

		LPThreads->IncreaseThreadTick(16);
	}
	return 0;
}

void CThreads::InitThreadTickCheck()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Thread tick check thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hTickCheckThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)InitExThreadTickCheck, 0, 16);
	if (!hTickCheckThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '6', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x16! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Thread tick check thread creation completed!");
#endif
}

void CThreads::CheckTickCheckerThreadIntegrity()
{
	if (LPThreads->GetThreadTick(16) == 0)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Null tick count on Thread: 16 !!!");
#endif

		CHAR __warn[] = { 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'o', 'm', 'm', 'u', 'n', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Thread communication failed! Thread code: %d
		char szWarn[1024];
		sprintf(szWarn, __warn, 16);
		LPFunctions->CloseProcess(szWarn, false, "");
	}

	LPThreads->ReleaseThreadTicks(16);
}


HANDLE hEnumHandleThread		= nullptr;
HANDLE hAdjustPrivThread		= nullptr;
HANDLE hDirCheckThread			= nullptr;
HANDLE hModuleCheckThread		= nullptr;
HANDLE hDriverScanThread		= nullptr;
HANDLE hSectionScanThread		= nullptr;
HANDLE hThreadScanThread		= nullptr;
HANDLE hAntiThread				= nullptr;
HANDLE hChecksumThread			= nullptr;
HANDLE hAntiMacroThread			= nullptr;
HANDLE hWatchdogThread			= nullptr;
HANDLE hMetin2PackHashThread	= nullptr;
HANDLE hLicenseCheckThread		= nullptr;
HANDLE hWindowScanThread		= nullptr;

DWORD dwEnumHandleThreadId		= 0;
DWORD dwAdjustPrivThreadId		= 0;
DWORD dwDirCheckThreadId		= 0;
DWORD dwModuleCheckThreadId		= 0;
DWORD dwDriverScanThreadId		= 0;
DWORD dwSectionScanThreadId		= 0;
DWORD dwThreadScanThreadId		= 0;
DWORD dwAntiThreadId			= 0;
DWORD dwChecksumThreadId		= 0;
DWORD dwAntiMacroThreadId		= 0;
DWORD dwWatchdogThreadId		= 0;
DWORD dwMetin2PackHashThreadId	= 0;
DWORD dwLicenseCheckThreadId	= 0;
DWORD dwWindowScanThreadId		= 0;


void CThreads::InitEnumHandle()
{
	hEnumHandleThread = LPAccess->InitBlockHandles();
	dwEnumHandleThreadId = LPThreads->__GetThreadId(hEnumHandleThread);
}

void CThreads::InitAdjustPriv()
{
	hAdjustPrivThread = LPAccess->InitAdjustPrivThread();
	dwAdjustPrivThreadId = LPThreads->__GetThreadId(hAdjustPrivThread);
}

void CThreads::InitDirCheckThread()
{
	hDirCheckThread = LPDirFunctions->InitializeFolderCheck();
	dwDirCheckThreadId = LPThreads->__GetThreadId(hDirCheckThread);
}

void CThreads::InitModuleCheck()
{
	hModuleCheckThread = LPMain->CheckModuleModifications();
	dwModuleCheckThreadId = LPThreads->__GetThreadId(hModuleCheckThread);
}

void CThreads::InitDriverCheck()
{
	hDriverScanThread = LPScan->InitCheckDrivers();
	dwDriverScanThreadId = LPThreads->__GetThreadId(hDriverScanThread);
}

void CThreads::InitSectionCheck()
{
	hSectionScanThread = LPScan->InitCheckSections();
	dwSectionScanThreadId = LPThreads->__GetThreadId(hSectionScanThread);
}

void CThreads::InitThreadCheck()
{
	hThreadScanThread = LPThreads->InitThreadEnumerator();
	dwThreadScanThreadId = LPThreads->__GetThreadId(hThreadScanThread);
}

void CThreads::InitAntiThread()
{
	hAntiThread = LPAntiBreakpoint->InitAntiThread();
	dwAntiThreadId = LPThreads->__GetThreadId(hAntiThread);
}

void CThreads::InitChecksumThread()
{
	hChecksumThread = LPScan->InitChecksumScan();
	dwChecksumThreadId = LPThreads->__GetThreadId(hChecksumThread);
}

void CThreads::InitAntiMacroThread()
{
	hAntiMacroThread = LPSelfApiHooks->InitAntiMacro();
	dwAntiMacroThreadId = LPThreads->__GetThreadId(hAntiMacroThread);
}

void CThreads::InitWatchdog()
{
	hWatchdogThread = LPWatchdog->InitializeWatchdog();
	dwWatchdogThreadId = LPThreads->__GetThreadId(hWatchdogThread);
}

void CThreads::InitMetin2PackHashCheck()
{
	hMetin2PackHashThread = LPPluginMetin2->InitCheckIngame();
	dwMetin2PackHashThreadId = LPThreads->__GetThreadId(hMetin2PackHashThread);
}

void CThreads::InitLicenseCheck()
{
	hLicenseCheckThread = LPInternetAPI->InitLicenseCheck();
	dwLicenseCheckThreadId = LPThreads->__GetThreadId(hLicenseCheckThread);
}

void CThreads::InitWindowScan()
{
	hWindowScanThread = LPScan->InitWindowScan();
	dwWindowScanThreadId = LPThreads->__GetThreadId(hWindowScanThread);
}



bool CThreads::IsSelfThread(DWORD dwThreadId)
{
	return (
		dwThreadId == dwEnumHandleThreadId || dwThreadId == dwAdjustPrivThreadId || dwThreadId == dwModuleCheckThreadId ||
		dwThreadId == dwDriverScanThreadId || dwThreadId == dwSectionScanThreadId || dwThreadId == dwThreadScanThreadId ||
		dwThreadId == dwAntiThreadId || dwThreadId == dwChecksumThreadId || dwThreadId == dwAntiMacroThreadId ||
		dwThreadId == dwWatchdogThreadId || dwThreadId == dwMetin2PackHashThreadId || dwThreadId == dwDirCheckThreadId ||
		dwThreadId == dwLicenseCheckThreadId || dwThreadId == dwWindowScanThreadId
	);
}



__forceinline int CheckThread(HANDLE hThread)
{
	if (!hThread && LPData->MainIsInitialized())
		return -1;

	__try {
		auto hKillResult = BetaFunctionTable->WaitForSingleObject(hThread, 0);
		if (hKillResult != WAIT_TIMEOUT)
			return 1;

		auto dwSuspendResult = BetaFunctionTable->ResumeThread(hThread);
		if (dwSuspendResult)
			return 2;

		auto iPriorityResult = BetaFunctionTable->GetThreadPriority(hThread);
		if (iPriorityResult < 0)
			return 3;
	}
	__except (1) {

	}
	return 0;
}

void CThreads::CheckSelfThreads()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Self thread check started!");
#endif

	HANDLE hThreadList[] = { 
		hEnumHandleThread, hAdjustPrivThread, hModuleCheckThread, hDriverScanThread, /* hSectionScanThread ,*/
		hThreadScanThread, hAntiThread, hAntiMacroThread, hWatchdogThread, hLicenseCheckThread, hWindowScanThread
	};
	CHAR __warn[] = { 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', ' ', 'T', 'y', 'p', 'e', ':', ' ', '%', 'd', 0x0 }; // Thread integrity failed! Error code: %d Type: %d

	for (int i = 0; i < _countof(hThreadList); i++)
	{
		int iRet = CheckThread(hThreadList[i]);
		if (iRet != 0) {
			char szWarn[1024];
			sprintf(szWarn, __warn, i, iRet);
			LPFunctions->CloseProcess(szWarn, false, "");
		}
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Self thread check completed!");
#endif
}

HANDLE CThreads::GetThreadCheckThreadHandle()
{
	return hThreadScanThread;
}

