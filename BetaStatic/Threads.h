#pragma once
#include <Windows.h>

class CThreads {
	public:
		CThreads();
		virtual ~CThreads();

		HANDLE			_CreateThread(LPTHREAD_START_ROUTINE lpStart, LPVOID Param, int iThreadCode);
		DWORD			AntiTraceThread(HANDLE hThread);

		DWORD			GetThreadOwnerProcessId(DWORD dwThreadID);
		DWORD			GetThreadIdFromAddress(DWORD dwAddress);
		DWORD			GetThreadStartAddress(HANDLE hThread);
		std::string		GetThreadOwner(HANDLE hThread);
		DWORD			__GetThreadId(HANDLE hThread);
		DWORD			__GetThreadProcessId(HANDLE hThread);
		DWORD			GetMainThreadId();
		bool			IsSelfThread(DWORD dwThreadId);
		int				GetThreadCount();
		bool			IsSuspendedThread(DWORD dwThreadId);

		void			AntiThreadKill(HANDLE hThread);
		void			AntiThreadSuspend(HANDLE hThread);
		void			CheckThreadPriority(HANDLE hThread);

		void			CheckThreadStates(bool bForceCheck = false);
		HANDLE			InitThreadEnumerator();

		void			IncreaseThreadTick(DWORD dwThread);
		void			DecreaseThreadTick(DWORD dwThread);
		void			ReleaseThreadTicks(DWORD dwThread);
		DWORD			GetThreadTick(DWORD dwThread);
		void			InitThreadTickCheck();
		void			CheckTickCheckerThreadIntegrity();


		void			CheckSelfThreads();


		void			InitAdjustPriv();
		void			InitEnumHandle();
		void			InitDirCheckThread();
		void			InitModuleCheck();
		void			InitDriverCheck();
		void			InitSectionCheck();
		void			InitThreadCheck();
		void			InitAntiThread();
		void			InitChecksumThread();
		void			InitAntiMacroThread();
		void			InitWatchdog();
		void			InitMetin2PackHashCheck();
		void			InitLicenseCheck();
		void			InitWindowScan();

		HANDLE			GetThreadCheckThreadHandle();
};
extern CThreads* LPThreads;
