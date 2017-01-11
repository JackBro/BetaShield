#pragma once

enum ESectionScanTypes {
	SECTIONSCAN_CHECK_PATTERN,
	SECTIONSCAN_SCAN_CODECAVE
};


class CScan {
	public:
		CScan();
		virtual ~CScan();

	public:
		void IsSignedFile(LPCWSTR c_wszFile, PBOOL bRet);

		void ScanDNSHistory();

		void ScanModules();

		void CheckWindowCount();

		void CheckHiddenProcesses();

		void CheckTestSignEnabled();

		void InitializeEventLogCheck();

		void AntiWow32ReservedHook();

		void InitializeMemoryWatchdog();
		void CheckMemoryWatchdog();

		void CheckDriver(std::string szDriver, int iType);
		HANDLE InitCheckDrivers();

		HANDLE InitCheckSections();
		HANDLE InitChecksumScan();
		HANDLE InitWindowScan();

		void CheckThread(DWORD dwThreadId, bool bSingleCheck = false);
		void EnumModulesAndCompareThreads();
};
extern CScan* LPScan;
