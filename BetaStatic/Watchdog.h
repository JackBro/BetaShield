#pragma once

class CWatchdog {
	public:
		CWatchdog();
		virtual ~CWatchdog();

		bool IsWatchdogWindow(HWND hWnd);
		size_t GetWatchdogCount();
		HANDLE InitializeWatchdog();

		void SetInitCheckTimer();
};
extern CWatchdog* LPWatchdog;
