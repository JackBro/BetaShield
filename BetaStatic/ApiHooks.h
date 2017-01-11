#pragma once
#define HOOK_CHECK_SIZE 5

extern inline int CheckCallerAddress(DWORD dwCaller, int iType, std::string szName);

class CSelfApiHooks {
	public:
		CSelfApiHooks();
		virtual ~CSelfApiHooks();

		bool HooksIsInitialized();

		void BlockAPI(LPCTSTR lpModule, LPCSTR lpFuncName, int iType);
		void InitializeHookAPIs();
		void InitApfnHooks();

		HANDLE InitAntiMacro();
		void DestroyAntiMacro();

		void InitDLLProberCallback();
		void InitDllNotificationCallback();

		void PreHookCheck();
};
extern CSelfApiHooks* LPSelfApiHooks;

