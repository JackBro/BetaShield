#pragma once

typedef enum _HARDERROR_RESPONSE_OPTION {
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem,
	OptionExplorerTrayBaloon,
	OptionCancelTryAgainContinue
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;
typedef enum _HARDERROR_RESPONSE {
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes,
	ResponseTryAgain,
	ResponseContinue
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;


class CData {
	public:
		CData();
		 ~CData();


		void			SetInitializedMain(bool bFlag);
		bool			MainIsInitialized();

		void			SetDynamicAPIsInitialized();
		bool			DynamicAPIsIsInitialized();

		void			SetWatchdogFirstCheck();
		bool			WatchdogIsFirstChecked();

		HMODULE			GetAntiModule();
		void			SetAntiModule(HMODULE hModule);

		void			SetAntiModuleInformations(const char* lpModuleInfo);
		const char*		GetAntiModuleInformations();

		std::string		GetLicenseCode();
		void			SetLicenseCode(std::string tszLicenseCode);

		char**			GetLicensedIPArray();
		size_t			GetLicensedIPCount();
		void			SetLicensedIPs(char* cIpList[], int iIpCount);

		std::string		GetPatcherName();
		void			SetPatcherName(std::string tszPatcherName);

		int				GetGameCode();
		void			SetGameCode(int iCode);

		HMODULE			GetPythonHandle();
		void			SetPythonHandle(HMODULE hModule);

		std::string		GetPythonName();
		void			SetPythonName(std::string szName);

		bool			IsPackedProcess();
		void			SetPackedProcess(bool bRet);

		bool			IsShadowInitialized();
		void			SetShadowInitialized(bool bRet);
};
extern CData* LPData;
