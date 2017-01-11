#include "ProjectMain.h"
#include "DynamicWinapi.h"
#include "XOR.h"
#include "ApiHooks.h"
#include "Scan.h"
#include "DirFuncs.h"
#include "CLog.h"
#include "VersionHelpers.h"
#include "Functions.h"

#pragma optimize("", off )
VOID NTAPI LdrDllNotification_TRAMPOLINE(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrDllNotification called!");
#endif

	if (NotificationReason == 1 /* aka. Load Event */)
	{
#ifdef _DEBUG
		LPLog->DetourLog(0, "LdrDllNotification call reason: LOAD!");
#endif

		std::wstring wszModule = NotificationData->Loaded.FullDllName->Buffer;
		transform(wszModule.begin(), wszModule.end(), wszModule.begin(), towlower);
		std::string szModule = LPFunctions->WstringToUTF8(wszModule);

#ifdef _DEBUG
		LPLog->DetourLog(0,"LdrDllNotification loaded dll: %s", szModule.c_str());
#endif

		CScan lpScan;
		static BOOL bSignRet = FALSE;
		lpScan.IsSignedFile(wszModule.c_str(), &bSignRet);
		if (bSignRet == FALSE)
		{
			WCHAR wc_szPYD[] = { L'.', L'p', L'y', L'd', L'\0' };
			WCHAR wc_szMIX[] = { L'.', L'm', L'3', L'd', L'\0' };
			WCHAR wc_szM3D[] = { L'.', L'm', L'i', L'x', L'\0' };
			WCHAR wc_szFLT[] = { L'.', L'f', L'l', L't', L'\0' };
			WCHAR wc_szASI[] = { L'.', L'a', L's', L'i', L'\0' };

			if (!wcsstr(wszModule.c_str(), wc_szPYD) && !wcsstr(wszModule.c_str(), wc_szMIX) && !wcsstr(wszModule.c_str(), wc_szM3D) &&
				!wcsstr(wszModule.c_str(), wc_szFLT) && !wcsstr(wszModule.c_str(), wc_szASI) &&
				!LPDirFunctions->IsFromCurrentPath(wszModule) && !LPDirFunctions->IsFromWindowsPath(wszModule))
			{
				CHAR __warnunknown[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'd', 'l', 'l', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ':', ' ', '%', 's', 0x0 }; // Unknown dll detected in process: %s
				LPLog->AddLog(0,__warnunknown, szModule.c_str());
				BetaFunctionTable->NtUnmapViewOfSection(NtCurrentProcess, NotificationData->Loaded.DllBase);
			}
		}

	}
}
#pragma optimize("", on )

typedef VOID(NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG NotificationReason, PCLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);
void CSelfApiHooks::InitDllNotificationCallback()
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrRegisterDllNotification has been initializing");
#endif

	if (!IsWindowsVistaOrGreater()) {
#ifdef _DEBUG
		LPLog->DetourLog(0,"LdrRegisterDllNotification passed in this OS");
#endif
		return;
	}

	typedef NTSTATUS(NTAPI *lpLdrRegisterDllNotification)(ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction, void* Context, void **Cookie);
	auto LdrRegisterDllNotification = (lpLdrRegisterDllNotification)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("LdrRegisterDllNotification"));
	void * pvCookie = NULL;

	LdrRegisterDllNotification(0, LdrDllNotification_TRAMPOLINE, NULL, &pvCookie);

#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrRegisterDllNotification succesfuly initialized");
#endif
}

