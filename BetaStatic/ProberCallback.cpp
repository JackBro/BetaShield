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
typedef NTSTATUS(NTAPI* PLDR_MANIFEST_PROBER_ROUTINE)(HMODULE DllBase, PCWSTR FullDllPath, PHANDLE ActivationContext);
typedef NTSTATUS(NTAPI* PLDR_ACTX_LANGUAGE_ROURINE)(HANDLE Unk, USHORT LangID, PHANDLE ActivationContext);
typedef void(NTAPI* PLDR_RELEASE_ACT_ROUTINE)(HANDLE ActivationContext);
typedef VOID(NTAPI* LdrSetDllManifestProberPtr)(PLDR_MANIFEST_PROBER_ROUTINE ManifestProberRoutine, PLDR_ACTX_LANGUAGE_ROURINE CreateActCtxLanguageRoutine, PLDR_RELEASE_ACT_ROUTINE ReleaseActCtxRoutine);
bool IsValidLoadedDLLFromCallback(std::string szSourceString)
{
	auto szLowerString = LPFunctions->szLower(szSourceString);
#ifdef _DEBUG
	LPLog->DetourLog(0, "IsValidLoadedDLLFromCallback started: %s", szLowerString.c_str());
#endif

	if (LPDirFunctions->IsFromWindowsPath(LPFunctions->szLower(szLowerString)))
	{
#ifdef _DEBUG
		LPLog->DetourLog(0,"IsValidLoadedDLLFromCallback returned module is from windows! %s passed!", szLowerString.c_str());
#endif
		return true;
	}

	// If in the source string have a anticheat module name pass it.
	CHAR __BetaCoredll[] = { 'b', 'e', 't', 'a', 'c', 'o', 'r', 'e', 0x0 }; // betacore
	std::string szExePath = LPDirFunctions->ExePath();
	transform(szExePath.begin(), szExePath.end(), szExePath.begin(), tolower);
	if (strstr(szLowerString.c_str(), szExePath.c_str()))
	{
		if (strstr(szLowerString.c_str(), __BetaCoredll))
		{
#ifdef _DEBUG
			LPLog->DetourLog(0, "IsValidLoadedDLLFromCallback returned module is anticheat! %s passed!", szLowerString.c_str());
#endif
			return true;
		}

		CHAR __mix[] = { '.', 'm', 'i', 'x', 0x0 }; //".mix"
		CHAR __asi[] = { '.', 'a', 's', 'i', 0x0 }; //".asi"
		CHAR __m3d[] = { '.', 'm', '3', 'd', 0x0 }; //".m3d"
		CHAR __flt[] = { '.', 'f', 'l', 't', 0x0 }; //".flt"
		CHAR __pyd[] = { '.', 'p', 'y', 'd', 0x0 }; //".pyd"
		if (strstr(szLowerString.c_str(), __mix) || strstr(szLowerString.c_str(), __asi) || strstr(szLowerString.c_str(), __m3d) ||
			strstr(szLowerString.c_str(), __flt) || strstr(szLowerString.c_str(), __pyd))
		{
#ifdef _DEBUG
			LPLog->DetourLog(0,"IsValidLoadedDLLFromCallback returned with special extension, passed(%s)!", szSourceString.c_str());
#endif
			return true;
		}
	}

	// If in the source string have a main process name pass it (windows xp and vista generic problem).
	std::string szExeNameWithPath = LPDirFunctions->ExeNameWithPath();
	transform(szExeNameWithPath.begin(), szExeNameWithPath.end(), szExeNameWithPath.begin(), tolower);
	if (strstr(szLowerString.c_str(), szExeNameWithPath.c_str())) {
#ifdef _DEBUG
		LPLog->DetourLog(0,"IsValidLoadedDLLFromCallback returned with main process!");
#endif
		return true;
	}

	return false;
}

NTSTATUS NTAPI ProbeCallback(IN HMODULE DllBase, IN PCWSTR FullDllPath, OUT PHANDLE ActivationContext)
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"ProbeCallback: Base %p, path '%ls', context %p triggered!", DllBase, FullDllPath, *ActivationContext);
#endif
	if (IsValidLoadedDLLFromCallback(LPFunctions->WstringToUTF8(FullDllPath)) == false) {
		CHAR _warn[] = { 'D', 'L', 'L', ' ', 'L', 'o', 'a', 'd', ' ', 'B', 'l', 'o', 'c', 'k', 'e', 'd', ':', ' ', '%', 's', 0x0 }; // DLL Load Blocked: %s
		LPLog->ErrorLog(0, _warn, LPFunctions->WstringToUTF8(FullDllPath).c_str());
		return STATUS_INVALID_PARAMETER;
	}

	HANDLE actx = NULL;
	ACTCTXW act = { 0 };

	act.cbSize = sizeof(act);
	act.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
	act.lpSource = FullDllPath;
	act.hModule = DllBase;
	act.lpResourceName = ISOLATIONAWARE_MANIFEST_RESOURCE_ID_W;

	// Reset pointer, crucial for x64 version
	*ActivationContext = 0;

	actx = CreateActCtxW(&act);

	// Report no manifest is present
	if (actx == INVALID_HANDLE_VALUE)
		return STATUS_RESOURCE_NAME_NOT_FOUND;

	*ActivationContext = actx;

#ifdef _DEBUG
	LPLog->DetourLog(0, "ProbeCallback: Base %p, path '%ls', context %p Allowed!", DllBase, FullDllPath, *ActivationContext);
#endif
	return STATUS_SUCCESS;
}
#pragma optimize("", on )

void CSelfApiHooks::InitDLLProberCallback()
{
#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrSetDllManifestProber has been initializing");
#endif

	if (!IsWindowsVistaOrGreater()) {
#ifdef _DEBUG
		LPLog->DetourLog(0,"LdrSetDllManifestProber passed in this OS");
#endif
		return;
	}

	auto LdrSetDllManifestProber = (LdrSetDllManifestProberPtr)BetaFunctionTable->GetProcAddress(BetaModuleTable->hNtdll, XOR("LdrSetDllManifestProber"));
#ifdef _DEBUG
	LPLog->AddLog(0, "LdrSetDllManifestProber: %p", LdrSetDllManifestProber);
#endif	
	if (LdrSetDllManifestProber)
		LdrSetDllManifestProber(&ProbeCallback, NULL, &ReleaseActCtx);

#ifdef _DEBUG
	LPLog->DetourLog(0,"LdrSetDllManifestProber succesfuly initialized");
#endif
}

