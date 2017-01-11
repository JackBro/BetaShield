#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "DirFuncs.h"

#include "Threads.h"
#include "CLog.h"
#include "XOR.h"


__forceinline void CheckHeuristic(const char* c_szDriverName)
{
	CHAR pchunter_warn[] = { 'P', 'c', 'h', 'u', 'n', 't', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 };
	CHAR phacker_warn[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 'H', 'a', 'c', 'k', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 };
	CHAR xenos_warn[] = { 'X', 'e', 'n', 'o', 's', ' ', 'I', 'n', 'j', 'e', 'c', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 };
	CHAR ring0_warn[] = { 'R', 'i', 'n', 'g', '0', ' ', 'I', 'n', 'j', 'e', 'c', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 };
	CHAR debugger_warn[] = { 'I', 'n', 's', 't', 'a', 'l', 'l', 'e', 'd', ' ', 'd', 'e', 'b', 'u', 'g', 'g', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 };
	CHAR cheatengine_warn[] = { 'C', 'h', 'e', 'a', 't', ' ', 'e', 'n', 'g', 'i', 'n', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'u', 'n', 'i', 'n', 's', 't', 'a', 'l', 'l', ' ', 't', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'a', 'n', 'd', ' ', 'r', 'e', 's', 't', 'a', 'r', 't', ' ', 'y', 'o', 'u', 'r', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '.', 0x0 }; // Cheat engine detected! Please uninstall this process and restart your computer.
	CHAR apimonitor_warn[] = { 'A', 'P', 'I', ' ', 'M', 'o', 'n', 'i', 't', 'o', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // API Monitor detected!
	CHAR xuetr_warn[] = { 'X', 'u', 'e', 'T', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // XueTr detected!
	CHAR win64ast_warn[] = { 'W', 'i', 'n', '6', '4', 'A', 'S', 'T', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // Win64AST detected!


	CHAR _pchunter1[] = { 'p', 'c', 'h', 'u', 'n', 't', 'e', 'r', 0x0 };
	CHAR _pchunter2[] = { 'p', 'c', ' ', 'h', 'u', 'n', 't', 'e', 'r', 0x0 };
	if (strstr(c_szDriverName, _pchunter1) || strstr(c_szDriverName, _pchunter2))
		LPFunctions->CloseProcess(pchunter_warn, false, "");

	CHAR _phacker1[] = { 'p', 'r', 'o', 'c', 'e', 's', 's', 'h', 'a', 'c', 'k', 'e', 'r', 0x0 };
	CHAR _phacker2[] = { 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'h', 'a', 'c', 'k', 'e', 'r', 0x0 };
	if (strstr(c_szDriverName, _phacker1) || strstr(c_szDriverName, _phacker2))
		LPFunctions->CloseProcess(phacker_warn, false, "");

	CHAR __dbk32sys[] = { 'd', 'b', 'k', '3', '2', '.', 's', 'y', 's', 0x0 }; // dbk32.sys
	CHAR __dbk64sys[] = { 'd', 'b', 'k', '6', '4', '.', 's', 'y', 's', 0x0 }; // dbk64.sys
	if (strstr(c_szDriverName, __dbk32sys) || strstr(c_szDriverName, __dbk64sys))
		LPFunctions->CloseProcess(cheatengine_warn, false, "");

	CHAR _ring0[] = { 'i', 'n', 'j', 'e', 'c', 't', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _ring0))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	//xenos injector
	CHAR _xenos[] = { 'b', 'l', 'a', 'c', 'k', 'b', 'o', 'n', 'e', 0x0 };
	if (strstr(c_szDriverName, _xenos))
		LPFunctions->CloseProcess(xenos_warn, false, "");

	// API Monitor
	CHAR _apimonitor[] = { 'a', 'p', 'i', 'm', 'o', 'n', 'i', 't', 'o', 'r', 0x0 };
	if (strstr(c_szDriverName, _apimonitor))
		LPFunctions->CloseProcess(apimonitor_warn, false, "");

	// XueTr
	CHAR __xuetr[] = { 'x', 'u', 'e', 't', 'r', 0x0 };
	if (strstr(c_szDriverName, __xuetr))
		LPFunctions->CloseProcess(xuetr_warn, false, "");

	// Win64AST
	CHAR __win64ast[] = { 'w', 'i', 'n', '6', '4', 'a', 's', 't', 0x0 };
	if (strstr(c_szDriverName, __win64ast))	
		LPFunctions->CloseProcess(win64ast_warn, false, "");


	/*---------------------------------------------- DEBUG -----------------------------------------------------------\\*/
	CHAR _softice1[] = { 's', 'i', 'c', 'e', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _softice1))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _ntice[] = { 'n', 't', 'i', 'c', 'e', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _ntice))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _winice[] = { 'w', 'i', 'n', 'i', 'c', 'e', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _winice))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _syser[] = { 's', 'y', 's', 'e', 'r', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _syser))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _olly[] = { 'o', 'l', 'l', 'y', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _olly))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _softice2[] = { 's', 'i', 'c', 'e', '.', 'v', 'x', 'd', 0x0 };
	if (strstr(c_szDriverName, _softice2))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _windbg[] = { '7', '7', 'f', 'b', 'a', '4', '3', '1', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _windbg))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _iceext[] = { 'i', 'c', 'e', 'e', 'x', 't', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _iceext))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _hanolly[] = { 'h', 'a', 'n', 'o', 'l', 'l', 'y', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _hanolly))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _extrem[] = { 'e', 'x', 't', 'r', 'e', 'm', '.', 's', 'y', 's', 0x0 };
	CHAR _extremehide[] = { 'e', 'x', 't', 'r', 'e', 'm', 'e', 'h', 'i', 'd', 'e', '.', 's', 'y', 's', 0x0 };
	CHAR _frdtsc[] = { 'f', 'r', 'd', 't', 's', 'c', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _extrem) || strstr(c_szDriverName, _extremehide) || strstr(c_szDriverName, _frdtsc))
		LPFunctions->CloseProcess(ring0_warn, false, "");

	CHAR _fengyue[] = { 'f', 'e', 'n', 'g', 'y', 'u', 'e', '.', 's', 'y', 's', 0x0 };
	if (strstr(c_szDriverName, _fengyue))
		LPFunctions->CloseProcess(ring0_warn, false, "");
}

bool IsWhiteListedDriver(const char* c_szDriver)
{
#if 0
	return (
		strstr(c_szDriver, "vsock.sys") || strstr(c_szDriver, "avc3.sys") || strstr(c_szDriver, "bdfwfpf.sys") ||
		strstr(c_szDriver, "bdvedisk.sys") || strstr(c_szDriver, "atkwmiacpi64.sys") || strstr(c_szDriver, "dump_diskdump.sys") ||
		strstr(c_szDriver, "dump_iastora.sys") || strstr(c_szDriver, "dump_iastora.sys") || strstr(c_szDriver, "dump_dumpfve.sys") ||
		strstr(c_szDriver, "vstor2-mntapi20-shared.sys")
	);
#endif
	if (strstr(c_szDriver, XOR("c:/windows/sysnative")))
		return true;

	if (c_szDriver, XOR("bdfwfpf.sys"))
		return true;

	return false;
}

__forceinline void CheckIsHidden(std::string szDriver)
{
	CHAR __hiddendriver[] = { 'H', 'i', 'd', 'd', 'e', 'n', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'y', 'o', 'u', 'r', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'e', 'a', 'c', 't', 'i', 'v', 'a', 't', 'e', ' ', 't', 'h', 'i', 's', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ':', ' ', '%', 's', 0x0 }; // Hidden driver detected in your computer! Please deactivate this driver: %s
	if (LPDirFunctions->is_file_exist(szDriver) == false) {
		char szRealWarn[4096];
		sprintf(szRealWarn, __hiddendriver, szDriver.c_str());
		LPFunctions->CloseProcess(szRealWarn, false, "");
	}
}

__forceinline void CheckIsUnsigned(std::string szDriver)
{
	CHAR __unsigneddriver[] = { 'C', 'o', 'r', 'r', 'u', 'p', 't', 'e', 'd', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'y', 'o', 'u', 'r', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'e', 'a', 'c', 't', 'i', 'v', 'a', 't', 'e', ' ', 't', 'h', 'i', 's', ' ', 'd', 'r', 'i', 'v', 'e', 'r', ':', ' ', '%', 's', 0x0 }; // Corrupted driver detected in your computer! Please deactivate this driver: %s

	auto wszDriver = LPFunctions->UTF8ToWstring(szDriver);
	static BOOL bSignRet = FALSE;

	LPScan->IsSignedFile(wszDriver.c_str(), &bSignRet);
	if (bSignRet == FALSE) {
		char szRealWarn[4096];
		sprintf(szRealWarn, __unsigneddriver, szDriver.c_str());
		LPFunctions->CloseProcess(szRealWarn, false, "");
	}
}

__forceinline void CheckService(std::string szDisplayName, std::string szServiceName)
{
	const char* c_szServiceName = szServiceName.c_str();
	if ( strstr(c_szServiceName, XOR("KProcessHacker")) || strstr(c_szServiceName, XOR("CEDRIVER")) || strstr(c_szServiceName, XOR("XueTr")) )
	{
		CHAR __warn[] = { 'C', 'o', 'r', 'r', 'u', 'p', 't', 'e', 'd', ' ', 's', 'e', 'r', 'v', 'i', 'c', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'y', 'o', 'u', 'r', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'e', 'a', 'c', 't', 'i', 'v', 'a', 't', 'e', ' ', 't', 'h', 'i', 's', ' ', 's', 'e', 'r', 'v', 'i', 'c', 'e', ':', ' ', '%', 's', 0x0 }; // Corrupted service detected in your computer! Please deactivate this service: %s
		char szRealWarn[4096];
		sprintf(szRealWarn, __warn, szServiceName.c_str());
		LPFunctions->CloseProcess(szRealWarn, false, "");
	}
}


void CScan::CheckDriver(std::string szDriver, int iType)
{
	auto szDriverNameWin32 = LPFunctions->NtPathToWin32Path(LPFunctions->szLower(szDriver));
	auto szLowerDriverName = LPFunctions->szLower(szDriverNameWin32);

	if (IsWhiteListedDriver(szLowerDriverName.c_str()))
	{
//#ifdef _DEBUG
//		LPLog->AddLog(0, "%s is in whitelist, passed!", szLowerDriverName.c_str());
//#endif
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(-1, "Driver Check started! Driver name: %s Type: %d", szDriver.c_str(), iType);
#endif

	CheckIsHidden(szLowerDriverName);
	CheckIsUnsigned(szLowerDriverName);
	CheckHeuristic(szLowerDriverName.c_str());
}


__forceinline void CheckDriversNames()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Driver Check name event has been started!");
#endif
	KARMA_MACRO_1

	LPVOID drivers[1024];
	DWORD cbNeeded;

	if (BetaFunctionTable->EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[1024];
		for (size_t i = 0; i < cbNeeded / sizeof(drivers[0]); i++)
		{
			KARMA_MACRO_2
			if (BetaFunctionTable->GetDeviceDriverFileNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
				if (i == 0)
				{
					if (!strstr(szDriver, XOR("ntoskrnl"))) {
						CHAR __patchwarn[] = { 'F', 'A', 'T', 'A', 'L', ' ', 'E', 'R', 'R', 'O', 'R', '!', ' ', 'P', 'a', 't', 'c', 'h', 'e', 'd', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'e', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // FATAL ERROR! Patched Windows environment detected!
						LPFunctions->CloseProcess(__patchwarn, true, "");
					}


					BOOL bSignRet = FALSE;
					auto wszDriver = LPFunctions->UTF8ToWstring(szDriver);
					LPScan->IsSignedFile(wszDriver.c_str(), &bSignRet);

					if (bSignRet == FALSE) {
						CHAR __unsignwarn[] = { 'F', 'A', 'T', 'A', 'L', ' ', 'E', 'R', 'R', 'O', 'R', '!', ' ', 'U', 'n', 'v', 'e', 'r', 'i', 'f', 'i', 'e', 'd', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'e', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // FATAL ERROR! Unverified Windows environment detected!
						LPFunctions->CloseProcess(__unsignwarn, true, "");
					}
				}

				KARMA_MACRO_2

				LPScan->CheckDriver(szDriver, 1);
			}
		}
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Driver Check name event completed!");
#endif
}

 
__forceinline void CheckSystemModules()
{ 
#ifdef _DEBUG
	LPLog->AddLog(0, "System module check event is started!");
#endif
	KARMA_MACRO_1

	PRTL_PROCESS_MODULES ModuleInfo = (PRTL_PROCESS_MODULES)malloc(1024*1024);
    if (!ModuleInfo)
    {
#ifdef _DEBUG
		LPLog->AddLog(0, "Unable to allocate memory for module list Error(%u)", GetLastError());
#endif
		CHAR allocwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '6', 0x0 }; // Fatal Error on process initilization! Error code: 6
		LPFunctions->CloseProcess(allocwarn, false, "");
    }
 
	KARMA_MACRO_2
	NTSTATUS status = BetaFunctionTable->NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, 1024 * 1024, NULL);
    if (!NT_SUCCESS(status))
    {
#ifdef _DEBUG
		LPLog->AddLog(0, "Unable to query module list (%#x)", status);
#endif
		CHAR allocwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '7', 0x0 }; // Fatal Error on process initilization! Error code: 7
		LPFunctions->CloseProcess(allocwarn, false, ""); 
    }
 
	KARMA_MACRO_1
    for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
    {
		char* cDriverName = reinterpret_cast<char *>(ModuleInfo->Modules[i].FullPathName);
		LPScan->CheckDriver(cDriverName, 2);
		KARMA_MACRO_1
    }
 
    free(ModuleInfo);
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "System module check event is completed!");
#endif
}


__forceinline void CheckServices()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Service check event is started!");
#endif
	KARMA_MACRO_1
	SC_HANDLE scManager = BetaFunctionTable->OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scManager == NULL)
		return;

	KARMA_MACRO_2
	ENUM_SERVICE_STATUS struct_ServiceStatus;
	ENUM_SERVICE_STATUS *lpServiceStatus = 0;
	BOOL b_RetVal = FALSE;
	DWORD dw_BytesNeeded = 0;
	DWORD dw_ServiceCount = 0;
	DWORD dw_ResumeHandle = 0;
	DWORD dw_ServiceType = SERVICE_DRIVER;
	DWORD dw_ServiceState = SERVICE_ACTIVE;

	KARMA_MACRO_2
	BetaFunctionTable->EnumServicesStatusA(scManager, dw_ServiceType, dw_ServiceState, &struct_ServiceStatus, sizeof(struct_ServiceStatus), &dw_BytesNeeded, &dw_ServiceCount, &dw_ResumeHandle);
	DWORD dw_Error = BetaFunctionTable->GetLastError();

	KARMA_MACRO_1
	if ((b_RetVal == FALSE) || dw_Error == ERROR_MORE_DATA)
	{
		DWORD dw_Bytes = dw_BytesNeeded + sizeof(ENUM_SERVICE_STATUS);
		lpServiceStatus = new ENUM_SERVICE_STATUS[dw_Bytes];
		BetaFunctionTable->EnumServicesStatusA(scManager, dw_ServiceType, dw_ServiceState, lpServiceStatus, dw_Bytes, &dw_BytesNeeded, &dw_ServiceCount, &dw_ResumeHandle);
	}

	KARMA_MACRO_2
	for (DWORD i = 0; i < dw_ServiceCount; i++)
	{
		KARMA_MACRO_1
		if (lpServiceStatus[i].ServiceStatus.dwCurrentState == 4)
			CheckService(lpServiceStatus[i].lpDisplayName, lpServiceStatus[i].lpServiceName);
	}

	KARMA_MACRO_1
	delete[] lpServiceStatus;
	BetaFunctionTable->CloseServiceHandle(scManager);

#ifdef _DEBUG
	LPLog->AddLog(0, "Service check event is completed!");
#endif
}



DWORD WINAPI CheckDriversRoutine(LPVOID)
{
	KARMA_MACRO_2
	while (1)
	{
		KARMA_MACRO_1
		CheckDriversNames();
		CheckSystemModules();
		CheckServices();

#ifdef _DEBUG
		LPLog->AddLog(0, "Driver Scan completed!");
#endif

		LPThreads->IncreaseThreadTick(12);
		BetaFunctionTable->Sleep(15000);
		KARMA_MACRO_1
	}

	return 0;
}


HANDLE CScan::InitCheckDrivers()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Driver scan thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)CheckDriversRoutine, 0, 12);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '2', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x12! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Driver scan thread creation completed!");
#endif
	return hThread;
}
