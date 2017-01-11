#include "ProjectMain.h"
#include "AntiCheat_Index.h"
#include "Main.h"
#include "Data.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "VersionHelpers.h"
#include "CLog.h"

#include "XOR.h"
#include "Threads.h"
#include "DirFuncs.h"
#include "ApiHooks.h"
#include "Scan.h"
#include "Timer.h"
#include "AntiDebug.h"
#include "Access.h"
#include "Services.h"
#include "Test.h"
#include "AntiBreakpoint.h"
#include "Watchdog.h"
#include "Metin2_Plugin.h"
#include "InternetAPI.h"
#include "File_verification.h"
#include "MiniDump.h"


CMain* LPMain;
CMain::CMain()
{
}
CMain::~CMain()
{
}


#pragma optimize("", off )

inline void ExitRoutine()
{
	__PROTECTOR_START__("ex+")

#ifdef _DEBUG
	if (LPData->GetGameCode() != TEST_CONSOLE)
		FreeConsole();
#endif

	LPSelfApiHooks->DestroyAntiMacro();

	__PROTECTOR_END__("ex-")
}

DWORD dwMainCaller = 0;
__forceinline void InitMainEx()
{
#pragma region InitInfo
	CTimer<std::chrono::milliseconds> mainTimer;
#ifdef _DEBUG
	LPLog->AddLog(0, "Anticheat main(ex) function initialization has been started!");
	LPLog->AddLog(0, "Build Date: %s Build Time: %s", __DATE__, __TIME__);
	PrintActiveFlags();
#endif
#pragma endregion InitInfo

#ifdef TEST_MODE

	CTest lpTest;
	lpTest.InitTestMode();

#else

#pragma region PREHookCheck
	LPSelfApiHooks->PreHookCheck();
#pragma endregion PREHookCheck

#pragma region IsItPackedInfo
	auto szProcessName = LPDirFunctions->ExeNameWithPath();
	auto bPackedResult = LPFunctions->IsPackedProcess(szProcessName);
#ifdef _DEBUG
	LPLog->AddLog(0, "Main process packed result: %s", bPackedResult ? "True" : "False");
#endif
	LPData->SetPackedProcess(bPackedResult);
#pragma endregion IsItPackedInfo

#pragma region AdminRightsAndElevations
	try {
		if (LPAccess->IsProcessElevated() == FALSE && LPData->GetGameCode() != TEST_CONSOLE)
			LPFunctions->CloseProcess(XOR("Process can not elevated!"), false, "");
	}
	catch (DWORD dwError) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsProcessElevated failed w/err %lu\n", dwError);
#else
		UNREFERENCED_PARAMETER(dwError);
#endif
	}

	try {
		if (LPAccess->IsRunAsAdmin() == FALSE && LPData->GetGameCode() != TEST_CONSOLE)
			LPFunctions->CloseProcess(XOR("Please run this process as administrator"), false, "");
	}
	catch (DWORD dwError) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsRunAsAdmin failed w/err %lu", dwError);
#else
		UNREFERENCED_PARAMETER(dwError);
#endif
	}
#pragma endregion AdminRightsAndElevations

#pragma region DebugRights
#ifndef _DEBUG
	LPAntiDebug->CheckSeDebugPriv();

	if (IsWindowsVistaOrGreater() && LPData->GetGameCode() != TEST_CONSOLE)
	{
		BOOLEAN boAdjustPrivRet;
		NTSTATUS ntStat = BetaFunctionTable->RtlAdjustPrivilege(20, TRUE, FALSE, &boAdjustPrivRet);
		if (!NT_SUCCESS(ntStat)) {
			CHAR __accesswarn[] = { 'S', 'e', 'l', 'f', ' ', 'a', 'c', 'c', 'e', 's', 's', ' ', 'a', 'd', 'j', 'u', 's', 't', ' ', 'f', 'a', 'i', 'l', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'u', 'n', ' ', 'a', 's', ' ', 'a', 'd', 'm', 'i', 'n', 'i', 's', 't', 'r', 'a', 't', 'o', 'r', 0x0 }; // Self access adjust fail! Please run as administrator
			LPFunctions->CloseProcess(XOR(__accesswarn), false, "");
		}
	}
#endif
#pragma endregion DebugRights

#pragma region ParentCheck
	if (LPFunctions->IsCreatedFromItself() == false)
		LPAntiDebug->ParentCheck(LPData->GetPatcherName().c_str());
#pragma endregion ParentCheck

#pragma region SelfRestart
	CHAR szCorrectArg[] = { 'b', '1', 'c', '9', '1', 'b', '2', 'b', '4', 'f', 'c', 'd', 'f', '3', '2', 'b', 'f', 'a', 'e', 'd', 'c', '7', '5', 'c', 'e', 'a', '8', '1', 'e', '1', '3', '7', 0x0 }; // b1c91b2b4fcdf32bfaedc75cea81e137
	LPFunctions->InitSelfRestart(szCorrectArg);
#pragma endregion SelfRestart

#pragma region BoxCheck
#ifdef USE_BETABOX
	if (LPDirFunctions->IsBetaBox(LPFunctions->GetFirstArgument()) == false)
	{
		CHAR __box[] = { '\\', 'b', 'e', 't', 'a', 'b', 'o', 'x', '.', 'e', 'x', 'e', 0x0 }; // \betabox.exe
		auto szBetaBoxPath = LPDirFunctions->ExePath() + __box;

		char szBoxWarn[1024];
		CHAR __warn[] = { 'T', 'h', 'i', 's', ' ', 'l', 'a', 'u', 'n', 'c', 'h', 'e', 'r', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'a', 'l', 'l', 'o', 'w', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 's', 't', 'a', 'r', 't', ' ', 'w', 'i', 't', 'h', ':', ' ', '%', 's', 0x0 }; // This launcher is not allowed! Please start with: %s
		sprintf(szBoxWarn, __warn, szBetaBoxPath.c_str());
		LPFunctions->CloseProcess(szBoxWarn, false, "");
	}
#endif
#pragma endregion BoxCheck

#pragma region MiniDump
	CDump lpMinidump;
	lpMinidump.InitMiniDump();
#pragma endregion MiniDump

#pragma region SelfModuleInfo
	ANTI_MODULE_INFO* selfInfo = { 0 };
	if (LPData->GetGameCode() != TEST_CONSOLE)
	{
		auto pselfInfo = LPData->GetAntiModuleInformations();
		if (!pselfInfo)
			LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");

		selfInfo = (ANTI_MODULE_INFO*)pselfInfo;

		if ((HMODULE)selfInfo->BaseAddress != LPData->GetAntiModule())
			LPData->SetAntiModule((HMODULE)selfInfo->BaseAddress);
	}
#pragma endregion SelfModuleInfo

#pragma region OSCheck
	CHAR __oldoswarn[] = { 'T', 'h', 'i', 's', ' ', 'O', 'S', ' ', 'c', 'u', 'r', 'r', 'e', 'n', 't', 'l', 'y', ' ', 'n', 'o', 't', ' ', 's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', '!', 0x0 }; // This OS currently not supported!
	if (IsWindowsXPOrGreater() == false || IsWindowsServer())
		LPFunctions->CloseProcess(__oldoswarn, false, "");

	CHAR __NtCreateThreadEx[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', 0x0 }; // NtCreateThreadEx
	CHAR __fakeoswarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'e', 'r', 'r', 'o', 'r', '!', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'i', 's', ' ', 'c', 'o', 'r', 'r', 'u', 'p', 't', 'e', 'd', '!', 0x0 }; // Fatal error! Windows is corrupted!
	if (IsWindowsVistaOrGreater() == false && BetaFunctionTable->_GetProcAddress(BetaModuleTable->hNtdll, __NtCreateThreadEx) /* Any not XP supported windows api*/)
		LPFunctions->CloseProcess(__fakeoswarn, false, "");

	CHAR __fakeversionwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'e', 'r', 'r', 'o', 'r', '!', ' ', 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'e', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e', 'n', 't', '!', 0x0 }; // Fatal error! Unknown Windows environment!
	if (IsFakeConditionalVersion())
		LPFunctions->CloseProcess(__fakeversionwarn, false, "");
#pragma endregion OSCheck

#pragma region SafeModeCheck
	CHAR __safemodewarn[] = { 'T', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'w', 'o', 'r', 'k', 's', ' ', 'o', 'n', ' ', 's', 'a', 'f', 'e', ' ', 'm', 'o', 'd', 'e', '!', 0x0 }; // This process can not works on safe mode!
	auto iSafeMode = BetaFunctionTable->GetSystemMetrics(SM_CLEANBOOT);
	if (iSafeMode > 0)
		LPFunctions->CloseProcess(__safemodewarn, false, "");
#pragma endregion SafeModeCheck

#pragma region WatchdogCheck
	LPWatchdog->SetInitCheckTimer();
#pragma endregion WatchdogCheck

#pragma region TestSignCheck
	LPScan->CheckTestSignEnabled();
#pragma endregion TestSignCheck

#pragma region CallerNameCheck
	char cFileName[2048] = { 0 };
	BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)dwMainCaller, cFileName, 2048);
	auto szLegitName = LPFunctions->DosDevicePath2LogicalPath(cFileName);

	dwMainCaller = 0;
	std::string szLowerDLLName;
	if (LPData->GetGameCode() != TEST_CONSOLE) {
		auto wszDLLName = selfInfo->FullDllName.Buffer;
		auto szDLLName = LPFunctions->WstringToUTF8(wszDLLName);
		szLowerDLLName = LPFunctions->szLower(szDLLName);
	}

	if (LPData->IsPackedProcess() == false)
	{
		char szRealCallerWarn[1024];
		CHAR __callerwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', ' ', 'F', 'r', 'o', 'm', ':', ' ', '%', 's', 0x0 }; // Fatal Error on process initilization! Error code: %d From: %s

		if ((LPData->GetGameCode() == TEST_CONSOLE && !strstr(LPFunctions->szLower(szLegitName).c_str(), LPFunctions->szLower(LPDirFunctions->ExeName()).c_str())) ||
			(LPData->GetGameCode() != TEST_CONSOLE && !strstr(LPFunctions->szLower(szLegitName).c_str(), XOR("betacore.dll")) && strcmp(LPFunctions->szLower(szLegitName).c_str(), szLowerDLLName.c_str()))
			)
		{
#ifdef _DEBUG
			LPLog->AddLog(0, "Main function caller: %s my process: %s anticheat: %s", LPFunctions->szLower(szLegitName).c_str(), LPFunctions->szLower(LPDirFunctions->ExeNameWithPath()).c_str(), szLowerDLLName.c_str());
#endif
			sprintf(szRealCallerWarn, __callerwarn, 1, LPFunctions->szLower(szLegitName).c_str());
			LPFunctions->CloseProcess(szRealCallerWarn, false, "");
		}
	}	
#pragma endregion CallerNameCheck

#pragma region ThreadCountCheck
	if (LPData->IsPackedProcess() == false)
		if (LPThreads->GetThreadCount() > 1)
			LPThreads->CheckThreadStates();
#pragma endregion ThreadCountCheck
		
#pragma region AntisInit
#ifndef _DEBUG
	LPAntiDebug->AntiAnalysis();
	LPAntiDebug->AntiEmulation();
	LPAntiDebug->InitAntiDebug();
	LPAntiDebug->AntiVirtualize();
#endif
	LPScan->InitializeMemoryWatchdog();
#pragma endregion AntisInit

#pragma region InitPermissionRules
	LPAccess->SetPermissions();

	if (LPAccess->SetDACLRulesToProcess() == FALSE) {
		CHAR __accesswarn1[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 'a', 'c', 'c', 'e', 's', 's', ' ', 'r', 'u', 'l', 'e', 's', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'a', 'd', 'j', 'u', 's', 't', 'e', 'd', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', ' ', 'a', 'n', 'd', ' ', 'f', 'i', 'r', 'e', 'w', 'a', 'l', 'l', ' ', 's', 'o', 'f', 't', 'w', 'a', 'r', 'e', 's', '.', 0x0 }; // Process access rules can not adjusted. Please disable antivirus and firewall softwares.
		LPFunctions->CloseProcess(__accesswarn1, false, "");
	}


	bool bUseCurrentThread = false;
	HANDLE hMainThread = nullptr;
	auto dwMainThreadId = LPThreads->GetMainThreadId();

	if (dwMainThreadId)
		hMainThread = BetaFunctionTable->OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwMainThreadId);

	if (!hMainThread) {
		hMainThread = NtCurrentThread;
		bUseCurrentThread = true;
	}

	LPAccess->SetDACLRulesToThread(hMainThread);
	if (bUseCurrentThread == false)
		BetaFunctionTable->CloseHandle(hMainThread);


	LPAccess->BlockAccess();

	if (IsWindowsVistaOrGreater()) {
		LPAccess->EnablePermanentDep();
		LPAccess->EnableNullPageProtection();
	}
#pragma endregion InitPermissionRules

#pragma region ExceptionHandlers
#ifndef _DEBUG

	bool bInitSeh = LPMain->InitializeSEH();
#ifdef _DEBUG
	LPLog->AddLog(0, "SEH Filter Init result: %s", bInitSeh ? "OK" : "Fail");
#endif
	bool bInitVeh = LPMain->InitializeVEH();
#ifdef _DEBUG
	LPLog->AddLog(0, "VEH Filter Init result: %s", bInitVeh ? "OK" : "Fail");
#endif
	
#endif
#pragma endregion ExceptionHandlers

#pragma region Threads
	LPThreads->InitEnumHandle();
	LPThreads->InitAdjustPriv();
	LPThreads->InitModuleCheck();
	LPThreads->InitDirCheckThread();
	LPThreads->InitDriverCheck();
//	LPThreads->InitSectionCheck();
	LPThreads->InitThreadCheck();
	LPThreads->InitAntiThread();
	LPThreads->InitAntiMacroThread();
	LPThreads->InitWindowScan();
	LPThreads->InitWatchdog();
	

#ifdef LICENSE_CHECK
	LPThreads->InitLicenseCheck();
#endif
	LPThreads->InitChecksumThread();
#pragma endregion Threads

#pragma region ThreadIntegrity
	LPThreads->InitThreadTickCheck();
#pragma endregion ThreadIntegrity

#pragma region ExitRoutine
	atexit(ExitRoutine);
#pragma endregion ExitRoutine

#endif

#pragma region FinalInfo
#ifdef _DEBUG
	LPLog->AddLog(0, "Anticheat main(ex) function initialization completed!");
	LPLog->AddLog(0, "Completed in: %lldms", mainTimer.diff());
#endif
#pragma endregion FinalInfo
}


void CMain::InitMain(DWORD dwCaller)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anticheat main function initialization has been started!");
#endif

	KARMA_MACRO_1
	dwMainCaller = dwCaller;
	KARMA_MACRO_1

	__asm
	{
		xor eax, eax
			jz valid
			__asm __emit(0xea)
	valid:
		 call InitMainEx
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anticheat main function initialization completed!");
#endif
}



DWORD WINAPI DelayedExit(LPVOID lpParam)
{
	Sleep((DWORD)lpParam);
	exit(-1);
	abort();
	while (1);
	return 0;
}
__forceinline bool CheckClasses()
{
	return (
		LPLog == NULL || LPData == NULL || BetaModuleTable == NULL || BetaFunctionTable == NULL ||
		LPFunctions == NULL || LPWinapi == NULL || LPDirFunctions == NULL || LPThreads == NULL || 
		LPSelfApiHooks == NULL || LPScan == NULL || LPAntiDebug == NULL || LPAntiBreakpoint == NULL ||
		LPWatchdog == NULL || LPPluginMetin2 == NULL || LPInternetAPI == NULL || LPFile_Verification == NULL
	);
}

void CMain::InitClasses()
{
#pragma region InitClass
	__PROTECTOR_START__("cls+")

	LPLog = new CLog();

	LPData = new CData();

	LPWinapi = new CWinapi();
	BetaModuleTable = (PWINAPI_MODULE_TABLE)nkt_malloc(sizeof(WINAPI_MODULE_TABLE));
	BetaFunctionTable = (PWINAPI_API_TABLE)nkt_malloc(sizeof(WINAPI_API_TABLE));

	LPFunctions = new CFunctions();

	LPDirFunctions = new CDirFunctions();

	LPThreads = new CThreads();

	LPSelfApiHooks = new CSelfApiHooks();

	LPScan = new CScan();

	LPAntiDebug = new CAntiDebug();

	LPAccess = new CAccess();

	LPAntiBreakpoint = new CAntiBreakpoint();

	LPWatchdog = new CWatchdog();

	LPPluginMetin2 = new CPluginMetin2();

	LPInternetAPI = new CInternetAPI();

	LPFile_Verification = new CFile_Verification();
	__PROTECTOR_END__("cls-")

	__MUTATE_START__("ccls+")
	if (CheckClasses()) {
		CreateThread(0, 0, DelayedExit, (LPVOID)3000, 0, 0);
		FatalAppExitA(0, XOR("Fatal error on initialization!!")); // todo dynamic
	}
	__MUTATE_END__("ccls-")

#pragma endregion InitClass
	__PROTECTOR_START__("clso+")

	LPLog->InitLog(XOR("syserr2.txt"), false, "");

	LPWinapi->InitDynamicWinapis();

#ifdef _DEBUG
	if (LPData->GetGameCode() != TEST_CONSOLE)
		LPFunctions->OpenConsoleWindow();
	LPLog->AddLog(0, "BetaShield V2 Anticheat software initialized!");
#endif

	__PROTECTOR_END__("clso-")

#ifdef _DEBUG
	LPLog->AddLog(0, "Anticheat classes initialization completed!");
#endif
}

#pragma optimize("", on )

