#include "ProjectMain.h"
#include "WatchDog.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "DirFuncs.h"
#include "XOR.h"
#include "CLog.h"
#include "Base64.h"
#include "Utils.h"



bool CFunctions::IsCreatedFromItself()
{
	KARMA_MACRO_1
	auto dwProcessId = BetaFunctionTable->GetCurrentProcessId();
	if (!dwProcessId) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCreatedFromItself: dwProcessId fail!");
#endif
		return false;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Process ID: %u", dwProcessId);
#endif

	KARMA_MACRO_1
	auto dwParent = LPFunctions->GetProcessParentProcessId(dwProcessId);
	if (!dwParent) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCreatedFromItself: dwParent fail!");
#endif
		return false;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Parent: %u", dwParent);
#endif

	KARMA_MACRO_2
	auto hParent = BetaFunctionTable->OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwParent);
	if (!hParent) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCreatedFromItself: hParent fail!");
#endif
		return false;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Parent: %p", hParent);
#endif

	KARMA_MACRO_1
	auto szParentOwner = LPFunctions->GetProcessFullName(hParent);
	if (szParentOwner.empty()) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCreatedFromItself: szParentOwner fail!");
#endif
		return false;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Owner: %s", szParentOwner.c_str());
#endif

	KARMA_MACRO_2
	auto szParentOwnerReal = LPFunctions->DosDevicePath2LogicalPath(szParentOwner.c_str());
	if (szParentOwnerReal.empty()) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCreatedFromItself: szParentOwnerReal fail!");
#endif
		return false;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Real Owner: %s", szParentOwnerReal.c_str());
#endif

	KARMA_MACRO_1
	auto szMe = LPDirFunctions->ExeNameWithPath();
	if (szMe.empty()) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCreatedFromItself: szMe fail!");
#endif
		return false;
	}
#ifdef _DEBUG
	LPLog->AddLog(0, "Me: %s", szMe.c_str());
#endif

	KARMA_MACRO_1
	if (!strcmp(LPFunctions->szLower(szParentOwnerReal).c_str(), LPFunctions->szLower(szMe).c_str()))
		return true;

	KARMA_MACRO_2
	return false;
}


void CheckParent(std::string szCorrectArg)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "CheckParent started! Correct arg: %s", szCorrectArg.c_str());
#endif

	KARMA_MACRO_1

	std::string szArg = LPFunctions->GetFirstArgument(/* lower */ false);
	if (szArg.empty()) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CheckParent: szArg fail!");
#endif
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "First arg: %s", szArg.c_str());
#endif

	if (LPDirFunctions->IsBetaBox(szArg)) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CheckParent: Parent is betabox! skipped.");
#endif
		return;
	}

	KARMA_MACRO_2


	if (strcmp(szArg.c_str(), szCorrectArg.c_str()))
	{
		KARMA_MACRO_2

		CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 's', 'e', 'l', 'f', '-', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', '!', 0x0 }; // Anticheat self-integrity failed!!
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "CheckParent completed! Parent is legit and created from itself!");
#endif
}

void CreateNewApp(std::string szCorrectArg)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "CreateNewApp started! Correct arg: %s", szCorrectArg.c_str());
#endif

	KARMA_MACRO_2

	char szWarn[2048];
	CHAR __warn[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 's', 'e', 'l', 'f', '-', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'c', 'r', 'e', 'a', 't', 'e', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ' ', 'S', 't', 'e', 'p', ':', ' ', '%', 'd', ' ', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'u', 0x0 }; // Anticheat self-integrity create failed Step: %d Error: %u

	KARMA_MACRO_1

	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	KARMA_MACRO_1

	PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));

	KARMA_MACRO_2

	if (!BetaFunctionTable->CreateProcessA(LPDirFunctions->ExeNameWithPath().c_str(), (char*)szCorrectArg.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CreateNewApp: Run Fail!!! Error: %u", LPWinapi->LastError());
#endif
		sprintf(szWarn, __warn, 1, LPWinapi->LastError());
		LPFunctions->CloseProcess(szWarn, false, "");

		return;
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "New parent run OK. PID: %u Handle: %p", pi.dwProcessId, pi.hProcess);
#endif

	KARMA_MACRO_2

	if (!NT_SUCCESS(BetaFunctionTable->NtResumeThread(pi.hThread, NULL))) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CreateNewApp: Resume Fail!!! Error: %u", LPWinapi->LastError());
#endif
		sprintf(szWarn, __warn, 2, LPWinapi->LastError());
		LPFunctions->CloseProcess(szWarn, false, "");

		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "New parent resume OK.");
#endif

	KARMA_MACRO_2
	if (LPData->GetGameCode() != TEST_CONSOLE)
	{
		BetaFunctionTable->ShowWindow(BetaFunctionTable->GetConsoleWindow(), SW_HIDE);
		
		LPFunctions->RunShadow(pi.dwProcessId); // Execute rundll(aka. BetaShadow) for check suspend
	}

	KARMA_MACRO_2
	// Wait for new app's parent check
	BetaFunctionTable->Sleep(2000);

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "New parent wait OK.");
#endif

	BetaFunctionTable->NtClose(pi.hThread);
	BetaFunctionTable->NtClose(pi.hProcess);

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "New parent ready! Me: %u Parent: %u", BetaFunctionTable->GetCurrentProcessId(), pi.dwProcessId);
#endif
}


void CFunctions::InitSelfRestart(std::string szCorrectArg)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "InitSelfRestart started! Correct arg: %s", szCorrectArg.c_str());
#endif

	KARMA_MACRO_1

	if (IsCreatedFromItself() == true)
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "InitSelfRestart: It's created from itself, Argument check processing...");
#endif

		KARMA_MACRO_2
		CheckParent(szCorrectArg);
		KARMA_MACRO_1

#ifdef _DEBUG
		LPLog->AddLog(0, "InitSelfRestart: Argument check processed!");
#endif

	}
	else
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "InitSelfRestart: It's NOT created from itself, Creating new process!");
#endif

		KARMA_MACRO_2
		CUtils lpUtils;
		lpUtils.SetFlagForExit();

		KARMA_MACRO_1
		CreateNewApp(szCorrectArg);

#ifdef _DEBUG
		LPLog->AddLog(0, "InitSelfRestart: Create new copy completed! Terminating old process: %u", BetaFunctionTable->GetCurrentProcessId());
#endif
		KARMA_MACRO_1

		exit(0);
		BetaFunctionTable->NtTerminateProcess(NtCurrentProcess, EXIT_SUCCESS);
		BetaFunctionTable->WinStationTerminateProcess(NULL, 0, DBG_TERMINATE_PROCESS);
		BetaFunctionTable->BlockInput(TRUE);

		KARMA_MACRO_2
		RtlZeroMemory((void*)BetaModuleTable->hBaseModule, 4096);
		KARMA_MACRO_1

		int* p = 0;
		*p = 0;

		KARMA_MACRO_2
	}


	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0, "InitSelfRestart completed!");
#endif
}
