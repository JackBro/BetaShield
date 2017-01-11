#include "ProjectMain.h"
#include "DynamicWinapi.h"
#include "VersionHelpers.h"
#include "Functions.h"
#include "CLog.h"
#include "XOR.h"
#include "Main.h"
#include "DirFuncs.h"


int ResumeThreads(DWORD dwProcessId)
{
	HANDLE hSnap = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	THREADENTRY32 ti = { 0 };
	ti.dwSize = sizeof(ti);
	int iCount = 0;
	ULONG uSuspCount = 0;

	if (BetaFunctionTable->Thread32First(hSnap, &ti))
	{
		do {
			if (ti.th32OwnerProcessID == dwProcessId)
			{
				HANDLE hThread = BetaFunctionTable->OpenThread(THREAD_QUERY_INFORMATION, false, ti.th32ThreadID);
				if (hThread) {
resstep:
					if (NT_SUCCESS(BetaFunctionTable->NtResumeThread(hThread, &uSuspCount)))
						iCount++;

					if (uSuspCount > 0) {
						uSuspCount--;
						goto resstep;
					}

					BetaFunctionTable->CloseHandle(hThread);
				}
			}
		} while (BetaFunctionTable->Thread32Next(hSnap, &ti));
	}

	BetaFunctionTable->CloseHandle(hSnap);
	return iCount;
}

void CFunctions::InitShadowEx(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	LPMain->InitClasses();

	BOOLEAN boAdjustPrivRet;
	if (!BetaFunctionTable->RtlAdjustPrivilege || !NT_SUCCESS(BetaFunctionTable->RtlAdjustPrivilege(20, TRUE, FALSE, &boAdjustPrivRet))) {
		CHAR __warn[] = { 'B', 'e', 't', 'a', 'S', 'h', 'a', 'd', 'o', 'w', ':', ' ', 'R', 't', 'l', 'A', 'd', 'j', 'u', 's', 't', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e', ' ', 'i', 's', ' ', 'n', 'u', 'l', 'l', '!', 0x0 }; // BetaShadow: RtlAdjustPrivilege is null!
		LPFunctions->CloseProcess(__warn, false, "");
	}

	DWORD dwProcessId = atol(lpszCmdLine);
	DWORD dwCheckCount = 0;

	while (1)
	{
		if (!LPFunctions->ProcessIsItAlive(dwProcessId)) {
			CHAR __warn[] = { 'B', 'e', 't', 'a', 'S', 'h', 'a', 'd', 'o', 'w', ':', ' ', 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'a', 'l', 'i', 'v', 'e', '!', 0x0 }; // BetaShadow: Process is not alive!
			LPFunctions->CloseProcess(__warn, false, "");
		}


		__try { ResumeThreads(dwProcessId); }
		__except (1) {}

		CHAR __notice[] = { 'B', 'e', 't', 'a', 'S', 'h', 'a', 'd', 'o', 'w', ' ', 'C', 'h', 'e', 'c', 'k', ':', ' ', '%', 'u', ' ', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'e', 'd', '!', 0x0 }; // BetaShadow Check: %u completed!
		LPLog->DebugLog(0, __notice, dwCheckCount++);
		BetaFunctionTable->Sleep(3000);
	}
}

void CFunctions::RunShadow(DWORD dwProcessId)
{
	auto pselfInfo = LPData->GetAntiModuleInformations();
	if (!pselfInfo)
		LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");

	auto selfInfo = (ANTI_MODULE_INFO*)pselfInfo;

	CHAR __rundllwarn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '1', '4', 0x0 }; // Fatal Error on process initilization! Error code: 14
	CHAR __rundlltext[] = { '/', 'c', ' ', 'r', 'u', 'n', 'd', 'l', 'l', '3', '2', '.', 'e', 'x', 'e', ' ', '%', 'l', 's', ',', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'S', 'h', 'a', 'd', 'o', 'w', ' ', '%', 'u', 0x0 }; // /c rundll32.exe %ls,InitializeShadow %u
	CHAR __cmdexe[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e', 0x0 }; // cmd.exe

	char szText[256];
	sprintf(szText, __rundlltext, selfInfo->FullDllName.Buffer, dwProcessId);

	KARMA_MACRO_2
	SHELLEXECUTEINFO ExecuteInfo = { 0 };
	ExecuteInfo.cbSize = sizeof(ExecuteInfo);
	ExecuteInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ExecuteInfo.hwnd = 0;
	ExecuteInfo.lpVerb = 0;
	ExecuteInfo.lpFile = __cmdexe;
	ExecuteInfo.lpParameters = szText;
	ExecuteInfo.lpDirectory = LPDirFunctions->ExePath().c_str();
	ExecuteInfo.nShow = SW_HIDE;
	ExecuteInfo.hInstApp = 0;

	KARMA_MACRO_1
	if (!ShellExecuteExA(&ExecuteInfo))
		LPFunctions->CloseProcess(__rundllwarn, false, "");

	KARMA_MACRO_1
}

