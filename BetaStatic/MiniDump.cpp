#include "ProjectMain.h"
#include "DynamicWinapi.h"
#include "MiniDump.h"
#include "Functions.h"
#include "XOR.h"
#include "BasePointers.h"
#include "Main.h"
#include "CLog.h"



// Custom minidump callback 
BOOL CALLBACK MyMiniDumpCallback(PVOID pParam, const PMINIDUMP_CALLBACK_INPUT pInput, PMINIDUMP_CALLBACK_OUTPUT pOutput)
{
	BOOL bRet = FALSE;

	// Check parameters 
	if (!pInput)
		return FALSE;

	if (!pOutput)
		return FALSE;

	// Process the callbacks 
	switch (pInput->CallbackType)
	{
		case IncludeModuleCallback:
		{
			// Include the module into the dump 
			bRet = TRUE;
		}
		break;

		case IncludeThreadCallback:
		{
			// Include the thread into the dump 
			bRet = TRUE;
		}
		break;

		case ModuleCallback:
		{
			// Does the module have ModuleReferencedByMemory flag set ? 
			if (!(pOutput->ModuleWriteFlags & ModuleReferencedByMemory)) {
				// No, it does not - exclude it 
				// wprintf(L"Excluding module: %s \n", pInput->Module.FullPath);
				pOutput->ModuleWriteFlags &= (~ModuleWriteModule);
			}
			bRet = TRUE;
		}
		break;

		case ThreadCallback:
		{
			// Include all thread information into the minidump 
			 bRet = TRUE;
		}
		break;

		case ThreadExCallback:
		{
			// Include this information 
			 bRet = TRUE;
		}
		break;

		case MemoryCallback:
		{
			// We do not include any information here -> return FALSE 
			bRet = FALSE;
		}
		break;

		case CancelCallback:
			break;
	}

	return bRet;
}


void CreateMiniDump(EXCEPTION_POINTERS* pep)
{
	BasePointers lpBasePointers;
	CMain lpMain;

	time_t t;
	time(&t);
	struct tm *tinfo;
	tinfo = localtime(&t);

	WCHAR __warn[] = { L'B', L'e', L't', L'a', L'L', L'o', L'g', L'%', L'Y', L'%', L'm', L'%', L'd', L'_', L'%', L'H', L'%', L'M', L'%', L'S', L'.', L'd', L'm', L'p', L'\0' }; // BetaLog%Y%m%d_%H%M%S.dmp
	wchar_t dump_name[128];
	wcsftime(dump_name, 128, __warn, tinfo);


	auto hKernel32 = reinterpret_cast<HMODULE>(lpBasePointers.GetKernel32Handle());
	auto _CreateFileW_ = (lpCreateFileW)BetaFunctionTable->GetProcAddress(hKernel32, XOR("CreateFileW"));
	auto _GetCurrentThreadId_ = (lpGetCurrentThreadId)BetaFunctionTable->GetProcAddress(hKernel32, XOR("GetCurrentThreadId"));
	auto _GetCurrentProcessId_ = (lpGetCurrentProcessId)BetaFunctionTable->GetProcAddress(hKernel32, XOR("GetCurrentProcessId"));
	auto _CloseHandle_ = (lpCloseHandle)BetaFunctionTable->GetProcAddress(hKernel32, XOR("CloseHandle"));

	HMODULE hDbgHelp =  BetaModuleTable->hDbghelp;
	hDbgHelp = hDbgHelp ? hDbgHelp : LoadLibraryA(XOR("dbghelp.dll"));
	auto _MiniDumpWriteDump_ = (lpMiniDumpWriteDump)BetaFunctionTable->GetProcAddress(hDbgHelp, XOR("MiniDumpWriteDump"));

	// file format MiniDump[YYYYMMDD][HH_MM_SEC]
	HANDLE hFile = _CreateFileW_(dump_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile && hFile != INVALID_HANDLE_VALUE) {
		// Create the minidump 

		MINIDUMP_EXCEPTION_INFORMATION mdei;
		mdei.ThreadId = _GetCurrentThreadId_();
		mdei.ExceptionPointers = pep;
		mdei.ClientPointers = FALSE;

		MINIDUMP_CALLBACK_INFORMATION mci;
		mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MyMiniDumpCallback;
		mci.CallbackParam = 0;

		MINIDUMP_TYPE mdt = (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory);

		BOOL rv = _MiniDumpWriteDump_(NtCurrentProcess, _GetCurrentProcessId_(), hFile, mdt, (pep != 0) ? &mdei : 0, 0, &mci);

		CHAR __ok[] = { 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', ' ', 'd', 'u', 'm', 'p', ' ', 's', 'u', 'c', 'c', 'e', 's', 's', 'f', 'u', 'l', 'l', 'y', ' ', 'c', 'r', 'e', 'a', 't', 'e', 'd', '.', 0x0 }; // Exception dump successfully created.
		CHAR __nop[] = { 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', ' ', 'd', 'u', 'm', 'p', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'c', 'r', 'e', 'a', 't', 'e', 'd', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'u', 0x0 }; // Exception dump is not created. Error code: %u

		if (!rv)
			LPLog->ErrorLog(0, __nop, LPWinapi->LastError());
		else
			LPLog->AddLog(0, __ok);

		// Close the file 
		_CloseHandle_(hFile);
	}
	else {
		CHAR __fileerror[] = { 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', ' ', 'd', 'u', 'm', 'p', ' ', 'f', 'i', 'l', 'e', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'c', 'r', 'e', 'a', 't', 'e', 'd', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'u', 0x0 }; // Exception dump file is not created. Error code: %u
		LPLog->AddLog(0, __fileerror, LPWinapi->LastError());
	}
}

LONG WINAPI ExceptionFilterSeh(EXCEPTION_POINTERS* pExceptionInfo)
{
	if (pExceptionInfo && pExceptionInfo->ExceptionRecord)
	{
		if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
			HANDLE hThread = BetaFunctionTable->CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CreateMiniDump, pExceptionInfo, 0, NULL);
			BetaFunctionTable->WaitForSingleObject(hThread, INFINITE);
			BetaFunctionTable->CloseHandle(hThread);
		}
		else {
			CreateMiniDump(pExceptionInfo);
		}

		LPLog->AddLog(0, XOR("Seh exception triggered. Code: %p"), pExceptionInfo->ExceptionRecord->ExceptionCode);
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

void CDump::InitMiniDump()
{
#ifdef _DEBUG
	if (BetaFunctionTable->SetUnhandledExceptionFilter(ExceptionFilterSeh))
		LPLog->AddLog(0, "Mini dump generator Exception handler is succesfully created!");
	else
		LPLog->ErrorLog(0, "Mini dump generator Exception handler is NOT created!");
#endif
}

