#include "ProjectMain.h"
#include "AntiCheat_Index.h"
#include "Main.h"
#include "CLog.h"
#include "Data.h"
#include "DynamicWinapi.h"


LONG WINAPI vehFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ContextRecord)
	{
		if (ExceptionInfo->ContextRecord->Dr0 != 0 || ExceptionInfo->ContextRecord->Dr1 != 0 || ExceptionInfo->ContextRecord->Dr2 != 0 ||
			ExceptionInfo->ContextRecord->Dr3 != 0 || ExceptionInfo->ContextRecord->Dr7 != 0)
		{
#ifdef _DEBUG
			LPLog->AddLog(0, "VehFilter: Cleaned debug registers!");
#endif

			ExceptionInfo->ContextRecord->Dr0 = 0;
			ExceptionInfo->ContextRecord->Dr1 = 0;
			ExceptionInfo->ContextRecord->Dr2 = 0;
			ExceptionInfo->ContextRecord->Dr3 = 0;
			ExceptionInfo->ContextRecord->Dr7 = 0;
		}
	}

	CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', ' ', 'o', 'c', 'c', 'u', 'r', 'e', 'd', ' ', '(', '%', 'd', ')', 0x0 }; // Unknown exception occured (%d)
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		LPLog->ErrorLog(0, __warn, 1);
		abort();
	}
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		LPLog->ErrorLog(0, __warn, 2);
		abort();
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
LONG WINAPI sehFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ContextRecord)
	{
		if (ExceptionInfo->ContextRecord->Dr0 != 0 || ExceptionInfo->ContextRecord->Dr1 != 0 || ExceptionInfo->ContextRecord->Dr2 != 0 ||
			ExceptionInfo->ContextRecord->Dr3 != 0 || ExceptionInfo->ContextRecord->Dr7 != 0)
		{
#ifdef _DEBUG
			LPLog->AddLog(0, "SehFilter: Cleaned debug registers!");
#endif
			ExceptionInfo->ContextRecord->Dr0 = 0;
			ExceptionInfo->ContextRecord->Dr1 = 0;
			ExceptionInfo->ContextRecord->Dr2 = 0;
			ExceptionInfo->ContextRecord->Dr3 = 0;
			ExceptionInfo->ContextRecord->Dr7 = 0;
		}
	}

	CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', ' ', 'o', 'c', 'c', 'u', 'r', 'e', 'd', ' ', '(', '%', 'd', ')', 0x0 }; // Unknown exception occured (%d)
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		LPLog->ErrorLog(0, __warn, 3);
		abort();
	}
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
	{
		LPLog->ErrorLog(0, __warn, 4);
		abort();
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

bool CMain::InitializeSEH()
{
	return (BetaFunctionTable->SetUnhandledExceptionFilter(sehFilter) != NULL);
}
bool CMain::InitializeVEH()
{
	return (BetaFunctionTable->AddVectoredExceptionHandler(0, vehFilter) != NULL);
}
