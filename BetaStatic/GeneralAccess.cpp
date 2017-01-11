#include "ProjectMain.h"
#include "XOR.h"
#include "Access.h"
#include "DynamicWinapi.h"
#include "Threads.h"
#include "Functions.h"
#include "VersionHelpers.h"

#include "DirFuncs.h"
#include "CLog.h"

CAccess* LPAccess;
CAccess::CAccess()
{
}

CAccess::~CAccess()
{
}

#pragma optimize("", off )
__forceinline bool AdjustSingleTokenPrivilege(HANDLE TokenHandle, LPCTSTR lpName, DWORD dwAttributes)
{
	KARMA_MACRO_2
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = dwAttributes;

	if (!BetaFunctionTable->LookupPrivilegeValueA(NULL, lpName, &(tp.Privileges[0].Luid)))
		return false;

	if (!BetaFunctionTable->AdjustTokenPrivileges(TokenHandle, FALSE, &tp, 0, NULL, NULL))
		return false;
	KARMA_MACRO_1

	return true;
}

bool CAccess::EnableDebugPrivileges()
{
	HANDLE hToken = NULL;

	KARMA_MACRO_1
	if (!BetaFunctionTable->OpenProcessToken(NtCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	if (!AdjustSingleTokenPrivilege(hToken, SE_SECURITY_NAME, SE_PRIVILEGE_ENABLED) ||
		!AdjustSingleTokenPrivilege(hToken, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED))
		return false;

	BetaFunctionTable->CloseHandle(hToken);
	KARMA_MACRO_2
	return true;
}

bool CAccess::DisableDebugPrivileges() {
	HANDLE hToken = NULL;

	KARMA_MACRO_1
	if (!BetaFunctionTable->OpenProcessToken(NtCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	if (!AdjustSingleTokenPrivilege(hToken, SE_SECURITY_NAME, SE_PRIVILEGE_REMOVED) ||
		!AdjustSingleTokenPrivilege(hToken, SE_DEBUG_NAME, SE_PRIVILEGE_REMOVED))
		return false;

	BetaFunctionTable->CloseHandle(hToken);
	KARMA_MACRO_2
	return true;
}


void CAccess::EnablePermanentDep()
{
	ULONG ExecuteFlags;
	
	/* Set up proper flags, call NtSetInformationProcess to disble RW memory execution and make it permanent */
	ExecuteFlags = MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_PERMANENT;
	NTSTATUS Status = BetaFunctionTable->NtSetInformationProcess(NtCurrentProcess, ProcessExecuteFlags, &ExecuteFlags, sizeof(ExecuteFlags));

#ifdef _DEBUG
	if (NT_SUCCESS(Status))
		LPLog->AddLog(0, "Permanent DEP enabled!");
	else 
		LPLog->ErrorLog(0, "Permanent DEP can NOT enabled!");
#endif
}

void CAccess::EnableNullPageProtection()
{
	SIZE_T RegionSize;
	LPVOID lpBaseAddress;
	
	/* Allocate null page and first 0x1000 bytes proceeding it */
	RegionSize = 0x1000;
	lpBaseAddress = (PVOID)0x1;

	NTSTATUS Status = BetaFunctionTable->NtAllocateVirtualMemory(NtCurrentProcess, &lpBaseAddress, 0L, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
#ifdef _DEBUG
	if (NT_SUCCESS(Status))
		LPLog->AddLog(0, "NULL Page Allocation Prevention Enabled!");
	else
		LPLog->ErrorLog(0, "NULL Page Allocation Prevention can NOT Enabled!");
#endif
}



bool CAccess::IsAccessibleMemory(MEMORY_BASIC_INFORMATION mbi)
{
	return (mbi.State & MEM_COMMIT) && !(mbi.State & MEM_RELEASE) &&
		((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_READWRITE)) &&
		!(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

bool CAccess::IsAccessibleImage(MEMORY_BASIC_INFORMATION mbi)
{
	return (mbi.Type == MEM_IMAGE) && IsAccessibleMemory(mbi);
}

#pragma optimize("", on )
