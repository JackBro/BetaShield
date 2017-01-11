#include "ProjectMain.h"
#include "Access.h"
#include "DynamicWinapi.h"
#include "VersionHelpers.h"
#include "CLog.h"
#include "XOR.h"


BOOL CAccess::SetDACLRulesToProcess()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Protect process event has been started!");
#endif
	KARMA_MACRO_1

	BYTE    abyBuffer[0x200];
	PACL    pACL;
	SID_IDENTIFIER_AUTHORITY stIdentifierAuthority = SECURITY_WORLD_SID_AUTHORITY;
	PSID pSid = NULL;
	BOOL bRet = FALSE;
	DWORD dwSize = 0;
	HANDLE hToken = NULL;
	PTOKEN_USER pUserInfo = NULL;

	if (BetaFunctionTable->AllocateAndInitializeSid(&stIdentifierAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSid) == FALSE)
		goto Cleanup;
	if (BetaFunctionTable->OpenProcessToken(NtCurrentProcess, TOKEN_QUERY, &hToken) == FALSE)
		goto Cleanup;
	BetaFunctionTable->GetTokenInformation(hToken, TokenUser, NULL, NULL, &dwSize);
	if (dwSize > 1024)
		goto Cleanup;
	pUserInfo = (PTOKEN_USER)BetaFunctionTable->GlobalAlloc(GPTR, dwSize);
	if (pUserInfo == NULL)
		goto Cleanup;
	if (BetaFunctionTable->GetTokenInformation(hToken, TokenUser, pUserInfo, dwSize, &dwSize) == FALSE)
		goto Cleanup;
	pACL = (PACL)&abyBuffer;
	if (BetaFunctionTable->InitializeAcl(pACL, 0x200, ACL_REVISION) == FALSE)
		goto Cleanup;
	// Deny except PROCESS_TERMINATE and PROCESS_SET_SESSIONID
	if (BetaFunctionTable->AddAccessDeniedAce(pACL, ACL_REVISION, PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, pSid) == FALSE)
		goto Cleanup;
	// Allow SYNCHRONIZE, PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA and PROCESS_TERMINATE
	if (BetaFunctionTable->AddAccessAllowedAce(pACL, ACL_REVISION, SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE, pUserInfo->User.Sid) == FALSE)
		goto Cleanup;
	//if (BetaFunctionTable->SetSecurityInfo(NtCurrentProcess, SE_KERNEL_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION /* Restart problem after close process | DACL_SECURITY_INFORMATION */, 0, 0, pACL, 0) != ERROR_SUCCESS)
	if (BetaFunctionTable->SetSecurityInfo(NtCurrentProcess, SE_KERNEL_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 0, 0, pACL, 0) != ERROR_SUCCESS)
		goto Cleanup;

	bRet = TRUE;
#ifdef _DEBUG
	LPLog->AddLog(0, "Process access rules succesfully adjusted. Process protected!");
#endif

Cleanup:
#ifdef _DEBUG
	if (!bRet)
		LPLog->AddLog(0, "ERROR! Process access rules adjust failed! Process can not protected!");
#endif
	if (hToken)
		BetaFunctionTable->CloseHandle(hToken);
	if (pSid)
		BetaFunctionTable->FreeSid(pSid);

#ifdef _DEBUG
	LPLog->AddLog(0, "Protect process event completed!");
#endif
	KARMA_MACRO_2
	return bRet;
}


BOOL CAccess::SetDACLRulesToThread(HANDLE hThread)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Protect thread event has been started!");
#endif
	KARMA_MACRO_1

	BYTE abyBuffer[0x200];
	PACL pACL;
	SID_IDENTIFIER_AUTHORITY stIdentifierAuthority = SECURITY_WORLD_SID_AUTHORITY;
	PSID pSid = NULL;
	BOOL bRet = FALSE;
	DWORD dwSize = 0;
	HANDLE hToken = NULL;
	PTOKEN_USER pUserInfo = NULL;
	DWORD dwLastErr = 0;
	DWORD dwErrStep = 0;

	if (BetaFunctionTable->AllocateAndInitializeSid(&stIdentifierAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSid) == FALSE) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 1;
		goto Cleanup;
	}
	if (BetaFunctionTable->OpenThreadToken(hThread, TOKEN_QUERY, TRUE, &hToken) == FALSE) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 2;
		goto Cleanup;
	}
	BetaFunctionTable->GetTokenInformation(hToken, TokenUser, NULL, NULL, &dwSize);
	if (dwSize > 1024) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 3;
		goto Cleanup;
	}
	pUserInfo = (PTOKEN_USER)BetaFunctionTable->GlobalAlloc(GPTR, dwSize);
	if (pUserInfo == NULL) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 4;
		goto Cleanup;
	}
	if (BetaFunctionTable->GetTokenInformation(hToken, TokenUser, pUserInfo, dwSize, &dwSize) == FALSE) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 5;
		goto Cleanup;
	}
	pACL = (PACL)&abyBuffer;
	if (BetaFunctionTable->InitializeAcl(pACL, 0x200, ACL_REVISION) == FALSE) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 6;
		goto Cleanup;
	}
	// Deny except PROCESS_TERMINATE and PROCESS_SET_SESSIONID
	if (BetaFunctionTable->AddAccessDeniedAce(pACL, ACL_REVISION, PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_ALL_ACCESS, pSid) == FALSE) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 7;
		goto Cleanup;
	}
	if (BetaFunctionTable->SetSecurityInfo(hThread, SE_KERNEL_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 0, 0, pACL, 0) != ERROR_SUCCESS) {
		dwLastErr = LPWinapi->LastError();
		dwErrStep = 8;
		goto Cleanup;
	}

	bRet = TRUE;
#ifdef _DEBUG
	LPLog->AddLog(0, "Thread access rules succesfully adjusted. Thread protected!");
#endif

Cleanup:
#ifdef _DEBUG
	if (!bRet)
		LPLog->AddLog(0, "ERROR! Thread access rules adjust failed! Thread can not protected! Error: %u Step: %u", dwLastErr, dwErrStep);
#endif

	if (hToken)
		BetaFunctionTable->CloseHandle(hToken);
	if (pSid)
		BetaFunctionTable->FreeSid(pSid);

#ifdef _DEBUG
	LPLog->AddLog(0, "Protect thread event completed!");
#endif
	KARMA_MACRO_2
	return bRet;
}

void CAccess::SetPermissions()
{
	HANDLE ProcessHandle = NtCurrentProcess;

	EXPLICIT_ACCESS denyAccess = { PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME };
	DWORD dwAccessPermissions = GENERIC_WRITE | PROCESS_ALL_ACCESS | WRITE_DAC | DELETE | WRITE_OWNER | READ_CONTROL;
	
	CHAR __CURRENT_USER[] = { 'C', 'U', 'R', 'R', 'E', 'N', 'T', '_', 'U', 'S', 'E', 'R', 0x0 }; // CURRENT_USER
	BetaFunctionTable->BuildExplicitAccessWithNameA(&denyAccess, __CURRENT_USER, dwAccessPermissions, DENY_ACCESS, NO_INHERITANCE);

	PACL Pacl = NULL;
	BetaFunctionTable->SetEntriesInAclA(1, &denyAccess, NULL, &Pacl);
	BetaFunctionTable->SetSecurityInfo(ProcessHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, Pacl, NULL);
	BetaFunctionTable->LocalFree(Pacl);

	BetaFunctionTable->CloseHandle(ProcessHandle);
	BetaFunctionTable->SetPriorityClass(ProcessHandle, REALTIME_PRIORITY_CLASS);
}

bool CAccess::BlockAccess()
{
	HANDLE hProcess = NtCurrentProcess;
	SECURITY_ATTRIBUTES sa;

	TCHAR * szSD = "D:P"
	"(D;OICI;GA;;;BG)" /* Deny access to built-in guests */
	"(D;OICI;GA;;;AN)"; /* Deny access to anonymous logon */

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = false;


	if (!BetaFunctionTable->ConvertStringSecurityDescriptorToSecurityDescriptorA(szSD, SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL))
		return false;

	if (!BetaFunctionTable->SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor))
		return true;

	return true;
}

