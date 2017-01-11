#include "ProjectMain.h"
#include "Access.h"
#include "DynamicWinapi.h"
#include "VersionHelpers.h"
#include "CLog.h"
#include "XOR.h"


BOOL CAccess::IsRunAsAdmin()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!BetaFunctionTable->AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
	{
		dwError = BetaFunctionTable->GetLastError();
		goto Cleanup;
	}

	if (!BetaFunctionTable->CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
	{
		dwError = BetaFunctionTable->GetLastError();
		goto Cleanup;
	}

Cleanup:
	if (pAdministratorsGroup)
	{
		BetaFunctionTable->FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	if (ERROR_SUCCESS != dwError)
		throw dwError;

	return fIsRunAsAdmin;
}

BOOL CAccess::IsProcessElevated()
{
	BOOL fIsElevated = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;

	if (!BetaFunctionTable->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = BetaFunctionTable->GetLastError();
		goto Cleanup;
	}

	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!BetaFunctionTable->GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
	{
		dwError = BetaFunctionTable->GetLastError();
		goto Cleanup;
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	if (hToken)
	{
		BetaFunctionTable->CloseHandle(hToken);
		hToken = NULL;
	}

	if (ERROR_SUCCESS != dwError)
		throw dwError;

	return fIsElevated;
}

