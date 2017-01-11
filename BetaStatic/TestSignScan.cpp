#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "CLog.h"
#include "XOR.h"


// TODO: If firmware is uefi and secure boot is not enabled close process


bool CheckTestSign_Type1()
{
	DWORD dw, infoci[2] = { sizeof(infoci) };
	unsigned char infosb[0x18];
	unsigned char infobe[0x20];
	ULONG_PTR ret = 0;

	NTSTATUS status1 = BetaFunctionTable->NtQuerySystemInformation(SystemCodeIntegrityInformation, &infoci, sizeof(infoci), &dw);
	if (!NT_SUCCESS(status1))
		return 0;

	dw = sizeof(infosb);
	NTSTATUS status2 = BetaFunctionTable->NtQuerySystemInformation(SystemSecureBootPolicyInformation, &infosb, sizeof(infosb), &dw);
	if (NT_SUCCESS(status2))
	{
		dw = sizeof(infobe);

		NTSTATUS status3 = BetaFunctionTable->NtQuerySystemInformation(SystemBootEnvironmentInformation, &infobe, sizeof(infobe), &dw);
		if (NT_SUCCESS(status3)) {
			if (infosb[0x14] & 0x80)
				ret |= 0x20;
		}
	}

	if (infoci[1] & 1) // enabled
		ret |= 6;
	if (infoci[1] & 2) // testsign
		ret |= 8;

#ifdef _DEBUG
	LPLog->AddLog(0, "Test signature result: %u", ret);
#endif
	return ret ? ret != 6 : false;
}

bool CheckTestSign_Type2()
{
	bool bRet = false;
	char RegKey[_MAX_PATH] = { 0 };
	DWORD BufSize = _MAX_PATH;
	DWORD dataType = REG_DWORD;

	HKEY hKey;
	CHAR __regpath[] = { 'S', 'Y', 'S', 'T', 'E', 'M', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'S', 'e', 't', '\\', 'C', 'o', 'n', 't', 'r', 'o', 'l', '\\', 'C', 'I', 0x0 }; // SYSTEM\CurrentControlSet\Control\CI
	long lError = BetaFunctionTable->RegOpenKeyExA(HKEY_LOCAL_MACHINE, __regpath, NULL, KEY_QUERY_VALUE, &hKey);
	if (lError == ERROR_SUCCESS)
	{
		CHAR __DebugFlags[] = { 'D', 'e', 'b', 'u', 'g', 'F', 'l', 'a', 'g', 's', 0x0 }; // DebugFlags
		long lVal = BetaFunctionTable->RegQueryValueExA(hKey, __DebugFlags, NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
		if (lVal == ERROR_SUCCESS)
		{
			if (!strcmp(RegKey, "1"))
				bRet = true;
		}
		BetaFunctionTable->RegCloseKey(hKey);
	}
	return bRet;
}

bool CheckTestSign_Type3()
{
	bool bRet = false;
	char RegKey[_MAX_PATH] = { 0 };
	DWORD BufSize = _MAX_PATH;
	DWORD dataType = REG_SZ;

	HKEY hKey;
	CHAR __regpath[] = { 'S', 'Y', 'S', 'T', 'E', 'M', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'S', 'e', 't', '\\', 'C', 'o', 'n', 't', 'r', 'o', 'l', 0x0 }; // SYSTEM\CurrentControlSet\Control
	long lError = BetaFunctionTable->RegOpenKeyExA(HKEY_LOCAL_MACHINE, __regpath, NULL, KEY_QUERY_VALUE, &hKey);
	if (lError == ERROR_SUCCESS)
	{
		CHAR __SystemStartOptions[] = { 'S', 'y', 's', 't', 'e', 'm', 'S', 't', 'a', 'r', 't', 'O', 'p', 't', 'i', 'o', 'n', 's', 0x0 }; // SystemStartOptions
		long lVal = BetaFunctionTable->RegQueryValueExA(hKey, __SystemStartOptions, NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
		if (lVal == ERROR_SUCCESS)
		{
			CHAR __TESTSIGNING[] = { 'T', 'E', 'S', 'T', 'S', 'I', 'G', 'N', 'I', 'N', 'G', 0x0 }; // TESTSIGNING
			if (strstr(RegKey, __TESTSIGNING))
				bRet = true;
		}
		BetaFunctionTable->RegCloseKey(hKey);
	}
	return bRet;
}

bool CheckTestSign_Type4()
{
	HKEY hTestKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, TEXT("BCD00000000\\Objects"), 0, KEY_READ, &hTestKey) != ERROR_SUCCESS)
		return false;

	TCHAR    achKey[255];
	DWORD    cbName;
	TCHAR    achClass[MAX_PATH] = TEXT("");
	DWORD    cchClassName = MAX_PATH;
	DWORD    cSubKeys = 0;
	DWORD    cbMaxSubKey;
	DWORD    cchMaxClass;
	DWORD    cValues;
	DWORD    cchMaxValue;
	DWORD    cbMaxValueData;
	DWORD    cbSecurityDescriptor;
	FILETIME ftLastWriteTime;

	DWORD dwApiRetCode = 0;
	bool bRet = false;

	DWORD dwReturn[1000];
	DWORD dwBufSize = sizeof(dwReturn);

	dwApiRetCode = RegQueryInfoKeyA(hTestKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues,
		&cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime);

	if (cSubKeys)
	{
		for (DWORD i = 0; i < cSubKeys; i++)
		{
			cbName = 255;
			dwApiRetCode = RegEnumKeyExA(hTestKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);
			if (dwApiRetCode == ERROR_SUCCESS)
			{

				char szNewWay[4096];
				sprintf(szNewWay, "BCD00000000\\Objects\\%s\\Elements\\16000049", achKey);

				HKEY hnewKey;
				long lError = BetaFunctionTable->RegOpenKeyExA(HKEY_LOCAL_MACHINE, szNewWay, NULL, KEY_QUERY_VALUE, &hnewKey);
				if (lError == ERROR_SUCCESS)
				{
					long lVal = BetaFunctionTable->RegQueryValueExA(hnewKey, "Element", NULL, 0, (LPBYTE)dwReturn, &dwBufSize);
					if (lVal == ERROR_SUCCESS)
					{
						if (dwReturn[0] == (DWORD)1)
							bRet = true;
					}
					BetaFunctionTable->RegCloseKey(hnewKey);
				}

			}
		}
	}

	RegCloseKey(hTestKey);
	return bRet;
}

void CScan::CheckTestSignEnabled()
{
	int iTestSignRet = 0;
	if (CheckTestSign_Type1())
		iTestSignRet = 1;
	else if (CheckTestSign_Type2())
		iTestSignRet = 2;
	else if (CheckTestSign_Type3())
		iTestSignRet = 3;
	else if (CheckTestSign_Type4())
		iTestSignRet = 4;


	if (iTestSignRet)
	{
		CHAR __guide[] = { 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 't', 'e', 's', 't', ' ', '-', ' ', 's', 'i', 'g', 'n', 'i', 'n', 'g', ' ', 'm', 'o', 'd', 'e', ' ', 'b', 'y', ' ', 'f', 'o', 'l', 'l', 'o', 'w', 'i', 'n', 'g', ' ', 't', 'h', 'i', 's', ' ', 'g', 'u', 'i', 'd', 'e', ':', ' ', 'h', 't', 't', 'p', ':', '/', '/', 's', 'u', 'p', 'p', 'o', 'r', 't', '.', 'm', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '.', 'c', 'o', 'm', '/', 'k', 'b', '/', '2', '5', '0', '9', '2', '4', '1', '.', ' ', 'A', 'l', 't', 'e', 'r', 'n', 'a', 't', 'i', 'v', 'e', 'l', 'y', ' ', 'y', 'o', 'u', ' ', 'c', 'a', 'n', ' ', 'f', 'o', 'l', 'l', 'o', 'w', ' ', 't', 'h', 'e', ' ', 'm', 'a', 'n', 'u', 'a', 'l', ' ', 'i', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 's', ' ', 'p', 'r', 'o', 'v', 'i', 'd', 'e', 'd', ' ', 'h', 'e', 'r', 'e', ':', ' ', 'h', 't', 't', 'p', 's', ':', '/', '/', 'm', 's', 'd', 'n', '.', 'm', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '.', 'c', 'o', 'm', '/', 'w', 'i', 'n', 'd', 'o', 'w', 's', '/', 'h', 'a', 'r', 'd', 'w', 'a', 'r', 'e', '/', 'd', 'r', 'i', 'v', 'e', 'r', 's', '/', 'i', 'n', 's', 't', 'a', 'l', 'l', '/', 't', 'h', 'e', '-', 't', 'e', 's', 't', 's', 'i', 'g', 'n', 'i', 'n', 'g', '-', 'b', 'o', 'o', 't', '-', 'c', 'o', 'n', 'f', 'i', 'g', 'u', 'r', 'a', 't', 'i', 'o', 'n', '-', 'o', 'p', 't', 'i', 'o', 'n', 0x0 }; // Please disable test - signing mode by following this guide: http://support.microsoft.com/kb/2509241. Alternatively you can follow the manual instructions provided here: https://msdn.microsoft.com/windows/hardware/drivers/install/the-testsigning-boot-configuration-option
		CHAR __testsignwarn[] = { 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'T', 'e', 's', 't', '-', 'S', 'i', 'g', 'n', 'i', 'n', 'g', ' ', 'M', 'o', 'd', 'e', ' ', 'n', 'o', 't', ' ', 's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', '\n', '\n', 'L', 'o', 'o', 'k', ' ', 'a', 't', ' ', 't', 'o', ' ', 's', 'y', 's', 'e', 'r', 'r', '2', '.', 't', 'x', 't', ' ', 'f', 'o', 'r', ' ', 'm', 'o', 'r', 'e', ' ', 'd', 'e', 't', 'a', 'i', 'l', 's', '.', 0x0 }; // Windows Test-Signing Mode not supported		Look at to syserr2.txt for more details.
		LPLog->AddLog(0, XOR("#%d#\n%s"), iTestSignRet, __guide);
		LPFunctions->CloseProcess(__testsignwarn, false, "");
	}
}

