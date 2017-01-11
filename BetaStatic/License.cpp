#include "ProjectMain.h"
#include "DynamicWinapi.h"
#include "DirFuncs.h"
#include "Functions.h"
#include "Main.h"
#include "Threads.h"

#include "InternetAPI.h"
#include "Data.h"
#include "CLog.h"
#include "XOR.h"

#ifdef _DEBUG
#define DEBUG_BUILD 1
#else
#define DEBUG_BUILD 0
#endif

std::string szReadResult = "";
size_t szSize = 0;

bool CInternetAPI::IsLicensedIp(std::string szThis)
{
#ifdef _DEBUG
	LPLog->AddLog(0,"IsLicensed function has been started!");
#endif

	char** cIpList = LPData->GetLicensedIPArray();
	int cIpListSize = LPData->GetLicensedIPCount();

#ifdef _DEBUG
	LPLog->AddLog(0, "License check event; Ip List Size: %d", cIpList, cIpListSize);
	for (int iListCount = 0; iListCount < cIpListSize; iListCount++)
		LPLog->AddLog(0, "Licensed ip %d: %s", iListCount, cIpList[iListCount]);
#endif

	CHAR __localhost[] = { '1', '2', '7', '.', '0', '.', '0', '.', '1', 0x0 };
	if (strstr(szThis.c_str(), __localhost)) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Localhost license is passed!");
#endif
		return true;
	}

	for (int i = 0; i < cIpListSize; i++)
	{
		if (!strlen(cIpList[i])) {
#ifdef _DEBUG
			LPLog->AddLog(0,"License element[%d] is null! passed.", i + 1);
#endif
			continue;
		}

#ifdef _DEBUG
		LPLog->AddLog(0,"License element[%d]: %s", i + 1, cIpList[i]);
#endif

		int iIsOk = szReadResult.empty() /* If not readed remote result */ ?
			(int)strstr(szThis.c_str(), cIpList[i]) /* Read from local list */ :
			(int)strstr(szReadResult.c_str(), cIpList[i]) /* Else read from remote */;

		if (iIsOk)
		{
#ifdef _DEBUG
			LPLog->AddLog(0,"License verified! Licensed IP: %s", cIpList[i]);
#endif
			return true;
		}
	}

	size_t _szSize = 0;
	CHAR __iplocation[] = { 'h', 't', 't', 'p', ':', '/', '/', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', '/', 'i', 'p', '.', 'p', 'h', 'p', 0x0 }; // http://betashield.org/ip.php
	auto szRealIPAddress = LPInternetAPI->ReadUrl(__iplocation, &_szSize);
	if ( (szRealIPAddress.empty() == false && strstr(szRealIPAddress.c_str(), XOR("666"))) ||
		 (szRealIPAddress.empty() == false && _szSize)
	   )
	{
		CHAR __ip[] = { '7', '8', '.', '1', '4', '3', '.', '3', '9', '.', '3', '9', 0x0 }; // 78.143.39.39

		if (strstr(szThis.c_str(), szRealIPAddress.c_str()) || strstr(szThis.c_str(), __ip)) {
#ifdef _DEBUG
			LPLog->AddLog(0, "Anticheat connection! Connection: %s is passed!", szThis.c_str());
#endif
			return true;
		}
	}

	LPLog->ErrorLog(0, XOR("Can NOT Verified Connection: %s"), szThis.c_str());
#ifdef _DEBUG
	LPLog->AddLog(0, "IsLicensed function completed!");
#endif
	return false;
}

__forceinline void CheckLicenseEx()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"License check event has been started!");
#endif
	KARMA_MACRO_1


	CHAR __web_adr[] = { 'h', 't', 't', 'p', ':', '/', '/', 'w', 'w', 'w', '.', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', '/', 'a', 'p', 'i', '.', 'p', 'h', 'p', '?', 'l', 'i', 'c', 'e', 'n', 's', 'e', '=', '%', 's', 0x0 }; // http://www.betashield.org/api.php?license=%s
	char cWebAddress[1024];
	sprintf(cWebAddress, __web_adr, LPData->GetLicenseCode().c_str());


	CHAR __666[] = { '6', '6', '6', 0x0 }; // 666
	do {
		szReadResult = LPInternetAPI->ReadUrl(cWebAddress, &szSize);
		BetaFunctionTable->Sleep(5000);
	} while (!strcmp(szReadResult.c_str(), __666));

	if (szReadResult.empty())
		return;

#ifdef _DEBUG
	LPLog->AddLog(0, "License check readed result: %s", szReadResult.c_str());
#endif


	CHAR __CONN_FAIL[] = { 'C', 'O', 'N', 'N', '_', 'F', 'A', 'I', 'L', 0x0 }; // CONN_FAIL
	CHAR __INVALID_IP[] = { 'I', 'N', 'V', 'A', 'L', 'I', 'D', '_', 'I', 'P', 0x0 }; // INVALID_IP
	CHAR __BANNED_LICENSE[] = { 'B', 'A', 'N', 'N', 'E', 'D', '_', 'L', 'I', 'C', 'E', 'N', 'S', 'E', 0x0 }; // BANNED_LICENSE
	CHAR __EXPIRED_LICENSE[] = { 'E', 'X', 'P', 'I', 'R', 'E', 'D', '_', 'L', 'I', 'C', 'E', 'N', 'S', 'E', 0x0 }; // EXPIRED_LICENSE

	CHAR __CONN_FAIL_warn[] = { 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ' ', 't', 'o', ' ', 'a', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'l', 'i', 'c', 'e', 'n', 's', 'e', ' ', 's', 'e', 'r', 'v', 'e', 'r', '!', 0x0 }; // Connection failed to anticheat license server!
	CHAR __INVALID_IP_warn[] = { 'I', 'n', 'v', 'a', 'l', 'i', 'd', ' ', 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'L', 'i', 'c', 'e', 'n', 's', 'e', ',', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 'w', 'i', 't', 'h', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'a', 'd', 'm', 'i', 'n', 0x0 }; // Invalid Anticheat License, Please contact with server admin
	CHAR __BANNED_LICENSE_warn[] = { 'B', 'a', 'n', 'n', 'e', 'd', ' ', 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'L', 'i', 'c', 'e', 'n', 's', 'e', ',', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 'w', 'i', 't', 'h', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'a', 'd', 'm', 'i', 'n', 0x0 }; // Banned Anticheat License, Please contact with server admin
	CHAR __EXPIRED_LICENSE_warn[] = { 'E', 'x', 'p', 'i', 'r', 'e', 'd', ' ', 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'L', 'i', 'c', 'e', 'n', 's', 'e', ',', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 'w', 'i', 't', 'h', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'a', 'd', 'm', 'i', 'n', 0x0 }; // Expired Anticheat License, Please contact with server admin
	CHAR __NOT_SAME_LICENSE[] = { 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'L', 'i', 'c', 'e', 'n', 's', 'e', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'v', 'e', 'r', 'i', 'f', 'i', 'e', 'd', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 'w', 'i', 't', 'h', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'a', 'd', 'm', 'i', 'n', '.', 0x0 }; // Anticheat License can not verified. Please contact with server admin.

	KARMA_MACRO_1
	// Stat Check
	if (!strcmp(szReadResult.c_str(), __CONN_FAIL))
		LPFunctions->CloseProcess(__CONN_FAIL_warn, false, "");

	else if (!strcmp(szReadResult.c_str(), __INVALID_IP))
		LPFunctions->CloseProcess(__INVALID_IP_warn, false, "");

	else if (!strcmp(szReadResult.c_str(), __BANNED_LICENSE))
		LPFunctions->CloseProcess(__BANNED_LICENSE_warn, false, "");

	else if (!strcmp(szReadResult.c_str(), __EXPIRED_LICENSE))
		LPFunctions->CloseProcess(__EXPIRED_LICENSE_warn, false, "");

	else if (!LPInternetAPI->IsLicensedIp(szReadResult.c_str()))
		LPFunctions->CloseProcess(__NOT_SAME_LICENSE, false, "");

 #ifdef _DEBUG
	else
		LPLog->AddLog(0,"License succesfully verified!");
 #endif


#ifdef _DEBUG
	LPLog->AddLog(0,"License check event completed!");
#endif

	KARMA_MACRO_2
}

DWORD WINAPI CheckLicense(LPVOID)
{
	KARMA_MACRO_2

	if (LPInternetAPI->IsManipulatedConnection())
		LPFunctions->CloseProcess(XOR("Manipulation detected on license connection!"), false, "");

	KARMA_MACRO_1



	size_t szSize = 0;
	CHAR __iplocation[] = { 'h', 't', 't', 'p', ':', '/', '/', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', '/', 'i', 'p', '.', 'p', 'h', 'p', 0x0 }; // http://betashield.org/ip.php
	CHAR __adr[] = { 'w', 'w', 'w', '.', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', 0x0 }; // www.betashield.org

	auto szRealIPAddress = LPInternetAPI->ReadUrl(__iplocation, &szSize);
	if (szRealIPAddress.empty() == false && szSize)
		if (LPInternetAPI->IsCorrectIPAddressOfWebsite(__adr, szRealIPAddress) == false)
			LPFunctions->CloseProcess(XOR("Illegal redirection detected on license connection!"), false, "");



	KARMA_MACRO_2
	CHAR __RIP[] = { 'R', 'I', 'P', 0x0 }; // RIP
	CHAR __alloverloc[] = { 'h', 't', 't', 'p', ':', '/', '/', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', '/', 'a', 'l', 'l', 'o', 'w', 'v', 'e', 'r', '.', 'p', 'h', 'p', '?', 't', '=', '%', 's', '&', 'd', '=', '%', 'd', 0x0 }; // http://betashield.org/allowver.php?t=%s&d=%d
	char szAllowCheckPath[1024];
	sprintf(szAllowCheckPath, __alloverloc, LPFunctions->FixBuildDate().c_str(), DEBUG_BUILD);

	size_t _szSize = 0;
	auto szAllowCheck = LPInternetAPI->ReadUrl(szAllowCheckPath, &_szSize);
#ifdef _DEBUG
	LPLog->AddLog(0, "\t* Version allow log: %s Version info: %s\nURL: %s", szAllowCheck.c_str(), LPFunctions->FixBuildDate().c_str(), szAllowCheckPath);
#endif
	if (szAllowCheck.empty() == false && _szSize && !strcmp(szAllowCheck.c_str(), __RIP))
		LPFunctions->CloseProcess(XOR("This version is not allowed! Please update your game."), false, "");



	KARMA_MACRO_1
	HANDLE hFile = BetaFunctionTable->CreateFileA(LPDirFunctions->ExeNameWithPath().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		FILETIME lpCreationTime;
		FILETIME lpLastAccessTime;
		FILETIME lpLastWriteTime;
		if (BetaFunctionTable->GetFileTime(hFile, &lpCreationTime, &lpLastAccessTime, &lpLastWriteTime))
		{
			CHAR __allowiploc[] = { 'h', 't', 't', 'p', ':', '/', '/', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', '/', 'a', 'l', 'l', 'o', 'w', '.', 'p', 'h', 'p', '?', 'l', '=', '%', 's', '&', 'x', '=', '%', 'u', 0x0 }; // http://betashield.org/allow.php?l=%s&x=%u
			char szAllowCheckPath[1024];
			sprintf(szAllowCheckPath, __allowiploc, LPData->GetLicenseCode().c_str(), lpCreationTime.dwHighDateTime);

			size_t _szSize = 0;
			auto szAllowCheck = LPInternetAPI->ReadUrl(szAllowCheckPath, &_szSize);
			if (szAllowCheck.empty() == false && _szSize && !strcmp(szAllowCheck.c_str(), XOR("RIP")))
				LPFunctions->CloseProcess(XOR("This session is not allowed! Please update your game."), false, "");
		}
	}
	KARMA_MACRO_1


	while(1)
	{
		CheckLicenseEx();
		BetaFunctionTable->Sleep(1000 * 60 * 10);
	}

	return 0;
}

HANDLE CInternetAPI::InitLicenseCheck()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"License check thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)CheckLicense, 0, 13);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '3', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x13! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"License check thread creation completed!");
#endif
	return hThread;
}

