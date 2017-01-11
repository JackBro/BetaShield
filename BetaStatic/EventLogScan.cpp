#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "CLog.h"
#include "VersionHelpers.h"
#include "DirFuncs.h"
#include "XOR.h"
#include "boost/algorithm/string/replace.hpp"
#include <boost/foreach.hpp>
#include <boost/algorithm/string/iter_find.hpp>
#include <boost/tokenizer.hpp>
#include <list>
using namespace boost;


bool IsVBoxInstalled()
{
	HKEY hKey = NULL;
	LRESULT lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, XOR("Software\\Oracle\\VirtualBox"), 0, KEY_READ, &hKey);

	bool bRet = (hKey != NULL);

	if (hKey) 
		RegCloseKey(hKey);

	return bRet;
}

ULONGLONG WindowsTickToUnixSeconds(ULONGLONG windowsTicks)
{
	return (ULONGLONG)(windowsTicks / 10000000 - 11644473600);
}

LPWSTR AllocEvtFormatMessage(EVT_HANDLE ehPublisherMetadata, EVT_HANDLE ehLogEntry, DWORD dwFlags)
{
	LPWSTR wszOutput = NULL;
	DWORD dwLength = 32768;
	DWORD dwBufferUsedSize = 0;

	while (1) {
		wszOutput = (LPWSTR)realloc(wszOutput, dwLength * sizeof(WCHAR));
		if (wszOutput == NULL)
			return NULL;

		if (BetaFunctionTable->EvtFormatMessage(ehPublisherMetadata, ehLogEntry, 0, 0, NULL, dwFlags, dwLength, wszOutput, &dwBufferUsedSize))
			return wszOutput;

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			free(wszOutput);
			return NULL;
		}

		dwLength *= 10;
	}

	return wszOutput;
}

void ProcessEventRecord(std::string szServiceName, std::string szFileName)
{
	// LPLog->AddLog(0, "ServiceName: '%s'", szServiceName.c_str());
	// LPLog->AddLog(0, "FileName: '%s'", szFileName.c_str());

	std::string szLowerServiceName = LPFunctions->szLower(szServiceName);

	char szWarn[2048];
	CHAR __err[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'd', 'e', 'v', 'i', 'c', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', '%', 's', ' ', '-', ' ', '%', 'd', 0x0 }; // Unknown device detected! %s - %d

	CHAR __vbox[] = { 'v', 'b', 'o', 'x', 0x0 }; // vbox
	if (strstr(szLowerServiceName.c_str(), __vbox))
	{
		if (IsVBoxInstalled() == false)
		{
			sprintf(szWarn, __err, szFileName.c_str(), 1);
			LPLog->ErrorLog(0, szWarn);
		}

		char szLink[1024];
		sprintf(szLink, "\\\\.\\%s", szServiceName.c_str());
		if (INVALID_HANDLE_VALUE == BetaFunctionTable->CreateFileA(szLink, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0))
		{
			sprintf(szWarn, __err, szFileName.c_str(), 2);
			LPLog->ErrorLog(0, szWarn);
		}
	}
}

void CheckEventRecord(LPCWSTR c_wszSource, LPCWSTR c_wszMessage)
{
	typedef vector< std::string > pVecReadResult;

	std::string szSource = LPFunctions->WstringToUTF8(c_wszSource);
	if (strstr(szSource.c_str(), "Service Control Manager"))
	{
		std::string szMessage = LPFunctions->WstringToUTF8(c_wszMessage);

		std::string szServiceName = "";
		std::string szFileName = "";

		std::vector<std::string> stringList;
		boost::iter_split(stringList, szMessage, boost::first_finder("\n"));
		for (size_t i = 0; i < stringList.size(); i++)
		{

			// Service Name:  VBoxDrv
			if (strstr(stringList[i].c_str(), "Service Name"))
			{
				std::vector<std::string> subStringList;
				boost::iter_split(subStringList, stringList[i], boost::first_finder(":  "));
				szServiceName = subStringList[1];
			}

			// Service File Name:  C:\Windows\system32\drivers\VBoxDrv.sys
			if (strstr(stringList[i].c_str(), "Service File Name"))
			{
				std::vector<std::string> subStringList;
				boost::iter_split(subStringList, stringList[i], boost::first_finder(":  "));
				szFileName = subStringList[1];
			}

		}

		if (szServiceName.empty() == false && szFileName.empty() == false)
			ProcessEventRecord(szServiceName, szFileName);

	}
}

bool CheckLog(EVT_HANDLE ehRenderContext, EVT_HANDLE ehLogEntry)
{
	PEVT_VARIANT peVariant = nullptr;
	DWORD dwLength = 32768;
	DWORD dwBufferUsedSize = 0;
	DWORD dwPropertyCount = 0;

	while (1) {
		peVariant = (PEVT_VARIANT)realloc(peVariant, dwLength);
		if (peVariant == NULL) {
			LPLog->ErrorLog(0, "CheckLog alloc fail! Err: %u", GetLastError());
			return false;
		}

		if (BetaFunctionTable->EvtRender(ehRenderContext, ehLogEntry, EvtRenderEventValues, dwLength, peVariant, &dwBufferUsedSize, &dwPropertyCount))
			break;

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			LPLog->ErrorLog(0, "CheckLog unknown error! Err: %u", GetLastError());
			free(peVariant);
			return false;
		}

		dwLength = dwBufferUsedSize;
	}

	LPWSTR wszMetaMessage = NULL;
	EVT_HANDLE ehMetaData = BetaFunctionTable->EvtOpenPublisherMetadata(NULL, peVariant[2].StringVal, NULL, 0, 0);
	if (ehMetaData)
		wszMetaMessage = AllocEvtFormatMessage(ehMetaData, ehLogEntry, EvtFormatMessageEvent);


	CheckEventRecord(peVariant[2].StringVal, wszMetaMessage);


	if (wszMetaMessage)
		free(wszMetaMessage);
	if (ehMetaData)
		BetaFunctionTable->EvtClose(ehMetaData);

	free(peVariant);
	return true;
}

bool EventLogCheckEx()
{
	if (IsWindowsVistaOrGreater() == false) {
		LPLog->ErrorLog(0, "EventLogCheckEx not supported os");
		return true;
	}

	LPCWSTR c_wszPaths[] = { 
		L"/Event/System/EventRecordID", L"/Event/System/TimeCreated/@SystemTime",
		L"/Event/System/Provider/@Name", L"/Event/System/Computer",
	};

	bool bRet = false;
	int iCount = 0;

	EVT_HANDLE ehRenderContext = BetaFunctionTable->EvtCreateRenderContext(_countof(c_wszPaths), c_wszPaths, EvtRenderContextValues);
	if (ehRenderContext == NULL) {
		LPLog->ErrorLog(0, "EvtCreateRenderContext fail! Err: %u", GetLastError());
		return bRet;
	}

	EVT_HANDLE ehQuery = BetaFunctionTable->EvtQuery(NULL, L"System", L"*", EvtQueryChannelPath | EvtQueryReverseDirection);
	if (ehQuery == NULL) {
		LPLog->ErrorLog(0, "EvtQuery fail! Err: %u", GetLastError());
		BetaFunctionTable->EvtClose(ehRenderContext);
		return bRet;
	}

	DWORD i = 0;
	DWORD dwEventCount = 0;
	EVT_HANDLE ehEvents[1024];
	while (BetaFunctionTable->EvtNext(ehQuery, _countof(ehEvents), ehEvents, INFINITE, 0, &dwEventCount))
	{
		for (i = 0; i < dwEventCount; i++)
		{
			if (!CheckLog(ehRenderContext, ehEvents[i]))
				goto leave_loop;
			
			if (!BetaFunctionTable->EvtClose(ehEvents[i]))
				goto leave_loop;		

			if (iCount > 1000)
				goto leave_loop; // First 1000 log
			
			iCount++;
		}
	}

	if (GetLastError() == ERROR_NO_MORE_ITEMS)
		bRet = true;

	if (iCount <= 10) {
		// cleaned log, kill process
	}

leave_loop:
	while (i < dwEventCount) {
		BetaFunctionTable->EvtClose(ehEvents[i]);
		i++;
	}

	BetaFunctionTable->EvtClose(ehQuery);
	BetaFunctionTable->EvtClose(ehRenderContext);

	return bRet;
}


void CScan::InitializeEventLogCheck()
{
	EventLogCheckEx();
}

