#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "Access.h"
#include "DirFuncs.h"
#include "XOR.h"
#include "Utils.h"
#include "CLog.h"
#include "Data.h"

#include "Threads.h"


bool bDataSectionInitialized = false;
DWORD dwDataSectionChecksumFirst = 0;

bool bTextSectionInitialized = false;
DWORD dwTextSectionChecksumFirst = 0;


#pragma region SectionChecksumUtils
DWORD CalculateChecksum(DWORD dwSectionStart, DWORD dwSectionLen)
{
	DWORD dwChecksumResult = 0;

	__try {
		dwChecksumResult = BetaFunctionTable->RtlComputeCrc32(0, (const BYTE*)dwSectionStart, dwSectionLen);
	}
	__except (1) {

	}
	if (dwChecksumResult)
		goto skip;


	auto pSectionBuf = (BYTE*)malloc(sizeof(BYTE)*dwSectionLen);
	auto pSectionAddress = (DWORD*)dwSectionStart;

	BetaFunctionTable->Toolhelp32ReadProcessMemory(BetaFunctionTable->GetCurrentProcessId(), pSectionAddress, pSectionBuf, dwSectionLen, NULL);
	for (DWORD i = 0; i < dwSectionLen; i++)
		dwChecksumResult += pSectionBuf[i++];

	if (dwChecksumResult != 0)
		dwChecksumResult = (dwChecksumResult & 0x0000FFFF);

	free(pSectionBuf);
skip:
	return dwChecksumResult;
}

bool FindSection(PBYTE pbImageBase, const char* c_szSectionName, LPDWORD dwOffset, LPDWORD dwLen)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pbImageBase;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(pbImageBase + pImageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

	for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		//LPLog->AddLog(0, "%s %s | %d", (char*)pImageSectionHeader[i].Name, c_szSectionName, !strcmp(c_szSectionName, (char*)pImageSectionHeader[i].Name));
		
		if (!strcmp(c_szSectionName, (char*)pImageSectionHeader[i].Name))
		{
			*dwOffset	=	DWORD(pbImageBase + pImageSectionHeader[i].VirtualAddress);
			*dwLen		=	pImageSectionHeader[i].SizeOfRawData;
			return true;
		}
	}

	return false;
}
#pragma endregion SectionChecksumUtils

#pragma region DataSectionCheck
DWORD GetDataSectionHash()
{
	DWORD dwDataBase = 0;
	DWORD dwDataSize = 0;
	bool bFindDataSection = FindSection((BYTE*)BetaModuleTable->hBaseModule, XOR(".data"), &dwDataBase, &dwDataSize);
	if (!bFindDataSection) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Data section can not found!");
#endif
		return 1;
	}
	
	if (dwDataBase == 0) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Data section base address is null! Size: %p", dwDataSize);
#endif
		return 2;
	}
	
	if (dwDataSize == 0) {
		dwDataSize = 1024 * 100;

#ifdef _DEBUG
		LPLog->ErrorLog(0, "Data section size can not detected! Size created as manual: %p IsPacked result: %d Base: %p",
			dwDataSize, LPData->IsPackedProcess() ? 1 : 0, dwDataBase);
#endif
	}

#if 0
	if (LPData->IsPackedProcess())
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "Process is packed! Data section protecting with PAGE_READONLY flag! Base: %p Size: %p",
			dwDataBase, dwDataSize);
#endif

		DWORD dwOldProtect = 0;
		if (BetaFunctionTable->VirtualProtect((LPVOID)dwDataBase, dwDataSize, PAGE_READONLY, &dwOldProtect) == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "Data section can not protected with PAGE_READONLY!");
#endif
			return 3;
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "Data section succesfully protected with PAGE_READONLY!");
#endif
		return 0;
	}
	else
#endif
	{
		if (IsBadReadPtr((LPCVOID)dwDataBase, dwDataSize)) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "Data section is not readable area! Base: %p Size: %p", dwDataBase, dwDataSize);
#endif
			return 4;
		}

		auto dwChecksum = CalculateChecksum(dwDataBase, dwDataSize);
		if (!dwChecksum) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "Data section checksum can not calculated!");
#endif
			return 5;
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "Data section checksum calculated: %p - %p -> (%p)", dwDataBase, dwDataSize, dwChecksum);
#endif
		return dwChecksum;
	}

	return 0;
}

void InitCheckDataSectionHash()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Data section check init started!");
#endif
	KARMA_MACRO_1

re_search:
	if (dwDataSectionChecksumFirst == 0)
		dwDataSectionChecksumFirst = GetDataSectionHash();
	
	BetaFunctionTable->Sleep(100);
	if (dwDataSectionChecksumFirst == 0) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Data section can not detected yet! result: %p", dwDataSectionChecksumFirst);
#endif
		goto re_search;
	}

	bDataSectionInitialized = true;
#ifdef _DEBUG
	LPLog->AddLog(0, "Data section check initialized... first value = %p", dwDataSectionChecksumFirst);
#endif
}

void CheckDataSectionHash()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Data section check started!");
#endif
	KARMA_MACRO_1

	if (bDataSectionInitialized == false) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Data section can not initialized yet!");
#endif
		return;
	}

	DWORD dwDataSectionChecksumSecond = GetDataSectionHash();
#ifdef _DEBUG
	LPLog->AddLog(0, "Data section Checking.. second value = %p", dwDataSectionChecksumSecond);
#endif
	KARMA_MACRO_2
	if (LPData->IsPackedProcess() == false && (!dwDataSectionChecksumFirst || !dwDataSectionChecksumSecond)){
#ifdef _DEBUG
		LPLog->AddLog(0, "Data section Check failed! Ispacked: %d First: %p Second: %p", LPData->IsPackedProcess() ? 1 : 0, dwDataSectionChecksumFirst, dwDataSectionChecksumSecond);
#endif
		LPFunctions->CloseProcess("Anticheat integrity check failed! Error code: 1", false, "");
	}

	if (dwDataSectionChecksumFirst != dwDataSectionChecksumSecond)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Data section is corrupted! Ispacked: %d First: %p Second: %p", LPData->IsPackedProcess() ? 1 : 0, dwDataSectionChecksumFirst, dwDataSectionChecksumSecond);
#endif
		CHAR __warn[] = { 'G', 'a', 'm', 'e', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'd', 'a', 't', 'a', ' ', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', ' ', 'o', 'r', ' ', 'f', 'i', 'r', 'e', 'w', 'a', 'l', 'l', ' ', 's', 'o', 'f', 't', 'w', 'a', 'r', 'e', 's', 0x0 }; // Game process data integrity failed. Please disable antivirus or firewall softwares
		LPFunctions->CloseProcess(__warn, false, "");
	}
#ifdef _DEBUG
	else {
		LPLog->AddLog(0, "Data section Check is OK! Ispacked: %d First: %p Second: %p", LPData->IsPackedProcess() ? 1 : 0, dwDataSectionChecksumFirst, dwDataSectionChecksumSecond);
	}
#endif
}
#pragma endregion DataSectionCheck

#pragma region TextSectionCheck
DWORD GetTextSectionHash()
{
	DWORD dwTextBase = 0;
	DWORD dwTextSize = 0;
	bool bFindTextSection = FindSection((BYTE*)BetaModuleTable->hBaseModule, XOR(".text"), &dwTextBase, &dwTextSize);
	if (!bFindTextSection) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Text section can not found!");
#endif
		return 1;
	}
	
	if (dwTextBase == 0) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Text section base address is null! Base wrapped as module base: %p IsPacked result: %d",
			BetaModuleTable->hBaseModule, LPData->IsPackedProcess() ? 1 : 0);
#endif
		dwTextBase = (DWORD)BetaModuleTable->hBaseModule;
	}
	
	if (dwTextSize == 0) {
		dwTextSize = 1024 * 1024;

#ifdef _DEBUG
		LPLog->ErrorLog(0, "Text section size can not detected! Size created as manual: %p IsPacked result: %d Base: %p",
			dwTextSize, LPData->IsPackedProcess() ? 1 : 0, dwTextBase);
#endif
	}

#if 0
	if (LPData->IsPackedProcess())
	{
#ifdef _DEBUG
		LPLog->AddLog(0, "Process is packed! Text section protecting with PAGE_READONLY flag! Base: %p Size: %p",
			dwTextBase, dwTextSize);
#endif

		DWORD dwOldProtect = 0;
		if (BetaFunctionTable->VirtualProtect((LPVOID)dwTextBase, dwTextSize, PAGE_READONLY, &dwOldProtect) == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "Text section can not protected with PAGE_READONLY!");
#endif
			return 3;
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "Text section succesfully protected with PAGE_READONLY!");
#endif
		return 0;
	}
	else
#endif
	{
		if (IsBadReadPtr((LPCVOID)dwTextBase, dwTextSize)) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "Text section is not readable area! Base: %p Size: %p", dwTextBase, dwTextSize);
#endif
			return 4;
		}

		auto dwChecksum = CalculateChecksum(dwTextBase, dwTextSize);
		if (!dwChecksum) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "Text section checksum can not calculated!");
#endif
			return 5;
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "Text section checksum calculated: %p - %p -> (%p)", dwTextBase, dwTextSize, dwChecksum);
#endif
		return dwChecksum;
	}

	return 0;
}

void InitCheckTextSectionHash()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Text section check init started!");
#endif
	KARMA_MACRO_1

re_search:
	if (dwTextSectionChecksumFirst == 0)
		dwTextSectionChecksumFirst = GetTextSectionHash();
	
	BetaFunctionTable->Sleep(100);
	if (dwTextSectionChecksumFirst == 0 && LPData->IsPackedProcess() == false) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Text section can not detected yet! result: %p", dwTextSectionChecksumFirst);
#endif
		goto re_search;
	}
	else if (dwTextSectionChecksumFirst == 0 && LPData->IsPackedProcess() == true) {
		bTextSectionInitialized = false;
		return;
	}

	bTextSectionInitialized = true;
#ifdef _DEBUG
	LPLog->AddLog(0, "Text section check initialized... first value = %p", dwTextSectionChecksumFirst);
#endif
}

void CheckTextSectionHash()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Text section check started!");
#endif
	KARMA_MACRO_1

	if (bTextSectionInitialized == false) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Text section can not initialized yet!");
#endif
		return;
	}

	DWORD dwTextSectionChecksumSecond = GetTextSectionHash();
#ifdef _DEBUG
	LPLog->AddLog(0, "Text section Checking.. second value = %p", dwTextSectionChecksumSecond);
#endif
	KARMA_MACRO_2

	if (LPData->IsPackedProcess() == false && (!dwTextSectionChecksumFirst || !dwTextSectionChecksumSecond)){
#ifdef _DEBUG
		LPLog->AddLog(0, "Text section Check failed! Ispacked: %d First: %p Second: %p", LPData->IsPackedProcess() ? 1 : 0, dwTextSectionChecksumFirst, dwTextSectionChecksumSecond);
#endif
		LPFunctions->CloseProcess("Anticheat integrity check failed! Error code: 2", false, "");
	}

	if (dwTextSectionChecksumFirst != dwTextSectionChecksumSecond)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Text section is corrupted! Ispacked: %d First: %p Second: %p", LPData->IsPackedProcess() ? 1 : 0, dwTextSectionChecksumFirst, dwTextSectionChecksumSecond);
#endif
		CHAR __warn[] = { 'G', 'a', 'm', 'e', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'o', 'd', 'e', ' ', 'i', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', ' ', 'o', 'r', ' ', 'f', 'i', 'r', 'e', 'w', 'a', 'l', 'l', ' ', 's', 'o', 'f', 't', 'w', 'a', 'r', 'e', 's', 0x0 }; // Game process code integrity failed. Please disable antivirus or firewall softwares
		LPFunctions->CloseProcess(__warn, false, "");
	}
#ifdef _DEBUG
	else {
		LPLog->AddLog(0, "Text section Check is OK! Ispacked: %d First: %p Second: %p", LPData->IsPackedProcess() ? 1 : 0, dwTextSectionChecksumFirst, dwTextSectionChecksumSecond);
	}
#endif
}
#pragma endregion TextSectionCheck



DWORD WINAPI CheckSectionsHash(LPVOID)
{
	BetaFunctionTable->Sleep(3000);

	//InitCheckDataSectionHash();
	InitCheckTextSectionHash();

	while (1) {
		//CheckDataSectionHash();
		CheckTextSectionHash();

		LPThreads->IncreaseThreadTick(9);
		BetaFunctionTable->Sleep(6000);
	}
	return 0;
}

HANDLE CScan::InitChecksumScan()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Checksum control thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)CheckSectionsHash, 0, 9);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '9', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x9! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Checksum control thread creation completed!");
#endif
	return hThread;
}