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


std::vector<DWORD> vDestroyedSections;

enum {
	BAD_PATTERN_1 = 1, /* "Embarcadero RAD" */
	BAD_PATTERN_2 /* DLLMain stubs */
};

inline void CheckSectionHash(const char* c_szSectionOwnerName, DWORD dwBase, SIZE_T szSectionSize)
{
	CUtils lpUtils;

	auto szExeNameWithPath = LPDirFunctions->ExeNameWithPath();
	transform(szExeNameWithPath.begin(), szExeNameWithPath.end(), szExeNameWithPath.begin(), tolower);

	if (!strcmp(c_szSectionOwnerName, szExeNameWithPath.c_str()) || strstr(c_szSectionOwnerName, XOR("betacore")))
		return;


	DWORD dwBorlandPattern = LPFunctions->FindPatternClassic(dwBase, (DWORD)szSectionSize,
		(PBYTE)"\x45\x6D\x62\x61\x72\x63\x61\x72\x63\x61\x64\x65\x72\x6F\x20\x52\x41\x44", "xx????xx????xx");

	DWORD dwDLLMain = LPFunctions->FindPatternClassic(dwBase, (DWORD)szSectionSize,
		(BYTE*)"\x55\x8b\xec\x83\x7d\x0c\x01\x75\x00", "xxxxxxxx?");
	DWORD dwDLLMain2 = LPFunctions->FindPatternClassic(dwBase, (DWORD)szSectionSize,
		(BYTE*)"\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x57", "xxxxxxxxxxxxxxxxxxxxxxx");


	CHAR __warn[] = { 'G', 'a', 'm', 'e', ' ', 'h', 'a', 'c', 'k', ' ', 'd', 'e', 't', 'e', 'c', 'c', 't', 'e', 'd', ' ', 'a', 'n', 'd', ' ', 'r', 'e', 'm', 'o', 'v', 'e', 'd', '!', '(', '%', 's', '|', '%', 'd', ')', 0x0 }; // Game hack deteccted and removed!(%s|%d)
	if (dwBorlandPattern) {
		LPLog->ErrorLog(0, __warn, c_szSectionOwnerName, BAD_PATTERN_1);
		if (!NT_SUCCESS(BetaFunctionTable->NtUnmapViewOfSection(NtCurrentProcess, (PVOID)dwBase)))
			lpUtils.Close();
	}

	if ((dwDLLMain || dwDLLMain2) && LPDirFunctions->IsFromWindowsPath(c_szSectionOwnerName) == false)
	{
		auto wszSectionOwner = LPFunctions->UTF8ToWstring(c_szSectionOwnerName);
		static BOOL bSignRet = FALSE;
		LPScan->IsSignedFile(wszSectionOwner.c_str(), &bSignRet);
		if (bSignRet == TRUE)
			return;

		if (strstr(c_szSectionOwnerName, XOR("crashrpt1402")) || strstr(c_szSectionOwnerName, LPData->GetPythonName().c_str()) ||
			strstr(c_szSectionOwnerName, XOR("msvcp1")) || strstr(c_szSectionOwnerName, XOR("msvcr1")))
			return;

		LPLog->ErrorLog(0, __warn, c_szSectionOwnerName, BAD_PATTERN_2);
		if (!NT_SUCCESS(BetaFunctionTable->NtUnmapViewOfSection(NtCurrentProcess, (PVOID)dwBase)))
			lpUtils.Close();
	}

}

inline void ProcessSectionScan(int iType, PBYTE pCurAddr, MEMORY_BASIC_INFORMATION mbi, PMEMORY_SECTION_NAME msnName)
{
	auto szFileName = LPFunctions->WstringToUTF8(msnName->SectionFileName.Buffer);
	auto szLegitName = LPFunctions->DosDevicePath2LogicalPath(szFileName.c_str());
	transform(szLegitName.begin(), szLegitName.end(), szLegitName.begin(), tolower);
	auto wszLegitName = LPFunctions->UTF8ToWstring(szLegitName);

	if (iType == SECTIONSCAN_CHECK_PATTERN)
	{
		if (LPAccess->IsAccessibleImage(mbi) && mbi.AllocationBase)
			CheckSectionHash(szLegitName.c_str(), (DWORD)mbi.AllocationBase, mbi.RegionSize);
	}

	else if (iType == SECTIONSCAN_SCAN_CODECAVE)
	{
		if ((mbi.State & MEM_COMMIT) && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD) && !(mbi.State & MEM_RELEASE))
		{
			/*
			TODO; QueryWorkingSetEx
			*/

			if (std::find(vDestroyedSections.begin(), vDestroyedSections.end(), (DWORD)pCurAddr) == vDestroyedSections.end())
			{

				IMAGE_SECTION_HEADER * pCurrentSecHdr = (IMAGE_SECTION_HEADER*)pCurAddr;
				if (pCurrentSecHdr)
				{
					BOOL IsMonitored =
						(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_READ) &&
						(pCurrentSecHdr->Characteristics & IMAGE_SCN_CNT_CODE) && !(pCurrentSecHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);

					//if (IsMonitored || (!pCurrentSecHdr->Misc.PhysicalAddress && !pCurrentSecHdr->Misc.VirtualSize) /* not touched, allocated section */)
					if (IsMonitored)
					{
						static BOOL bSignRet = FALSE;
						LPScan->IsSignedFile(wszLegitName.c_str(), &bSignRet);
						if (bSignRet == TRUE)
							return;

						CHAR __mix[] = { 'm', 'i', 'x', 0x0 }; //"mix"
						CHAR __asi[] = { 'a', 's', 'i', 0x0 }; //"asi"
						CHAR __m3d[] = { 'm', '3', 'd', 0x0 }; //"m3d"
						CHAR __flt[] = { 'f', 'l', 't', 0x0 }; //"flt"
						CHAR __pyd[] = { 'p', 'y', 'd', 0x0 }; //"pyd"
						if (LPDirFunctions->IsFromCurrentPath(szLegitName.c_str()) &&
							( strstr(szLegitName.c_str(), __mix) || strstr(szLegitName.c_str(), __asi) ||
							  strstr(szLegitName.c_str(), __m3d) || strstr(szLegitName.c_str(), __flt) ||
							  strstr(szLegitName.c_str(), __pyd) ))
						{
							return;
						}

						if (LPData->GetGameCode() != TEST_CONSOLE)
						{
							ANTI_MODULE_INFO* selfInfo = { 0 };
							auto pselfInfo = LPData->GetAntiModuleInformations();
							if (!pselfInfo)
								LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");

							selfInfo = (ANTI_MODULE_INFO*)pselfInfo;

							auto wszDLLName = selfInfo->FullDllName.Buffer;
							auto szDLLName = LPFunctions->WstringToUTF8(wszDLLName);
							auto szLowerDLLName = LPFunctions->szLower(szDLLName);

							if (!strcmp(szLowerDLLName.c_str(), szLegitName.c_str()))
								return;
						}

						if (LPDirFunctions->IsBetaBox(szLegitName))
							return;

						if ( ( LPDirFunctions->IsFromWindowsPath(szLegitName) || LPDirFunctions->IsFromCurrentPath(szLegitName) ) &&
							 ( strstr(szLegitName.c_str(), XOR("python2")) || strstr(szLegitName.c_str(), XOR("speedtreert")) )
						   )
						{
							return;
						}

						CHAR __nvscpapidll[] = { 'n', 'v', 's', 'c', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0x0 }; // nvscpapi.dll
						if (strstr(szLegitName.c_str(), __nvscpapidll))
							return;

						CHAR __warn[] = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'm', 'e', 'm', 'o', 'r', 'y', ' ', 'b', 'l', 'o', 'c', 'k', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'a', 'n', 'd', ' ', 'r', 'e', 'm', 'o', 'v', 'e', 'd', ' ', 'f', 'r', 'o', 'm', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', '!', ' ', 'O', 'w', 'n', 'e', 'r', ':', ' ', '%', 's', 0x0 }; // Unknown memory block detected and removed from process! Owner: %s
						LPLog->ErrorLog(0, __warn, szLegitName.c_str());
						BetaFunctionTable->VirtualFree(pCurAddr, mbi.RegionSize, MEM_FREE);
						vDestroyedSections.push_back((DWORD)pCurAddr);
					}
				}

			}
		}
	}
}

void ScanSections(int iType)
{
	MEMORY_BASIC_INFORMATION mbi;
	ULONG sizeMSNBuffer = 512;

	PMEMORY_SECTION_NAME msnName = (PMEMORY_SECTION_NAME)BetaFunctionTable->VirtualAlloc(NULL, sizeMSNBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!msnName)
		return;

	SYSTEM_INFO sysINFO;
	BetaFunctionTable->GetSystemInfo(&sysINFO);
	PBYTE pCurAddr = (PBYTE)sysINFO.lpMinimumApplicationAddress;
	PBYTE pMaxAddr = (PBYTE)sysINFO.lpMaximumApplicationAddress;

	while (pCurAddr < pMaxAddr)
	{
		NTSTATUS ntRet_mbi = BetaFunctionTable->NtQueryVirtualMemory(NtCurrentProcess, pCurAddr, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		NTSTATUS ntRet_sname = BetaFunctionTable->NtQueryVirtualMemory(NtCurrentProcess, pCurAddr, MemoryMappedFilenameInformation, msnName, sizeMSNBuffer, NULL);

		if (ntRet_mbi == STATUS_SUCCESS && ntRet_sname == STATUS_SUCCESS)
		{
			ProcessSectionScan(iType, pCurAddr, mbi, msnName);

			memset(msnName, 0, sizeMSNBuffer);
		}

		//Get the Next page
		pCurAddr += mbi.RegionSize;
	}

	if (msnName)
		BetaFunctionTable->VirtualFree(msnName, NULL, MEM_RELEASE);
}


DWORD WINAPI ScanSectionsRoutine(LPVOID)
{
	while (1)
	{
	//	ScanSections(SECTIONSCAN_CHECK_PATTERN);
		ScanSections(SECTIONSCAN_SCAN_CODECAVE);

#ifdef _DEBUG
		LPLog->AddLog(0, "Section scan completed!");
#endif

		LPThreads->IncreaseThreadTick(6);
		BetaFunctionTable->Sleep(10000);
	}

	return 0;
}

HANDLE CScan::InitCheckSections()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Section scan thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)ScanSectionsRoutine, 0, 6);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '6', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x6! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Section scan thread creation completed!");
#endif
	return hThread;
}

