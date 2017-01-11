#include "ProjectMain.h"
#include "Functions.h"
#include "Main.h"
#include "Threads.h"
#include "CLog.h"
#include "BasePointers.h"
#include "DynamicWinapi.h"
#include "ApiHooks.h"
#include "XOR.h"
#include "Metin2_Plugin.h"
#include "VersionHelpers.h"
#include "Access.h"
#include "DirFuncs.h"


void ChangeThreadsStatus(bool bSuspend)
{
	HANDLE hThreadSnap = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);

		if (BetaFunctionTable->Thread32First(hThreadSnap, &te32))
		{
			do {
				if (te32.th32OwnerProcessID == BetaFunctionTable->GetCurrentProcessId())
				{
					if (te32.th32ThreadID == LPThreads->__GetThreadId(NtCurrentThread))
						continue;

					HANDLE hThread = BetaFunctionTable->OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
					if (hThread && hThread != INVALID_HANDLE_VALUE)
					{
						if (bSuspend)
							BetaFunctionTable->SuspendThread(hThread);
						else
							BetaFunctionTable->ResumeThread(hThread);

						BetaFunctionTable->CloseHandle(hThread);
					}
				}
			} while (BetaFunctionTable->Thread32Next(hThreadSnap, &te32));
		}
		BetaFunctionTable->CloseHandle(hThreadSnap);
	}
}


typedef struct _module_data
{
	BYTE* bMemory;
	BYTE* bFileCopy;
}MODULE_DATA, *PMODULE_DATA;



DWORD Rva2Offset(DWORD dwModule, DWORD dwRVA)
{
	IMAGE_DOS_HEADER* lpDosHdr = (IMAGE_DOS_HEADER *)dwModule;
	IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS *)(dwModule + lpDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pISH = IMAGE_FIRST_SECTION(pNtHdrs);

	for (WORD i = 0, sections = pNtHdrs->FileHeader.NumberOfSections; i < sections; i++, pISH++)
	{
		if (pISH->VirtualAddress <= dwRVA)
		{
			if ((pISH->VirtualAddress + pISH->Misc.VirtualSize) > dwRVA)
			{
				dwRVA -= pISH->VirtualAddress;
				dwRVA += pISH->PointerToRawData;
				return dwRVA;
			}
		}
	}
	return 0;
}

int SaveModuleToBuffer(wchar_t* wcPath, DWORD dwRealBase, BYTE*& byBuffer)
{
	PIMAGE_THUNK_DATA pFirstThunkMirror, pOrigThunkMirror;
	PIMAGE_THUNK_DATA pFirstThunkMemory, pOrigThunkMemory;
	DWORD dwCount, dwDelta;
	DWORD* dwPtrReloc;
	WORD* woList;

	/// Check basics
	if (__STRLENW__(wcPath) < 3) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "%ls is not a specific file name!", wcPath);
#endif
		return -1;
	}

	if (!dwRealBase) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Real base: %u is empty! Path: %ls", dwRealBase, wcPath);
#endif
		return -2;
	}

	/// Store file bytes to memory
	HANDLE hFile = BetaFunctionTable->CreateFileW(wcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "%ls can not opened. Error code: %u", wcPath, LPWinapi->LastError());
#endif
		return -3;
	}

	DWORD dwFileSize = BetaFunctionTable->GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE || !dwFileSize) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "%ls's size can not detected. Error code: %u", wcPath, LPWinapi->LastError());
#endif
		BetaFunctionTable->CloseHandle(hFile);
		return -4;
	}

	BYTE* byFileBytes = new BYTE[dwFileSize];
	if (!byFileBytes) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Memory can not allocated for %ls Size: %u. Error code: %u", wcPath, dwFileSize, LPWinapi->LastError());
#endif
		BetaFunctionTable->CloseHandle(hFile);
		return -5;
	}

	DWORD dwReadBytes = 0;
	BOOL bReadFile = BetaFunctionTable->ReadFile(hFile, byFileBytes, dwFileSize, &dwReadBytes, NULL);
	if (!bReadFile) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File: %ls can not readed. Error code: %u", wcPath, LPWinapi->LastError());
#endif
		delete[] byFileBytes;
		return -6;
	}

	BetaFunctionTable->CloseHandle(hFile);
#ifdef _DEBUG
	LPLog->AddLog(0, "File: %ls's bytes is stored!", wcPath);
#endif

	/// Header check
	if (byFileBytes[0] != 'M' || byFileBytes[1] != 'Z')
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File: %ls's header is not MZ. First: 0x%x Second: 0x%x", wcPath, byFileBytes[0], byFileBytes[1]);
#endif
		delete[] byFileBytes;
		return -7;
	}


	// Parse PE Headers
	IMAGE_DOS_HEADER* lpDosHdr = (IMAGE_DOS_HEADER *)byFileBytes;
	IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS *)(byFileBytes + lpDosHdr->e_lfanew);
	IMAGE_SECTION_HEADER* pISH = (PIMAGE_SECTION_HEADER)(pNtHdrs + 1);

	if (!pNtHdrs->OptionalHeader.SizeOfImage) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File: %ls's NT headers size of image can not detected!", wcPath);
#endif
		delete[] byFileBytes;
		return -8;
	}

	/// Buffer for relocate
	byBuffer = new BYTE[pNtHdrs->OptionalHeader.SizeOfImage];
	if (!byBuffer) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Memory can not allocated for NT Headers. File: %ls Size: %u", wcPath, pNtHdrs->OptionalHeader.SizeOfImage);
#endif
		delete[] byFileBytes;
		return -9;
	}

	ZeroMemory(byBuffer, pNtHdrs->OptionalHeader.SizeOfImage);

	/// Copy PE Header
	memcpy(byBuffer, byFileBytes, 0x1000);

	/// Copy sections
	for (WORD i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++)
		memcpy(byBuffer + pISH[i].VirtualAddress, byFileBytes + pISH[i].PointerToRawData, pISH[i].SizeOfRawData);

	/// Parse headers
	if (pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		int iteration = 0;
		IMAGE_BASE_RELOCATION* pIBR_BUF = (PIMAGE_BASE_RELOCATION)(byBuffer + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		dwDelta = (DWORD)((DWORD)dwRealBase - pNtHdrs->OptionalHeader.ImageBase);

		/// Relocate pointers
		while (pIBR_BUF->VirtualAddress)
		{
			if (pIBR_BUF->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				dwCount = (pIBR_BUF->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				woList = (PWORD)(pIBR_BUF + 1);

				for (DWORD i = 0; i < dwCount; i++)
				{
					if ((woList[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
					{
						dwPtrReloc = (PDWORD)(byBuffer + (pIBR_BUF->VirtualAddress + (woList[i] & 0xFFF)));
						*dwPtrReloc += dwDelta;
					}
				}
			}

			iteration++;
			pIBR_BUF = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR_BUF + pIBR_BUF->SizeOfBlock);
		}
	}

	IMAGE_DOS_HEADER* pDOS_BUF = (IMAGE_DOS_HEADER *)byBuffer;
	IMAGE_NT_HEADERS* pINH_BUF = (IMAGE_NT_HEADERS *)(byBuffer + pDOS_BUF->e_lfanew);

	IMAGE_DOS_HEADER* pDOS_MEM = (IMAGE_DOS_HEADER *)dwRealBase;
	IMAGE_NT_HEADERS* pINH_MEM = (IMAGE_NT_HEADERS *)(dwRealBase + pDOS_MEM->e_lfanew);

	/// Review IAT pointers
	if (pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		IMAGE_IMPORT_DESCRIPTOR* pIID_BUF = (PIMAGE_IMPORT_DESCRIPTOR)(byBuffer + pINH_BUF->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		IMAGE_IMPORT_DESCRIPTOR* pIID_MEM = (PIMAGE_IMPORT_DESCRIPTOR)(dwRealBase + pINH_MEM->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pIID_BUF->Characteristics)
		{
			pOrigThunkMirror = (PIMAGE_THUNK_DATA)(byBuffer + pIID_BUF->OriginalFirstThunk);
			pFirstThunkMirror = (PIMAGE_THUNK_DATA)(byBuffer + pIID_BUF->FirstThunk);

			pOrigThunkMemory = (PIMAGE_THUNK_DATA)(dwRealBase + pIID_MEM->OriginalFirstThunk);
			pFirstThunkMemory = (PIMAGE_THUNK_DATA)(dwRealBase + pIID_MEM->FirstThunk);

			while (pOrigThunkMirror->u1.AddressOfData)
			{
				pFirstThunkMirror->u1.Function = pFirstThunkMemory->u1.Function;


				pOrigThunkMirror++;
				pFirstThunkMirror++;

				pOrigThunkMemory++;
				pFirstThunkMemory++;
			}

			pIID_BUF++;
			pIID_MEM++;
		}
	}

	/// Review EAT Pointers
	if (pINH_BUF->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		PIMAGE_EXPORT_DIRECTORY pIED_BUF = (PIMAGE_EXPORT_DIRECTORY)(byBuffer + pINH_BUF->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PIMAGE_EXPORT_DIRECTORY pIED_MEM = (PIMAGE_EXPORT_DIRECTORY)(dwRealBase + pINH_MEM->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (pIED_BUF->NumberOfFunctions != pIED_MEM->NumberOfFunctions)
		{
#ifdef _DEBUG
			LPLog->ErrorLog(0, "EAT Mismatch detected on file: %ls Mem: %p Mem function count: %u File: %p File function count: %u", 
				wcPath, pIED_MEM, pIED_MEM->NumberOfFunctions, pIED_BUF, pIED_BUF->NumberOfFunctions);
#endif

			return -10;
		}

		if (pIED_BUF->NumberOfFunctions)
		{
			for (DWORD i = 0; i < pIED_BUF->NumberOfFunctions; i++)
			{
				DWORD dwAdrOfFunctions_MEM = pIED_MEM->AddressOfFunctions + dwRealBase;
				DWORD dwAdrOfFunctions_BUF = pIED_BUF->AddressOfFunctions + (DWORD)byBuffer;

				if (*(DWORD*)(dwAdrOfFunctions_MEM + i * 4) != *(DWORD*)(dwAdrOfFunctions_BUF + i * 4))
					*(DWORD*)(dwAdrOfFunctions_BUF + i * 4) = *(DWORD*)(dwAdrOfFunctions_MEM + i * 4);
			}
		}
	}

	delete[] byFileBytes;
	return 1;
}

bool bSkipCheck = false;
bool RewriteBytes(BYTE* byBackup, BYTE* bMemory, DWORD dwLength)
{
	BOOL bVPRet = TRUE;
	DWORD dwOldProt = 0;

	bVPRet = BetaFunctionTable->VirtualProtectEx(NtCurrentProcess, (void*)bMemory, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProt);
	if (bVPRet == FALSE) {
		if (LPWinapi->LastError() == 487)
			bSkipCheck = true;
		return false;
	}


	ChangeThreadsStatus(true);

	if (IsBadWritePtr(byBackup, dwLength) == FALSE)
		nkt_memcopy(bMemory, byBackup, dwLength);

	ChangeThreadsStatus(false);


	bVPRet = BetaFunctionTable->VirtualProtectEx(NtCurrentProcess, (void*)bMemory, dwLength, dwOldProt, &dwOldProt);
	if (bVPRet == FALSE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "RewriteBytes: VirtualProtect 2 fail! Error: %u Base: %p Length: %p", LPWinapi->LastError(), bMemory, dwLength);
#endif
		return false;
	}

	return true;
}

bool StoreBytes(BYTE* byBackup, BYTE* bMemory, DWORD dwLength)
{
	BOOL bVPRet = TRUE;
	DWORD dwOldProt = 0;

	bVPRet = BetaFunctionTable->VirtualProtectEx(NtCurrentProcess, (void*)bMemory, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProt);
	if (bVPRet == FALSE) {
		if (LPWinapi->LastError() == 487)
			bSkipCheck = true;
		return false;
	}


	ChangeThreadsStatus(true);

	if (IsBadReadPtr(bMemory, dwLength) == FALSE)
		nkt_memcopy(byBackup, bMemory, dwLength);

	ChangeThreadsStatus(false);


	bVPRet = BetaFunctionTable->VirtualProtectEx(NtCurrentProcess, (void*)bMemory, dwLength, dwOldProt, &dwOldProt);
	if (bVPRet == FALSE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "StoreBytes: VirtualProtect 2 fail! Error: %u Base: %p Length: %p", LPWinapi->LastError(), bMemory, dwLength);
#endif
		return false;
	}

	return true;
}

int ReloadModule(BYTE* byFileCopy, BYTE* byMemoryCopy, bool bReWrite)
{
	if (!byFileCopy) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Fail! File bytes is empty!");
#endif
		return -11;
	}

	if (!byMemoryCopy) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Fail! Memory bytes is empty!");
#endif
		return -12;
	}


	IMAGE_DOS_HEADER* lpDosHdrFile = (IMAGE_DOS_HEADER *)byFileCopy;
	IMAGE_NT_HEADERS* pNtHdrsFile = (IMAGE_NT_HEADERS *)(byFileCopy + lpDosHdrFile->e_lfanew);
	IMAGE_SECTION_HEADER* pISHFile = (PIMAGE_SECTION_HEADER)(pNtHdrsFile + 1);

	IMAGE_DOS_HEADER* lpDosHdrMem = (IMAGE_DOS_HEADER *)byMemoryCopy;
	IMAGE_NT_HEADERS* pNtHdrsMem = (IMAGE_NT_HEADERS *)(byMemoryCopy + lpDosHdrMem->e_lfanew);
	IMAGE_SECTION_HEADER* pISHMem = (PIMAGE_SECTION_HEADER)(pNtHdrsMem + 1);

	if (pNtHdrsFile->FileHeader.NumberOfSections != pNtHdrsMem->FileHeader.NumberOfSections) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CompareModuleBytes Fail! Section counts is not same! File: %u Mem: %u", pNtHdrsFile->FileHeader.NumberOfSections, pNtHdrsMem->FileHeader.NumberOfSections);
#endif
		return -13;
	}


	for (WORD i = 0; i < pNtHdrsFile->FileHeader.NumberOfSections; i++)
	{
		if ((pISHFile[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pISHFile[i].Characteristics & IMAGE_SCN_CNT_CODE) && (pISHFile[i].Characteristics & IMAGE_SCN_MEM_READ) && !(pISHFile[i].Characteristics & IMAGE_SCN_MEM_WRITE))
		{

			if (pISHFile[i].SizeOfRawData != pISHMem[i].SizeOfRawData) {
#ifdef _DEBUG
				LPLog->ErrorLog(0, "CompareModuleBytes Fail! Raw size-es is not same! File: %u Mem: %u", pISHFile[i].SizeOfRawData, pISHMem[i].SizeOfRawData);
#endif
				return -14;
			}


			if (memcmp(byFileCopy + pISHFile[i].VirtualAddress, byMemoryCopy + pISHMem[i].VirtualAddress, pISHFile[i].SizeOfRawData))
			{
#ifdef _DEBUG
				LPLog->AddLog(0, "Byte difference detected! File: 0x%X - %d _ Memory: %0x%X - %d",
					(UINT)byFileCopy + pISHFile[i].VirtualAddress, pISHFile[i].SizeOfRawData,
					(UINT)byMemoryCopy + pISHMem[i].VirtualAddress, pISHMem[i].SizeOfRawData);
#endif

				if (bReWrite)
				{
#ifdef _DEBUG
					LPLog->AddLog(0, "Rewriting module: 0x%X with buffer: 0x%X", (UINT)byMemoryCopy, (UINT)byFileCopy);
#endif
					if (!StoreBytes(byFileCopy + pISHFile[i].VirtualAddress, byMemoryCopy + pISHMem[i].VirtualAddress, pISHFile[i].SizeOfRawData))
						if (bSkipCheck == false)
							return -15;

					continue;
				}
				else
				{
#ifdef _DEBUG
					LPLog->AddLog(0, "Module: 0x%X is require rewrite...", (UINT)byMemoryCopy);
#endif
				}

#ifdef _DEBUG
				LPLog->AddLog(0, "Rewriting module: 0x%X with buffer: 0x%X size: %u", byFileCopy + pISHFile[i].VirtualAddress, byMemoryCopy + pISHMem[i].VirtualAddress, pISHFile[i].SizeOfRawData);
#endif

				if (!RewriteBytes(byFileCopy + pISHFile[i].VirtualAddress, byMemoryCopy + pISHMem[i].VirtualAddress, pISHFile[i].SizeOfRawData)) {
#ifdef _DEBUG
					LPLog->ErrorLog(0, "Module: 0x%X with size: %u can NOT rewrited!", byFileCopy + pISHFile[i].VirtualAddress, pISHFile[i].SizeOfRawData);
#endif			
					if (bSkipCheck == false)
						return -16;
				}

#ifdef _DEBUG
				LPLog->AddLog(0, "Module: 0x%X with size: %u is succesfully rewrited!", byFileCopy + pISHFile[i].VirtualAddress, pISHFile[i].SizeOfRawData);
#endif


				if (memcmp(byFileCopy + pISHFile[i].VirtualAddress, byMemoryCopy + pISHMem[i].VirtualAddress, pISHFile[i].SizeOfRawData)) {
#ifdef _DEBUG
					LPLog->ErrorLog(0, "Module: 0x%X with size: %u rewrited but is NOT correct!", byFileCopy + pISHFile[i].VirtualAddress, pISHFile[i].SizeOfRawData);
#endif				
					if (bSkipCheck == false)
						return -17;
				}

			}
		}
	}

	return 1;
}

int CheckModules(const vector<MODULE_DATA>& vModuleList)
{
	int iCount = 0;
	for (auto it = vModuleList.begin(); it != vModuleList.end(); ++it)
	{
		int mmErrCode = ReloadModule(it->bFileCopy, it->bMemory, false);
		if (mmErrCode == 1)
			continue;
		
#ifdef _DEBUG
		char cFileName[2048] = { 0 };
		BetaFunctionTable->GetMappedFileNameA(NtCurrentProcess, (LPVOID)it->bMemory, cFileName, 2048);
		LPLog->ErrorLog(0, "Module: %s(0x%X) is corrupted! Error: %d", cFileName, it->bMemory, mmErrCode);
#endif
		return mmErrCode;		
	}

	return 1;
}

bool AddDllToCheckList(int iStep, CHAR* strModuleName, vector<MODULE_DATA>& vModuleList, bool bIsOptional = false)
{
	WCHAR wszPath[MAX_PATH] = { 0 };
	MODULE_DATA mdTmpModule;

	mdTmpModule.bFileCopy = 0;
	int mmErrCode = 0;

	CHAR __1337[] = { '1', '3', '3', '7', 0x0 }; // 1337

	ANTI_MODULE_INFO* selfInfo = { 0 };
	if (LPData->GetGameCode() != TEST_CONSOLE && strModuleName && !strcmp(strModuleName, __1337))
	{
		auto pselfInfo = LPData->GetAntiModuleInformations();
		if (!pselfInfo)
			LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");
		
		selfInfo = (ANTI_MODULE_INFO*)pselfInfo;

		mdTmpModule.bMemory = (BYTE*)selfInfo->BaseAddress;
		goto startcheck;
	}

	if (LPData->GetGameCode() == TEST_CONSOLE && strModuleName && !strcmp(strModuleName, __1337))
		return true;

	if (strModuleName)
		mdTmpModule.bMemory = (BYTE*)NktHookLibHelpers::GetModuleBaseAddress(LPFunctions->UTF8ToWstring(strModuleName).c_str());
	else
		mdTmpModule.bMemory = (BYTE*)BetaModuleTable->hBaseModule;


startcheck:
	if (!mdTmpModule.bMemory && bIsOptional == false) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Module: %s is NOT loaded.", strModuleName);
#endif
		return false;
	}

	if (!mdTmpModule.bMemory && bIsOptional == true) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Optional Module: %s is NOT loaded.", strModuleName);
#endif
		return true;
	}

	if (LPData->GetGameCode() != TEST_CONSOLE && strModuleName && !strcmp(strModuleName, __1337)) { 
		mmErrCode = SaveModuleToBuffer(selfInfo->FullDllName.Buffer, (DWORD)mdTmpModule.bMemory, mdTmpModule.bFileCopy);
	}
	else {
		if (BetaFunctionTable->GetModuleFileNameW((HMODULE)mdTmpModule.bMemory, wszPath, MAX_PATH))
			mmErrCode = SaveModuleToBuffer(wszPath, (DWORD)mdTmpModule.bMemory, mdTmpModule.bFileCopy);
	}

	if (mmErrCode < 1)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Module: %s is NOT relocated. Error: %d", strModuleName, mmErrCode);
#endif
		return false;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "%d) %s is added to check list!", iStep, strModuleName);
#endif
	vModuleList.push_back(mdTmpModule);
	return true;
}

std::vector<MODULE_DATA> vModuleListPre;
void CSelfApiHooks::PreHookCheck()
{
	__try
	{
		CHAR __kernel32dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 }; //kernel32.dll
		CHAR __ntdlldll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 }; // ntdll.dll

		AddDllToCheckList(2, __kernel32dll, vModuleListPre);
		AddDllToCheckList(3, __ntdlldll, vModuleListPre);

		int mmErrCode = 0;
		for (size_t i = 0; i < vModuleListPre.size(); i++)
		{
			mmErrCode = ReloadModule(vModuleListPre[i].bFileCopy, vModuleListPre[i].bMemory, true);
			if (mmErrCode != 1)
			{
				char szWarn[1024];
				sprintf(szWarn, XOR("Pre hook check failed1! Step: %d Error: %d"), i, mmErrCode);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
		}


		mmErrCode = CheckModules(vModuleListPre);
		if (mmErrCode != 1)
		{
			char szWarn[1024];
			sprintf(szWarn, XOR("Module check failed1! Error: %d"), mmErrCode);
			LPFunctions->CloseProcess(szWarn, false, "");
		}
	}
	__except (1) { }
}


bool bIsLoaded = true;
bool CMain::ManualMapIsReady() { return bIsLoaded; };


int mmErrCode = 0;
std::vector<MODULE_DATA> vModuleList;
__forceinline void Step1ModuleCheck()
{
	ChangeThreadsStatus(true);

	__try {
		// Pre-scan Added DLLs
		for (size_t i = 0; i < vModuleList.size(); i++)
		{
			mmErrCode = ReloadModule(vModuleList[i].bFileCopy, vModuleList[i].bMemory, false);
			if (mmErrCode != 1)
			{
				char szWarn[1024];
				sprintf(szWarn, XOR("1st Module check failed! Step: %d Error: %d"), i, mmErrCode);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
		}
	}
	__except (1) {

	}
}
__forceinline void Step2ModuleCheck()
{
	__try {
		// Save changes
		for (size_t i = 0; i < vModuleList.size(); i++)
		{
			mmErrCode = ReloadModule(vModuleList[i].bFileCopy, vModuleList[i].bMemory, true);
			if (mmErrCode != 1)
			{
				char szWarn[1024];
				sprintf(szWarn, XOR("2nd Module check failed! Step: %d Error: %d"), i, mmErrCode);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
		}
	}
	__except (1) {

	}

	ChangeThreadsStatus(false);
}

DWORD WINAPI CheckModuleModificationsEx(LPVOID)
{
	if (false == LPDirFunctions->IsBetaBox(LPFunctions->GetFirstArgument()))
		AddDllToCheckList(1, 0, vModuleList);


	CHAR __kernel32dll[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 }; //kernel32.dll
	CHAR __ntdlldll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 }; // ntdll.dll
	CHAR __User32dll[] = { 'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // User32.dll
	CHAR __ws2_32dll[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // ws2_32.dll

	CHAR __psapidll[] = { 'p', 's', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0x0 }; // psapi.dll
	CHAR __winstadll[] = { 'w', 'i', 'n', 's', 't', 'a', '.', 'd', 'l', 'l', 0x0 }; // winsta.dll
	CHAR __advapi32[] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // advapi32.dll
	CHAR __GDI32dll[] = { 'G', 'D', 'I', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // GDI32.dll
	CHAR __Kernelbasedll[] = { 'K', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l', 0x0 }; // Kernelbase.dll
	CHAR __wininetdll[] = { 'w', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', 0x0 }; // wininet.dll
	CHAR __iphlpapidll[] = { 'i', 'p', 'h', 'l', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0x0 }; // iphlpapi.dll

	CHAR __d3d8dll[] = { 'd', '3', 'd', '8', '.', 'd', 'l', 'l', 0x0 }; // d3d8.dll
	CHAR __d3d9dll[] = { 'd', '3', 'd', '9', '.', 'd', 'l', 'l', 0x0 }; // d3d9.dll
	CHAR __d3d10dll[] = { 'd', '3', 'd', '1', '0', '.', 'd', 'l', 'l', 0x0 }; // d3d10.dll
	CHAR __d3d11dll[] = { 'd', '3', 'd', '1', '1', '.', 'd', 'l', 'l', 0x0 }; // d3d11.dll
	CHAR __d3d12dll[] = { 'd', '3', 'd', '1', '2', '.', 'd', 'l', 'l', 0x0 }; // d3d12.dll


	AddDllToCheckList(2, __kernel32dll, vModuleList);
	AddDllToCheckList(3, __ntdlldll, vModuleList);
	AddDllToCheckList(4, __User32dll, vModuleList);
	AddDllToCheckList(5, __ws2_32dll, vModuleList);

	AddDllToCheckList(6, __psapidll, vModuleList);
	AddDllToCheckList(7, __winstadll, vModuleList);
	AddDllToCheckList(9, __advapi32, vModuleList);
	AddDllToCheckList(10, __GDI32dll, vModuleList);
	AddDllToCheckList(11, __Kernelbasedll, vModuleList, true);
	AddDllToCheckList(12, __wininetdll, vModuleList);
	AddDllToCheckList(13, __iphlpapidll, vModuleList);

	AddDllToCheckList(80, __d3d8dll, vModuleList, true);
	AddDllToCheckList(81, __d3d9dll, vModuleList, true);
	AddDllToCheckList(82, __d3d10dll, vModuleList, true);
	AddDllToCheckList(83, __d3d11dll, vModuleList, true);
	AddDllToCheckList(84, __d3d12dll, vModuleList, true);

	if (IsWindowsVistaOrGreater())
	{
		CHAR __1337[] = { '1', '3', '3', '7', 0x0 }; // 1337
		AddDllToCheckList(99, __1337, vModuleList, true);
	}



	Step1ModuleCheck();


	LPSelfApiHooks->InitDLLProberCallback();
	LPSelfApiHooks->InitApfnHooks();
	LPSelfApiHooks->InitDllNotificationCallback();
	LPSelfApiHooks->InitializeHookAPIs();


	bIsLoaded = false;
	Step2ModuleCheck();
	bIsLoaded = true;

	if (LPData->GetGameCode() == METIN2_GAME) /* Wait for miles sdk initilization, mitigation policys(dll load policy) blocks of miles plugins */
		BetaFunctionTable->Sleep(5000);

#ifdef ENABLE_MITIGATION_POLICYS
	if (IsWindows8OrGreater())
		LPAccess->SetMitigationPolicys();
#endif


	int iCount = 0;
	while (1)
	{
		int mmErrCode = CheckModules(vModuleList);
		if (mmErrCode != 1)
		{
			char szWarn[1024];
			sprintf(szWarn, XOR("Module check failed! Error: %d"), mmErrCode);
			LPFunctions->CloseProcess(szWarn, false, "");
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "Modules checked! Step: %d succesfully completed!", iCount++);
#endif

		LPThreads->IncreaseThreadTick(4);
		BetaFunctionTable->Sleep(5000);
	}

	return 0;
}

HANDLE CMain::CheckModuleModifications()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Check module modification thread creation has been started!");
#endif

	KARMA_MACRO_1
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)CheckModuleModificationsEx, 0, 4);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '4', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x4! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Check module modification thread creation completed!");
#endif
	return hThread;
}

