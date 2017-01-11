#include "ProjectMain.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "Utils.h"
#include "VersionHelpers.h"
#include "XOR.h"
#include "Main.h"
#include "DirFuncs.h"
#include "Scan.h"

#include "CLog.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>


CFunctions* LPFunctions;
CFunctions::CFunctions()
{
}

CFunctions::~CFunctions()
{
}


void CFunctions::fMessageBox(HWND wind, DWORD dwTimeout, const char* title, const char* cArgFormat, ...) {
	KARMA_MACRO_1;
	char cTmpString[2000];

	va_list vaArgList;
	va_start(vaArgList, cArgFormat);
	KARMA_MACRO_2;
	vsnprintf(cTmpString, cArgFormat, vaArgList);
	KARMA_MACRO_2;
	va_end(vaArgList);

	if (dwTimeout)
		BetaFunctionTable->MessageBoxTimeout(wind, cTmpString, title, NULL, 0, dwTimeout);
	else
		BetaFunctionTable->MessageBoxA(wind, cTmpString, title, NULL);
	KARMA_MACRO_1;
}

void CFunctions::CsrssMessageBox(const wchar_t* c_wszTitle, const wchar_t* c_wszMessage)
{
	UNICODE_STRING uniTitle;
	BetaFunctionTable->RtlInitUnicodeString(&uniTitle, c_wszTitle);
	UNICODE_STRING uniMessage;
	BetaFunctionTable->RtlInitUnicodeString(&uniMessage, c_wszMessage);

	ULONG pUnicodeArguments[] = { 0, 0, 0 };
	pUnicodeArguments[0] = (ULONG)&uniTitle;
	pUnicodeArguments[1] = (ULONG)&uniMessage;

	HARDERROR_RESPONSE ReturnValue;
	BetaFunctionTable->NtRaiseHardError(0x50000018, 3, 3, (PVOID *)pUnicodeArguments, OptionOk, &ReturnValue);
}

void CFunctions::TrayBaloon(const wchar_t* c_wszTitle, const wchar_t* c_wszMessage)
{
	UNICODE_STRING uniTitle;
	BetaFunctionTable->RtlInitUnicodeString(&uniTitle, c_wszTitle);
	UNICODE_STRING uniMessage;
	BetaFunctionTable->RtlInitUnicodeString(&uniMessage, c_wszMessage);

	ULONG pUnicodeArguments[] = { 0, 0, 0 };
	pUnicodeArguments[0] = (ULONG)&uniTitle;
	pUnicodeArguments[1] = (ULONG)&uniMessage;

	HARDERROR_RESPONSE ReturnValue;
	BetaFunctionTable->NtRaiseHardError(0x50000018, 3, 3, (PVOID *)pUnicodeArguments, OptionExplorerTrayBaloon, &ReturnValue);
}

void CFunctions::CloseProcess(const char* c_szLog, bool bIsDebugger, const char* c_szFaqPage, bool bEncrypted, DWORD dwLastError)
{
	KARMA_MACRO_1
	CUtils lpUtils;

#ifndef PASSIVE_MODE
	if (lpUtils.IsFlaggedForExit())
		return;
	lpUtils.SetFlagForExit();
#endif

	if (strlen(c_szLog)) {
#ifdef _DEBUG
		CHAR __warntitle[] = { 'C', 'l', 'o', 's', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'a', 'l', 'l', 'e', 'd', '!', '!', '!', ' ', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 's', 0x0 }; // CloseProcess called!!! Error: %s
		LPLog->ErrorLog(0, __warntitle, c_szLog);
#else
		LPLog->ErrorLog(0, c_szLog);
#endif
	}

#ifdef SCRENSHOT_FEATURE
	SendScreenshotToServer();
#endif

#ifdef PASSIVE_MODE
	return;
#endif

	KARMA_MACRO_2
	if (LPData->DynamicAPIsIsInitialized())
	{
		if (!bIsDebugger) {
			CHAR __title[] = { 'E', 'R', 'R', 'O', 'R', '!', 0x0 }; // ERROR!
			BetaFunctionTable->MessageBoxTimeout(0, c_szLog, __title, MB_ICONERROR, 0, 4000);
		}

		CHAR __open[] = { 'o', 'p', 'e', 'n', 0x0 };
		if (strlen(c_szFaqPage))
			BetaFunctionTable->ShellExecute(NULL, __open, c_szFaqPage, NULL, NULL, SW_SHOWNORMAL);
	}

#ifdef _DEBUG
	BetaFunctionTable->Sleep(5000);
#endif
	KARMA_MACRO_2
	lpUtils.Close();
	KARMA_MACRO_1
}


#ifdef _DEBUG
int OpenConsoleWindowEx()
{
	if (!AllocConsole())
		return 0;

	CHAR __title[] = { 'D', 'e', 'b', 'u', 'g', ' ', 'C', 'o', 'n', 's', 'o', 'l', 'e', ' ', 'f', 'o', 'r', ' ', 'B', 'e', 't', 'a', 'S', 'h', 'i', 'e', 'l', 'd', 0x0 };
	CHAR __CONOUT[] = { 'C', 'O', 'N', 'O', 'U', 'T', '$', 0x0 };
	CHAR __CONIN[] = { 'C', 'O', 'N', 'I', 'N', '$', 0x0 }; 
	CHAR __a[] = { 'a', 0x0 }; 
	CHAR __r[] = { 'r', 0x0 }; 

	freopen(__CONOUT, __a, stdout);
	freopen(__CONIN, __r, stdin);

	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!h)
		return -2;

	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
	if (!GetConsoleScreenBufferInfo(h, &csbiInfo))
		return -3;
	if (!SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY))
		return -4;

	Sleep(120);

	if (!SetConsoleTitleA(__title))
		return -5;

	return 0;
}

void CFunctions::OpenConsoleWindow()
{
	CHAR __Consoleloaded[] = { 'C', 'o', 'n', 's', 'o', 'l', 'e', ' ', 'w', 'i', 'n', 'd', 'o', 'w', ' ', 's', 'u', 'c', 'c', 'e', 's', 'f', 'u', 'l', 'y', ' ', 'l', 'o', 'a', 'd', 'e', 'd', '!', '\n', 0x0 }; // Console window succesfuly loaded!
	CHAR __Consolefailed[] = { 'C', 'o', 'n', 's', 'o', 'l', 'e', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', 0x0 }; // Console failed! Error code:
	CHAR __syserr2[] = { 's', 'y', 's', 'e', 'r', 'r', '2', '.', 't', 'x', 't', 0x0 }; // syserr2.txt

	int iRet = OpenConsoleWindowEx();
	if (iRet < 0) {
		std::ofstream f(__syserr2, std::ofstream::out | std::ofstream::app);
		f << __Consolefailed << iRet << '\n' << std::endl;
		f.close();
		exit(0);
	}

	LPLog->ConsoleLog(0, __Consoleloaded);

}
#endif


std::wstring CFunctions::UTF8ToWstring(const std::string& input)
{
	wchar_t buf[8192] = { 0 };
#ifdef _DEBUG
	MultiByteToWideChar(CP_UTF8, 0, input.c_str(), (int)input.length(), buf, ARRAYSIZE(buf));
#else
	BetaFunctionTable->MultiByteToWideChar(CP_UTF8, 0, input.c_str(), (int)input.length(), buf, ARRAYSIZE(buf));
#endif
	return buf;
}

std::string CFunctions::WstringToUTF8(const std::wstring& input)
{
	char buf[8192] = { 0 };
#ifdef _DEBUG
	WideCharToMultiByte(CP_UTF8, 0, input.c_str(), (int)input.length(), buf, ARRAYSIZE(buf), nullptr, nullptr);
#else
	BetaFunctionTable->WideCharToMultiByte(CP_UTF8, 0, input.c_str(), (int)input.length(), buf, ARRAYSIZE(buf), nullptr, nullptr);
#endif
	return buf;
}

std::string CFunctions::szLower(std::string String)
{
	KARMA_MACRO_2
	std::transform(String.begin(), String.end(), String.begin(), tolower);
	return String;
}

std::wstring CFunctions::wszLower(std::wstring String)
{
	std::transform(String.begin(), String.end(), String.begin(), towlower);
	KARMA_MACRO_1
	return String;
}


struct EnumData {
	DWORD dwProcessId;
	HWND hWnd;
};
BOOL CALLBACK EnumProc(HWND hWnd, LPARAM lParam) {
	EnumData& ed = *(EnumData*)lParam;
	DWORD dwProcessId = 0x0;

	BetaFunctionTable->GetWindowThreadProcessId(hWnd, &dwProcessId);
	if (ed.dwProcessId == dwProcessId) {
		ed.hWnd = hWnd;
		BetaFunctionTable->SetLastError(ERROR_SUCCESS);
		return FALSE;
	}

	return TRUE;
}
HWND CFunctions::FindWindowFromProcessId(DWORD dwProcessId) {
	EnumData ed = { dwProcessId };
	if (!BetaFunctionTable->EnumWindows(EnumProc, (LPARAM)&ed) &&
		(BetaFunctionTable->GetLastError() == ERROR_SUCCESS)) {
		return ed.hWnd;
	}
	return NULL;
}
bool CFunctions::IsMainWindow(HWND hWnd)
{
	if (BetaFunctionTable->IsWindowVisible(hWnd))
		return BetaFunctionTable->GetWindow(hWnd, GW_OWNER) ? true : false;
	return false;
}


DWORD CFunctions::GetProcessParentProcessId(DWORD dwMainProcessId)
{
	KARMA_MACRO_1
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe = { 0 };
	DWORD dwProcessId = 0;
	pe.dwSize = sizeof(PROCESSENTRY32);

	KARMA_MACRO_2
	hSnapshot = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (BetaFunctionTable->Process32First(hSnapshot, &pe)) {
		do {
			if (pe.th32ProcessID == dwMainProcessId) {
				dwProcessId = pe.th32ParentProcessID;
				break;
			}
		} while (BetaFunctionTable->Process32Next(hSnapshot, &pe));
	}

	BetaFunctionTable->CloseHandle(hSnapshot);
	KARMA_MACRO_2
	return (dwProcessId);
}

DWORD CFunctions::GetProcessIdFromProcessName(const char* c_szProcessName) {
	KARMA_MACRO_1
	HANDLE hSnapshot;
	PROCESSENTRY32 pt;
	pt.dwSize = sizeof(PROCESSENTRY32);

	KARMA_MACRO_2
	hSnapshot = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (BetaFunctionTable->Process32First(hSnapshot, &pt)) {
		do {
			if (!strcmp(pt.szExeFile, c_szProcessName)) {
				BetaFunctionTable->CloseHandle(hSnapshot);
				return pt.th32ProcessID;
			}
		} while (BetaFunctionTable->Process32Next(hSnapshot, &pt));
	}

	BetaFunctionTable->CloseHandle(hSnapshot);
	return 0;
}

std::string CFunctions::GetProcessNameFromProcessId(DWORD dwProcessId) {
	KARMA_MACRO_1
	std::string szResult;
	HANDLE hSnapshot;
	PROCESSENTRY32 pt;
	pt.dwSize = sizeof(PROCESSENTRY32);

	KARMA_MACRO_2
	hSnapshot = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (BetaFunctionTable->Process32First(hSnapshot, &pt)) {
		do {
			if (dwProcessId == pt.th32ProcessID) {
				szResult = pt.szExeFile;
				BetaFunctionTable->CloseHandle(hSnapshot);
				return szResult;
			}
		} while (BetaFunctionTable->Process32Next(hSnapshot, &pt));
	}

	BetaFunctionTable->CloseHandle(hSnapshot);
	return szResult;
}


inline int ProcessIsItAliveWithSnapshot(DWORD dwProcessId)
{
	KARMA_MACRO_1
	HANDLE hSnapshot;
	PROCESSENTRY32 pt;
	pt.dwSize = sizeof(PROCESSENTRY32);

	KARMA_MACRO_2
	hSnapshot = BetaFunctionTable->CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (BetaFunctionTable->Process32First(hSnapshot, &pt)) {
		do {
			if (pt.th32ProcessID == dwProcessId) {
				BetaFunctionTable->CloseHandle(hSnapshot);
				return 1;
			}
		} while (BetaFunctionTable->Process32Next(hSnapshot, &pt));
	}

	BetaFunctionTable->CloseHandle(hSnapshot);
	return 0;
}

inline int ProcessIsItAliveWithHandle(DWORD dwProcessId)
{
	KARMA_MACRO_1
	HANDLE hProcess = BetaFunctionTable->OpenProcess(SYNCHRONIZE, FALSE, dwProcessId);
	int iResult = hProcess ? 1 : 0;
	if (iResult) BetaFunctionTable->CloseHandle(hProcess);
	KARMA_MACRO_1
	return iResult;
	KARMA_MACRO_2
}

int CFunctions::ProcessIsItAlive(DWORD dwProcessId) {
	KARMA_MACRO_2
	return ( ProcessIsItAliveWithSnapshot(dwProcessId) ? ProcessIsItAliveWithHandle(dwProcessId) : 0 );
	KARMA_MACRO_1
}

std::string CFunctions::NtPathToWin32Path(std::string ntPath)
{
	if (boost::starts_with(ntPath, XOR("\\\\?\\"))) {
		ntPath.erase(ntPath.begin(), ntPath.begin() + 4);
		return ntPath;
	}

	if (boost::starts_with(ntPath, XOR("\\??\\")))
		ntPath.erase(ntPath.begin(), ntPath.begin() + 4);
	if (boost::starts_with(ntPath, XOR("\\")))
		ntPath.erase(ntPath.begin(), ntPath.begin() + 1);
	//if (boost::starts_with(ntPath, XOR("\\device\\")))
	//	ntPath.erase(ntPath.begin(), ntPath.begin() + 8);
	if (boost::istarts_with(ntPath, XOR("globalroot\\")))
		ntPath.erase(ntPath.begin(), ntPath.begin() + 11);
	if (boost::istarts_with(ntPath, XOR("systemroot")))
		ntPath.replace(ntPath.begin(), ntPath.begin() + 10, LPDirFunctions->WinPath());
	if (boost::istarts_with(ntPath, XOR("windows")))
		ntPath.replace(ntPath.begin(), ntPath.begin() + 7, LPDirFunctions->WinPath());

	boost::replace_all(ntPath, XOR("\\"), XOR("/"));
	boost::replace_all(ntPath, XOR("system32"), XOR("sysnative"));
	boost::replace_all(ntPath, XOR("syswow64"), XOR("sysnative"));
	return ntPath;
}

std::string CFunctions::FixBuildDate()
{
	char CFixDate[512];
	sprintf(CFixDate, XOR("%s-%s"), __DATE__, __TIME__);

	std::string szFixDate(CFixDate);
	boost::replace_all(szFixDate, XOR(":"), "");
	boost::replace_all(szFixDate, XOR(" "), "");
	return szFixDate;
}

std::string CFunctions::DosDevicePath2LogicalPath(LPCTSTR lpszDosPath)
{
	std::string strResult;
	TCHAR szTemp[MAX_PATH];
	szTemp[0] = '\0';

	if (lpszDosPath == NULL || strlen(lpszDosPath) == NULL || !BetaFunctionTable->GetLogicalDriveStringsA(_countof(szTemp) - 1, szTemp))
		return strResult;

	TCHAR szName[MAX_PATH];
	TCHAR szDrive[3] = TEXT(" :");
	BOOL bFound = FALSE;
	TCHAR* p = szTemp;

	do {
		// Copy the drive letter to the template string
		*szDrive = *p;

		// Look up each device name
		if (QueryDosDeviceA(szDrive, szName, _countof(szName))) {
			UINT uNameLen = (UINT)strlen(szName);

			if (uNameLen < MAX_PATH)
			{
				bFound = strncmp(lpszDosPath, szName, uNameLen) == 0;

				if (bFound) {
					// Reconstruct pszFilename using szTemp
					// Replace device path with DOS path
					TCHAR szTempFile[MAX_PATH];
					sprintf_s(szTempFile, TEXT("%s%s"), szDrive, lpszDosPath + uNameLen);
					strResult = szTempFile;
				}
			}
		}

		// Go to the next NULL character.
		while (*p++);
	} while (!bFound && *p); // end of string

	return strResult;
}

std::string CFunctions::GetProcessFullName(HANDLE hProcess)
{
	CHAR processPath[MAX_PATH];
	if (BetaFunctionTable->GetProcessImageFileNameA(hProcess, processPath, _countof(processPath)))
		return processPath;

	nkt_memset(&processPath, 0, MAX_PATH);
	if (BetaFunctionTable->GetModuleFileNameExA(hProcess, NULL, processPath, _countof(processPath)))
		return processPath;

	return "";
}

std::string CFunctions::GetProcessFileName(DWORD dwPID)
{
	std::string szResult;
	BYTE* mp_Data;
	DWORD mu32_DataSize = 2048;

	while (true)
	{
		mp_Data = (BYTE*)nkt_malloc(mu32_DataSize);
		if (!mp_Data)
			return NULL;

		ULONG u32_Needed = 0;
		NTSTATUS s32_Status = BetaFunctionTable->NtQuerySystemInformation(SystemProcessInformation, mp_Data, mu32_DataSize, &u32_Needed);

		if (s32_Status == STATUS_INFO_LENGTH_MISMATCH) // The buffer was too small
		{
			mu32_DataSize = u32_Needed + 2048;
			nkt_mfree(mp_Data);
			mp_Data = NULL;
			continue;
		}

		SYSTEM_PROCESS_INFORMATION* pk_Proc = (SYSTEM_PROCESS_INFORMATION*)mp_Data;
		while(TRUE) {
			if ((DWORD)pk_Proc->UniqueProcessId == dwPID)
			{
				szResult = WstringToUTF8(pk_Proc->ImageName.Buffer);
				break;
			}

			if (!pk_Proc->NextEntryOffset)
				break;

			pk_Proc = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
		}
	}

	nkt_mfree(mp_Data);
	mp_Data = NULL;
	return szResult;
}

bool CFunctions::IsSysWow64()
{
#ifdef _WIN64
	return false;
#endif
	return ((DWORD)__readfsdword(0xC0) != 0);
}

bool CFunctions::IsX64System()
{
	SYSTEM_INFO SysInfo;
	BetaFunctionTable->GetNativeSystemInfo(&SysInfo);
	return (SysInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL);
}

float CFunctions::GetEntropy(BYTE* byBuffer, DWORD dwLength)
{
	DWORD dwSize = 0;
	long lBuff[0xFF + 1] = { 0 };
	float fTemp, fEntropy = 0;

	for (DWORD i = 0; i < dwLength; i++)
	{
		lBuff[byBuffer[i]]++;
		dwSize++;
	}

	for (DWORD i = 0; i < 256; i++)
	{
		if (lBuff[i])
		{
			fTemp = (float)lBuff[i] / (float)dwSize;
			fEntropy += (-fTemp * log2(fTemp));
		}
	}

	return fEntropy;
}

bool CFunctions::IsPackedProcess(std::string szName)
{
	bool bIsPacked = false;
	HANDLE hFile = BetaFunctionTable->CreateFileA(szName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CFunctions::IsPackedProcess: CreateFileA Error %u", LPWinapi->LastError());
#endif
		return bIsPacked;
	}
	DWORD dwFileLen = BetaFunctionTable->GetFileSize(hFile, NULL);
	if (!dwFileLen || dwFileLen == INVALID_FILE_SIZE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CFunctions::IsPackedProcess: GetFileSize Error %u", LPWinapi->LastError());
#endif
		return bIsPacked;
	}

	BYTE* byImage = new BYTE[dwFileLen];
	if (!byImage) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CFunctions::IsPackedProcess: Image allocation fail!");
#endif
		return bIsPacked;
	}

	DWORD dwReadedBytes;
	BOOL readRet = BetaFunctionTable->ReadFile(hFile, byImage, dwFileLen, &dwReadedBytes, NULL);
	if (!readRet || !dwReadedBytes) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "CFunctions::IsPackedProcess: ReadFile Error %u", LPWinapi->LastError());
#endif
		delete[] byImage;
		return bIsPacked;
	}

	float fEntropy = GetEntropy(byImage, dwFileLen);
	delete[] byImage;
	BetaFunctionTable->CloseHandle(hFile);
	return (fEntropy > 7.5);
}

DWORD CFunctions::FindPattern(DWORD dwAddress, DWORD dwSize, BYTE* lpBytes, int iPatternSize)
{
	DWORD dwNewSize = 0;
	DWORD dwBytes = 0;

	DWORD dwRangeLow = dwAddress ? dwAddress : (DWORD)GetModuleHandle(0);
	DWORD dwRangeHi = dwRangeLow + dwSize;

refreshd:
	dwNewSize = iPatternSize;
	dwBytes = (DWORD)lpBytes;

	while (1) {
		if (dwNewSize == 0)
			return dwRangeLow - iPatternSize;

		if (dwRangeLow == dwRangeHi)
			return 0;

		if (IsBadReadPtr((const void*)dwRangeLow, sizeof(DWORD)))
			return 0;

		if ((*(BYTE*)(dwBytes) == 0xFF) || (*(BYTE*)(dwBytes) == *(BYTE*)(dwRangeLow))) {
			--dwNewSize;
			++dwRangeLow;
			++dwBytes;
		}
		else {
			++dwRangeLow;
			goto refreshd;
		}
	}
	return 0;
}

BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;
	return (*szMask) == NULL;
}

DWORD CFunctions::FindPatternClassic(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask)
{
	__try {
		for (DWORD i = 0; i < dwLen; i++)
			if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
				return (DWORD)(dwAddress + i);
	}
	__except (1) {
	}
	return 0;
}

int CFunctions::GetTextSectionInformation(LPDWORD dwOffset, LPDWORD dwLen)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)BetaModuleTable->hBaseModule;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(BetaModuleTable->hBaseModule + pImageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

	for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (!strcmp(XOR(".text"), (char*)pImageSectionHeader[i].Name))
		{
			*dwOffset = DWORD(BetaModuleTable->hBaseModule + pImageSectionHeader[i].VirtualAddress);
			*dwLen = pImageSectionHeader[i].SizeOfRawData;
			return 1;
		}
	}
	return 0;

#if 0
	HANDLE m_hImgFile = BetaFunctionTable->CreateFileA(LPDirFunctions->ExeNameWithPath().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (m_hImgFile == NULL || m_hImgFile == INVALID_HANDLE_VALUE)
		return -1;

	HANDLE m_hImgMap = BetaFunctionTable->CreateFileMappingA(m_hImgFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (m_hImgMap == NULL || m_hImgMap == INVALID_HANDLE_VALUE)
		return -2;
	(LPTSTR)BetaFunctionTable->MapViewOfFile(m_hImgMap, FILE_MAP_READ, 0, 0, 256);
	LPBYTE m_pImgView = (LPBYTE)BetaFunctionTable->MapViewOfFile(m_hImgMap, FILE_MAP_READ, 0, 0, 0);
	if (m_pImgView == NULL)
		return -3;

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)m_pImgView;
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		return -4;

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(m_pImgView + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE)
		return -5;


	PIMAGE_OPTIONAL_HEADER32 pIOH = (PIMAGE_OPTIONAL_HEADER32)(m_pImgView + pIDH->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));


	*dwOffset = pIOH->ImageBase + pIOH->BaseOfCode;
	*dwLen = pIOH->SizeOfCode;


	BetaFunctionTable->UnmapViewOfFile(m_hImgMap);
	if (m_hImgFile && m_hImgFile != INVALID_HANDLE_VALUE)
		BetaFunctionTable->CloseHandle(m_hImgFile);
#endif
	return 1;
}


DWORD CFunctions::GetProcessIdNative(HANDLE hProcess)
{
	if (!hProcess)
		return 0;

	PROCESS_BASIC_INFORMATION pPBI;
	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pPBI, sizeof(PROCESS_BASIC_INFORMATION), 0)))
		return (DWORD)pPBI.UniqueProcessId;

	return 0;
}

bool CFunctions::IsInModuleRange(HMODULE hModule, DWORD dwAddress)
{
	bool bRet = false;
	MODULEINFO mi;
	if (BetaFunctionTable->GetModuleInformation(NtCurrentProcess, hModule, &mi, sizeof(mi)))
	{
		auto MBase = (DWORD)mi.lpBaseOfDll;
		auto MHi = (DWORD)mi.lpBaseOfDll + mi.SizeOfImage;
		bRet = (dwAddress >= MBase && dwAddress <= MHi);
	}
	return bRet;
}

bool CFunctions::IsInModuleRange(const char* c_szModuleName, DWORD dwAddress)
{
	bool bRet = false;
	MODULEINFO mi;
	if (BetaFunctionTable->GetModuleInformation(NtCurrentProcess, BetaFunctionTable->GetModuleHandleA(c_szModuleName), &mi, sizeof(mi)))
	{
		auto MBase = (DWORD)mi.lpBaseOfDll;
		auto MHi = (DWORD)mi.lpBaseOfDll + mi.SizeOfImage;
		bRet = (dwAddress >= MBase && dwAddress <= MHi);
	}
	return bRet;
}

bool CFunctions::IsInAnticheatModuleRange(DWORD dwAddress)
{
	if (LPData->GetGameCode() == TEST_CONSOLE)
		return true;

	ANTI_MODULE_INFO* selfInfo = { 0 };
	auto pselfInfo = LPData->GetAntiModuleInformations();
	if (!pselfInfo)
		LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");

	selfInfo = (ANTI_MODULE_INFO*)pselfInfo;
	auto antiBase = (DWORD)selfInfo->BaseAddress;
	auto antiHi = (DWORD)selfInfo->BaseAddress + selfInfo->SizeOfImage;

	return (dwAddress >= antiBase && dwAddress <= antiHi);
}

std::string CFunctions::GetAnticheatFilename()
{
	std::string szOutput = "";
	if (LPData->GetGameCode() == TEST_CONSOLE)
		return szOutput;

	ANTI_MODULE_INFO* selfInfo = { 0 };
	auto pselfInfo = LPData->GetAntiModuleInformations();
	if (!pselfInfo)
		LPFunctions->CloseProcess(XOR("Fatal Error! Anticheat can not initialized!!!"), false, "");

	selfInfo = (ANTI_MODULE_INFO*)pselfInfo;
	auto wszOutput = selfInfo->BaseDllName.Buffer;
	szOutput = WstringToUTF8(wszOutput);

	return szOutput;
}

std::string CFunctions::GetFirstArgument(bool bLower)
{
	std::string szOutput = "";
	int iArgCount = 0;
	auto wcArgs = BetaFunctionTable->CommandLineToArgvW(BetaFunctionTable->GetCommandLineW(), &iArgCount);
	if (iArgCount) {
		auto wszArgLaunch = wcArgs[0];
		auto szArgLaunch = LPFunctions->WstringToUTF8(wszArgLaunch);
		if (bLower)
			szOutput = szLower(szArgLaunch);
		else
			szOutput = szArgLaunch;
	}
	return szOutput;
}


void CFunctions::DecryptBuffer(LPBYTE lpBuf, DWORD dwSize, BYTE byKey)
{
	for (DWORD i = 0; i < dwSize; i++)
	{
		lpBuf[i] ^= byKey;
		lpBuf[i] += (BYTE)i;
		lpBuf[i] ^= (BYTE)i + 8;
	}
}

void CFunctions::EncryptBuffer(LPBYTE lpBuf, DWORD dwSize, BYTE byKey)
{
	for (DWORD i = 0; i < dwSize; i++)
	{
		lpBuf[i] ^= (BYTE)i + 8;
		lpBuf[i] -= (BYTE)i;
		lpBuf[i] ^= byKey;
	}
}

