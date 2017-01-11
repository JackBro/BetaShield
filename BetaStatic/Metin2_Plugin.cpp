#include "ProjectMain.h"
#include "Main.h"
#include "Metin2_Plugin.h"
#include "DynamicWinapi.h"
#include "Functions.h"

#include "DirFuncs.h"
#include "Threads.h"
#include "Main.h"
#include "Metin2_Pack_HashList.h"
#include "XOR.h"
#include "CLog.h"
#include "Data.h"


#pragma optimize("", off )
bool bIsInitialized = false;

// TraceError
typedef void(__cdecl* PROTOTYPE_Syserr)(const char* c_szFormat, ...); // Function prototype
PROTOTYPE_Syserr GFUNC_Syserr; // Function wrapper
FARPROC fpSyserrAdr; // Function Pointer Address

// IsExist - CEterPackManager
typedef bool(__cdecl* PROTOTYPE_isExist)(const char* c_szFileName);
PROTOTYPE_isExist GFUNC_isExist;
FARPROC fpIsExistAdr;

// GetName - CPythonPlayer
typedef const char*(__cdecl* PROTOTYPE_GetName)();
PROTOTYPE_GetName GFUNC_GetName;
FARPROC fpGetNameAdr;

// GetPhase - CPythonNetworkStream
typedef std::string(__cdecl* PROTOTYPE_GetPhase)();
PROTOTYPE_GetPhase GFUNC_GetPhase;
FARPROC fpGetPhaseAdr;

// NotifyHack - CPythonNetworkStream
typedef void(__cdecl* PROTOTYPE_SendHack)(const char* c_szMsg);
PROTOTYPE_SendHack GFUNC_SendHack;
FARPROC fpSendHackAdr;

// GetFromPack - GetCRC32 - CEterPackManager
typedef DWORD(__cdecl* PROTOTYPE_GetHashFromMappedFile)(const char* c_szFileName);
PROTOTYPE_GetHashFromMappedFile GFUNC_GetHashFromMappedFile;
FARPROC fpGetHashFromMappedFileAdr;
#pragma optimize("", on )


CPluginMetin2* LPPluginMetin2;
CPluginMetin2::CPluginMetin2()
{
}

CPluginMetin2::~CPluginMetin2()
{
}

bool CPluginMetin2::G_IsInitialized() { return bIsInitialized; }
void CPluginMetin2::G_SetInitialized(bool bType) { bIsInitialized = bType; };


bool IsInitializedTrigger(int iPluginType)
{
	CPluginMetin2 lpPlugin;

	if (!lpPlugin.G_IsInitialized())
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Triggers can not called yet");
#endif
		return false;
	}

	int iResult = 0;
	switch (iPluginType)
	{
		case TRIGGER_SYSERR:
			iResult = fpSyserrAdr ? 1 : 0;
			break;
		case TRIGGER_ETERPACK_ISEXIST:
			iResult = fpIsExistAdr ? 1 : 0;
			break;
		case TRIGGER_PYTHONPLAYER_GETNAME:
			iResult = fpGetNameAdr ? 1 : 0;
			break;
		case TRIGGER_NETWORKSTREAM_GETPHASE:
			iResult = fpGetPhaseAdr ? 1 : 0;
			break;
		case TRIGGER_NETWORKSTREAM_SENDHACK:
			iResult = fpSendHackAdr ? 1 : 0;
			break;
		case TRIGGER_NETWORKSTREAM_GETHASHFROMMAPPEDFILE:
			iResult = fpGetHashFromMappedFileAdr ? 1 : 0;
			break;

		default:
#ifdef _DEBUG
			LPLog->AddLog(0,"Called unknown trigger: %d", iPluginType);
#endif
			break;
	}
	if (iResult) {
		return true; // Trigger %d is ready, iPluginType
	}
	else {
#ifdef _DEBUG
		LPLog->AddLog(0,"Trigger %d can not initialized yet", iPluginType);
#endif
		return false;
	}
	return false;
}

void CPluginMetin2::G_Syserr(const char* c_szFormat, ...) {
	if (IsInitializedTrigger(TRIGGER_SYSERR) == false) return;
	GFUNC_Syserr(c_szFormat);
}
bool CPluginMetin2::G_isExist(const char* c_szFileName) {
	if (IsInitializedTrigger(TRIGGER_ETERPACK_ISEXIST) == false) return false;
	return GFUNC_isExist(c_szFileName);
}
const char* CPluginMetin2::G_GetName() {
	if (IsInitializedTrigger(TRIGGER_PYTHONPLAYER_GETNAME) == false) return "";
	return GFUNC_GetName();
}
std::string CPluginMetin2::G_GetPhase() {
	if (IsInitializedTrigger(TRIGGER_NETWORKSTREAM_GETPHASE) == false) return "";
	return GFUNC_GetPhase();
}
void CPluginMetin2::G_SendHack(const char* c_szMsg) {
	if (IsInitializedTrigger(TRIGGER_NETWORKSTREAM_SENDHACK) == false) return;
	GFUNC_SendHack(c_szMsg);
}
DWORD CPluginMetin2::G_GetMappedFileHash(const char* c_szFileName) {
	if (IsInitializedTrigger(TRIGGER_NETWORKSTREAM_GETHASHFROMMAPPEDFILE) == false) return 0;
	return GFUNC_GetHashFromMappedFile(c_szFileName);
}


bool FunctionIsInGameArea(DWORD dwAddress)
{
#if 0
	DWORD dwBase = 0;
	DWORD dwSize = 0;
	LPFunctions->GetTextSectionInformation(&dwBase, &dwSize);
	//if (LPFunctions->GetTextSectionInformation(&dwBase, &dwSize) != 1)
	//	return true;

	auto dwCodeHi = dwBase + dwSize;
	if (dwAddress >= dwBase && dwAddress <= dwCodeHi)
		return true;
	return false;
#endif
	return true;
}


/* -------------------------------------------------------------------------------------------------- */


void CPluginMetin2::GameFunctionTrigger(DWORD dwCaller, void * lpTarget, int iType)
{
	CFunctions lpFuncs;

#ifdef _DEBUG
	LPLog->AddLog(0,"Game Function Trigger called! Type: %d", iType);
#endif


	if (lpTarget == NULL) {
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger pointer is null, passed!");
#endif
		return;
	}


	if (!G_IsInitialized())
		G_SetInitialized(true);
	

	char szRealWarn[1024];
	CHAR __failwarn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game function initilization failed! Error code: %d
	CHAR __manipulationwarn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'u', 'n', 'c', 't', 'i', 'o', 'n', ' ', 'm', 'a', 'n', 'i', 'p', 'u', 'l', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game function manipulation detected! Error code: %d
	if (iType == TRIGGER_SYSERR)
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger type: Syserr aka. Test");
#endif
		fpSyserrAdr = (FARPROC)lpTarget;
		GFUNC_Syserr = (PROTOTYPE_Syserr)fpSyserrAdr;
		if (!GFUNC_Syserr) {
			sprintf(szRealWarn, __failwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
		if (FunctionIsInGameArea((DWORD)lpTarget) == false) {
			sprintf(szRealWarn, __manipulationwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
	}

	else if (iType == TRIGGER_ETERPACK_ISEXIST)
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger type: CEterPackManager::IsExist");
#endif
		fpIsExistAdr = (FARPROC)lpTarget;
		GFUNC_isExist = (PROTOTYPE_isExist)fpIsExistAdr;
		if (!GFUNC_isExist) {
			sprintf(szRealWarn, __failwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
		if (FunctionIsInGameArea((DWORD)lpTarget) == false) {
			sprintf(szRealWarn, __manipulationwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
	}

	else if (iType == TRIGGER_PYTHONPLAYER_GETNAME)
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger type: CPythonPlayer::GetName");
#endif
		fpGetNameAdr = (FARPROC)lpTarget;
		GFUNC_GetName = (PROTOTYPE_GetName)fpGetNameAdr;
		if (!GFUNC_GetName) {
			sprintf(szRealWarn, __failwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
		if (FunctionIsInGameArea((DWORD)lpTarget) == false) {
			sprintf(szRealWarn, __manipulationwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
	}

	else if (iType == TRIGGER_NETWORKSTREAM_GETPHASE)
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger type: CPythonNetworkStream::GetPhase");
#endif
		fpGetPhaseAdr = (FARPROC)lpTarget;
		GFUNC_GetPhase = (PROTOTYPE_GetPhase)fpGetPhaseAdr;
		if (!GFUNC_GetPhase) {
			sprintf(szRealWarn, __failwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
		if (FunctionIsInGameArea((DWORD)lpTarget) == false) {
			sprintf(szRealWarn, __manipulationwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
	}

	else if (iType == TRIGGER_NETWORKSTREAM_SENDHACK)
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger type: CPythonNetworkStream::SendHack");
#endif
		fpSendHackAdr = (FARPROC)lpTarget;
		GFUNC_SendHack = (PROTOTYPE_SendHack)fpSendHackAdr;
		if (!GFUNC_SendHack) {
			sprintf(szRealWarn, __failwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
		if (FunctionIsInGameArea((DWORD)lpTarget) == false) {
			sprintf(szRealWarn, __manipulationwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}

		// M2bob
		CHAR __bobfile_1[] = { 'c', ':', '\\', 'w', 'a', 'i', 't', '.', 'm', 's', 'a', 0x0 }; // C:\wait.msa
		CHAR __bobfile_2[] = { 'c', ':', '\\','\\', 'w', 'a', 'i', 't', '.', 'm', 's', 'a', 0x0 }; // C:\\wait.msa
		CHAR __bobfile_3[] = { 'c', ':', '\\', 'w', 'a', 'i', 't', '_', '1', '.', 'm', 's', 'a', 0x0 }; // C:\wait_1.msa
		CHAR __bobfile_4[] = { 'c', ':', '\\','\\', 'w', 'a', 'i', 't', '_', '1', '.', 'm', 's', 'a', 0x0 }; // C:\\wait_1.msa
		
		if ((G_isExist(__bobfile_1) || G_isExist(__bobfile_2)) && (G_isExist(__bobfile_3) || G_isExist(__bobfile_4))) {
			CHAR __warn[] = { 'b', '0', 't', ' ', 'd', '3', 't', '3', 'c', 't', '3', 'd', 0x0 }; // b0t d3t3ct3d
			G_SendHack(__warn);
		}
	}

	else if (iType == TRIGGER_NETWORKSTREAM_GETHASHFROMMAPPEDFILE)
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Trigger type: GetHashFromMappedFile");
#endif
		fpGetHashFromMappedFileAdr = (FARPROC)lpTarget;
		GFUNC_GetHashFromMappedFile = (PROTOTYPE_GetHashFromMappedFile)fpGetHashFromMappedFileAdr;
		if (!GFUNC_GetHashFromMappedFile) {
			sprintf(szRealWarn, __failwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}
		if (FunctionIsInGameArea((DWORD)lpTarget) == false) {
			sprintf(szRealWarn, __manipulationwarn, iType);
			LPFunctions->CloseProcess(szRealWarn, false, "");
		}

		LPThreads->InitMetin2PackHashCheck();
	}

	else {
#ifdef _DEBUG
		LPLog->AddLog(0,"Called Unknown Trigger Type!");
#endif
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Triggered Game Function succesfuly saved");
#endif
}

#ifdef _DEBUG
void CPluginMetin2::DumpRealHashes()
{
	int i = 0;
	char szXoredName[1024];
	LPLog->AddLog(0, "File Hash dump event has been started.");

	for (i = 0; strcmp(st_FileHashList_normal[i].c_szFileName, "XXX"); i++)
	{
		sprintf(szXoredName, "XOR('%s')", st_FileHashList_normal[i].c_szFileName);
		const char* c_szCurrentFileName = st_FileHashList_normal[i].c_szFileName;
		bool bIsExist = G_isExist(c_szCurrentFileName);

		DWORD dwHash = G_GetMappedFileHash(c_szCurrentFileName);
		if (dwHash == -1) {
			LPLog->M2HashLog(0, "*** ERROR: File: %s can not readed IsExist: %d!", c_szCurrentFileName, bIsExist);
			continue;
		}

		LPLog->M2HashLog(0, "{ '%s',		0x%x }, // %d", szXoredName, dwHash, i);
	}

	for (i = 0; strcmp(st_FileHashList_map_standart[i].c_szFileName, "XXX"); i++)
	{
		sprintf(szXoredName, "XOR('%s')", st_FileHashList_map_standart[i].c_szFileName);
		const char* c_szCurrentFileName = st_FileHashList_map_standart[i].c_szFileName;
		bool bIsExist = G_isExist(c_szCurrentFileName);

		DWORD dwHash = G_GetMappedFileHash(c_szCurrentFileName);
		if (dwHash == -1) {
			LPLog->M2HashLog(0, "*** ERROR: File: %s can not readed IsExist: %d!", c_szCurrentFileName, bIsExist);
			continue;
		}

		LPLog->M2HashLog(0, "{ '%s',		0x%x }, // %d", szXoredName, dwHash, i);
	}

	LPLog->AddLog(0, "File Hash dump event completed.");
}
#endif

void CPluginMetin2::CheckIngameHashes()
{	
#ifdef _DEBUG
	LPLog->AddLog(0, "Metin2 file hash check routine has been started!");
#endif

	for (int i = 0; strcmp(st_FileHashList_normal[i].c_szFileName, XOR("XXX")); i++)
	{
		const char* c_szCurrentFileName = st_FileHashList_normal[i].c_szFileName;
		DWORD dwCurrentCRC32 = st_FileHashList_normal[i].dwCRC32;
		bool bIsExist = G_isExist(c_szCurrentFileName);


		CHAR __wolfman[] = { 'w', 'o', 'l', 'f', 'm', 'a', 'n', 0x0 }; // wolfman
		if (!bIsExist && strstr(c_szCurrentFileName, __wolfman))
			continue;

		if (!bIsExist) {
			// char cRealWarn[1024];
			// CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'i', 'l', 'e', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 'w', 'i', 't', 'h', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'a', 'd', 'm', 'i', 'n', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game file not found! Please contact with server admin. Error code: %d
			// sprintf(cRealWarn, _warn, i);

			// CFunctions lpFuncs;
#ifndef _DEBUG
			// LPFunctions->CloseProcess(cRealWarn, false, "");
			continue;
#else
			LPLog->AddLog(0,"ERROR! File hash check event failed! Real game hashes now dumping...");
			DumpRealHashes();
			break;
#endif
		}

		DWORD dwRealHash = G_GetMappedFileHash(c_szCurrentFileName);
		if (dwRealHash == -1 && bIsExist) {
			char cRealWarn[1024];
			CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'i', 'l', 'e', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'r', 'e', 'a', 'd', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', ' ', 's', 'o', 'f', 't', 'w', 'a', 'r', 'e', 's', ' ', 'a', 'n', 'd', ' ', 't', 'r', 'y', ' ', 'a', 'g', 'a', 'i', 'n', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game file can not readed! Please disable antivirus softwares and try again. Error code: %d
			sprintf(cRealWarn, _warn, i);

#ifndef _DEBUG
			LPFunctions->CloseProcess(cRealWarn, false, "");
#else
			LPLog->AddLog(0,"ERROR! File hash check event failed! Real game hashes now dumping...");
			DumpRealHashes();
			break;
#endif
		}

		if (dwCurrentCRC32 != dwRealHash) {
			char cRealWarn[1024];
			CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'i', 'l', 'e', ' ', 'm', 'o', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'e', 'i', 'n', 's', 't', 'a', 'l', 'l', ' ', 'g', 'a', 'm', 'e', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game file modification detected! Please reinstall game. Error code: %d
			sprintf(cRealWarn, _warn, i);

#ifndef _DEBUG
			LPFunctions->CloseProcess(cRealWarn, false, "");
#else
			LPLog->AddLog(0,"ERROR! File hash check event failed! Real game hashes now dumping...");
			DumpRealHashes();
			break;
#endif
		}

		// BetaFunctionTable->Sleep(1);
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Metin2 file hash check routine completed!");
#endif
}


void CPluginMetin2::CheckIngameHashes_map()
{
	return; // Appear correct hash-es
	for (int i = 0; strcmp(st_FileHashList_map_standart[i].c_szFileName, XOR("XXX")); i++)
	{
		const char* c_szCurrentFileName = st_FileHashList_map_standart[i].c_szFileName;
		DWORD dwCurrentCRC32 = st_FileHashList_map_standart[i].dwCRC32;
		bool bIsExist = G_isExist(c_szCurrentFileName);

		if (!bIsExist) {
			//char cRealWarn[1024];
			//CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'i', 'l', 'e', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'o', 'n', 't', 'a', 'c', 't', ' ', 'w', 'i', 't', 'h', ' ', 's', 'e', 'r', 'v', 'e', 'r', ' ', 'a', 'd', 'm', 'i', 'n', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game file not found! Please contact with server admin. Error code: %d
			//sprintf(cRealWarn, _warn, i);

#ifndef _DEBUG
			continue;
#else
			LPLog->AddLog(0,"ERROR! File hash check event failed! Real game hashes now dumping...");
			DumpRealHashes();
			break;
#endif
		}

		DWORD dwRealHash = G_GetMappedFileHash(c_szCurrentFileName);
		if (dwRealHash == -1 && bIsExist) {
			char cRealWarn[1024];
			CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'i', 'l', 'e', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'r', 'e', 'a', 'd', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', ' ', 's', 'o', 'f', 't', 'w', 'a', 'r', 'e', 's', ' ', 'a', 'n', 'd', ' ', 't', 'r', 'y', ' ', 'a', 'g', 'a', 'i', 'n', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game file can not readed! Please disable antivirus softwares and try again. Error code: %d
			sprintf(cRealWarn, _warn, i);

#ifndef _DEBUG
			LPFunctions->CloseProcess(cRealWarn, false, "");
#else
			LPLog->AddLog(0,"ERROR! File hash check event failed! Real game hashes now dumping...");
			DumpRealHashes();
			break;
#endif
		}

		if (dwCurrentCRC32 != dwRealHash) {
			char cRealWarn[1024];
			CHAR _warn[] = { 'G', 'a', 'm', 'e', ' ', 'f', 'i', 'l', 'e', ' ', 'm', 'o', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'e', 'i', 'n', 's', 't', 'a', 'l', 'l', ' ', 'g', 'a', 'm', 'e', '.', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Game file modification detected! Please reinstall game. Error code: %d
			sprintf(cRealWarn, _warn, i);

#ifndef _DEBUG
			LPFunctions->CloseProcess(cRealWarn, false, "");
#else
			LPLog->AddLog(0,"ERROR! File hash check event failed! Real game hashes now dumping...");
			DumpRealHashes();
			break;
#endif
		}

		// BetaFunctionTable->Sleep(1);
	}
}


DWORD WINAPI InitializeCheckIngame(LPVOID)
{
	CPluginMetin2 lpPlugin;

	do {
		KARMA_MACRO_1
		BetaFunctionTable->Sleep(2000);
		KARMA_MACRO_2
		lpPlugin.CheckIngameHashes();

#if 0
		KARMA_MACRO_1
		lpPlugin.CheckIngameHashes_map();
#endif

		BetaFunctionTable->Sleep(15000);
	} while (lpPlugin.G_IsInitialized() &&
		IsInitializedTrigger(TRIGGER_ETERPACK_ISEXIST) && IsInitializedTrigger(TRIGGER_NETWORKSTREAM_GETHASHFROMMAPPEDFILE)
	);

	return 0;
}

HANDLE CPluginMetin2::InitCheckIngame()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Metin2 file hash check event thread creation has been started!");
#endif

	KARMA_MACRO_1

	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)InitializeCheckIngame, 0, 11);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '1', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x11! */
		LPFunctions->CloseProcess(__warn, false, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Metin2 file hash check event thread creation completed!");
#endif
	KARMA_MACRO_2

	return hThread;
}

