#include "ProjectMain.h"
#include "Main.h"
#include "File_verification.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "DirFuncs.h"
#include "VersionHelpers.h"
#include "Threads.h"
#include "InternetAPI.h"
#include "CLog.h"
#include "Utils.h"

#include "boost/algorithm/string/split.hpp"
#include "boost/algorithm/string/classification.hpp"
#include "boost/algorithm/string/replace.hpp"

#include "Data.h"
#include "md5.h"
#include "XOR.h"



std::string szIpAddressVeriable;

CFile_Verification* LPFile_Verification;
CFile_Verification::CFile_Verification()
{
}

CFile_Verification::~CFile_Verification()
{
}


void ProcessFileVerificationEvent(const char* c_szReadResult)
{
#ifdef _DEBUG
	LPLog->AddLog(0,"File Verification process event has been started!");
	LPLog->AddLog(0,"File Verification data: %s", c_szReadResult);
#endif

	typedef vector< std::string > pVecReadResult;
	pVecReadResult VecReadResult;
	boost::split(VecReadResult, c_szReadResult, boost::is_any_of(XOR("{$}")), boost::token_compress_on);
	if (VecReadResult.empty())
	{
#ifdef _DEBUG
		LPLog->AddLog(0,"ERROR! File Verification returned string splitted and result is empty!");
#endif
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"File Verification to be checked amount: %d", VecReadResult.size() - 1);
#endif

	for (size_t i = 0; i < VecReadResult.size(); ++i)
	{
		if (strlen(VecReadResult[i].c_str())) { /* If not empty */
			std::string szFile(VecReadResult[i].c_str(), strlen(VecReadResult[i].c_str()));
			boost::replace_all(szFile, "|", "//");

			typedef vector< std::string > pVecFileInfo;
			pVecFileInfo VecFileInfo;
			boost::split(VecFileInfo, szFile, boost::is_any_of(":"), boost::token_compress_on);

			const char* c_szFile = VecFileInfo[0].c_str();
			const char* c_szHash = VecFileInfo[1].c_str();

#ifdef _DEBUG
			LPLog->AddLog(0,"File Verification processing: '%s' - '%s'", c_szFile, c_szHash);
#endif

			if (LPDirFunctions->is_file_exist(c_szFile) == false) {
#ifdef _DEBUG
				LPLog->AddLog(0,"ERROR! File Verification processed file(%s) is not exist!", c_szFile);
#endif
				LPFunctions->CloseProcess(XOR("File: %s can not found!"), false, "");
			}

#ifdef _DEBUG
			MD5 md5;
			char* c_szCorrectHash = md5.digestFile((char*)c_szFile);
			LPLog->AddLog(0,"File: %s Correct Hash: %s Remote Hash: %s IsCorrect Hash: %d Order: %d/%d", c_szFile, c_szCorrectHash, c_szHash, !strcmp(c_szHash, c_szCorrectHash), i + 1, VecReadResult.size() - 1);
#endif
			LPDirFunctions->CheckFileMd5((char*)c_szFile, c_szHash);
		}
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"File Verification process event completed!");
#endif

	BetaFunctionTable->ExitThread(EXIT_SUCCESS);
}

void CheckFileVerificationEx()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"File Verification event has been started!");
#endif
	KARMA_MACRO_1

#ifndef _DEBUG
	/* Crashreport */
	CHAR __localhost[] = { '1', '2', '7', '.', '0', '.', '0', '.', '1', 0x0 };
	if (!strcmp(szIpAddressVeriable.c_str(), __localhost))
	 	return;
#endif

	CHAR __web_adr[] = { 'h', 't', 't', 'p', ':', '/', '/', 'w', 'w', 'w', '.', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', '/', 'f', 'i', 'l', 'e', 's', '_', 'a', 'p', 'i', '.', 'p', 'h', 'p', '?', 'i', 'p', '=', '%', 's', 0x0 }; // http://www.betashield.org/files_api.php?ip=%s
	char cWebAddress[1024];
	sprintf(cWebAddress, __web_adr, szIpAddressVeriable.c_str());

	CHAR __666[] = { '6', '6', '6', 0x0 }; // 666
	size_t szSize = 0;
	std::string szReadResult;
	do {
		szReadResult = LPInternetAPI->ReadUrl(cWebAddress, &szSize);
		BetaFunctionTable->Sleep(5000);
	} while (!strcmp(szReadResult.c_str(), __666));

	if (szReadResult.empty())
		return;


	CHAR __CONN_FAIL[] = { 'C', 'O', 'N', 'N', '_', 'F', 'A', 'I', 'L', 0x0 }; // CONN_FAIL
	CHAR __NO_FILES[] = { 'N', 'O', '_', 'F', 'I', 'L', 'E', 'S', 0x0 }; // NO_FILES

	KARMA_MACRO_1																																																																																										  // Stat Check
	if (!strcmp(szReadResult.c_str(), __CONN_FAIL)) {
#ifdef _DEBUG
		LPLog->AddLog(0,"Web result returned as CONN_FAIL!");
#endif
		return;
	}
	else if (!strcmp(szReadResult.c_str(), __NO_FILES)) {
#ifdef _DEBUG
		LPLog->AddLog(0,"Web result returned as NO_FILES!");
#endif
		return;
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"File Verification event completed!");
#endif

	ProcessFileVerificationEvent(szReadResult.c_str());

	KARMA_MACRO_2
}


void CFile_Verification::CheckFileVerification(const char* c_szIpAddress)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "File Verification thread creation has been started!");
#endif

	KARMA_MACRO_2
	szIpAddressVeriable = c_szIpAddress;
	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)CheckFileVerificationEx, 0, 14);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '1', '4', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x14! */
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "File Verification thread creation completed!");
#endif
}
