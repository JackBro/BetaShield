#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "Data.h"
#include "CLog.h"
#include "VersionHelpers.h"
#include "DirFuncs.h"


inline BOOL IsLegitCatalog(LPCWSTR c_wszFile)
{
	/// UNIMPLEMENTED
	// TODO: Check with catalog name std::wcout << file << L" is signed by the catalog " << catalogInf.wszCatalogFile << L'\n';
	return TRUE;
}


inline BOOL GetHash(LPCWSTR c_wszFile, std::vector<BYTE>& hash)
{
	DWORD hashLen = 0;
	BOOL hashed = FALSE;
	HANDLE hFile = nullptr;

	__try
	{
		hFile = BetaFunctionTable->CreateFileW(c_wszFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "GetHash CreateFileW fail: %u File: %ls", GetLastError(), c_wszFile);
#endif
			return hashed;
		}

		if (BetaFunctionTable->CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, NULL, 0) == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "GetHash CryptCATAdminCalcHashFromFileHandle fail: %u File: %ls", GetLastError(), c_wszFile);
#endif
			BetaFunctionTable->CloseHandle(hFile);
			return hashed;
		}
		hash.resize(hashLen);
		if (!(hashed = BetaFunctionTable->CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, &hash[0], 0)))
			hash.resize(0);

		BetaFunctionTable->CloseHandle(hFile);
	}
	__except (1)
	{
		if (hFile)
			BetaFunctionTable->CloseHandle(hFile);
		return TRUE;
	}

	return hashed;
}

__forceinline BOOL IsSignedFileEx(LPCWSTR c_wszFile)
{
	if (LPData->DynamicAPIsIsInitialized() == false)
		return TRUE;

	if (LPDirFunctions->is_file_exist(LPFunctions->WstringToUTF8(c_wszFile)) == false) {
#ifdef _DEBUG
		LPLog->AddLog(0, "IsSignedFileEx: Triggered string is not a file: %ls | passed...", c_wszFile);
#endif
		return TRUE;
	}

	if (IsWindowsVistaOrGreater() == false && LPDirFunctions->IsFromWindowsPath(LPFunctions->wszLower(c_wszFile)) == true) {
#ifdef _DEBUG
		LPLog->AddLog(0, "IsSignedFileEx skipped on this os and file is from windows path: %ls", c_wszFile);
#endif
		return TRUE;
	}

	HCATADMIN hAdmin = NULL;
	if (BetaFunctionTable->CryptCATAdminAcquireContext(&hAdmin, NULL, NULL) == FALSE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsSignedFileEx CryptCATAdminAcquireContext fail: %u File: %ls", GetLastError(), c_wszFile);
#endif
		return FALSE;
	}

	std::vector<BYTE> hash;
	if (GetHash(c_wszFile, hash) == FALSE) {
#ifdef _DEBUG
		LPLog->AddLog(0, "GetHash returned as false!");
#endif
		return FALSE;
	}

	HCATINFO hPrev = NULL;
	HCATINFO hRes = BetaFunctionTable->CryptCATAdminEnumCatalogFromHash(hAdmin, &hash[0], hash.size(), 0, &hPrev);
	if (!hRes) {
#ifdef _DEBUG
		LPLog->AddLog(-1, "IsSignedFileEx CryptCATAdminEnumCatalogFromHash fail: %u File: %ls", GetLastError(), c_wszFile);
#endif
		BetaFunctionTable->CryptCATAdminReleaseContext(hAdmin, 0);
		return FALSE;
	}

	CATALOG_INFO catalogInf = { sizeof(catalogInf), 0 };
	if (BetaFunctionTable->CryptCATCatalogInfoFromContext(hRes, &catalogInf, 0) == FALSE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsSignedFileEx CryptCATCatalogInfoFromContext fail: %u File: %ls", GetLastError(), c_wszFile);
#endif
		BetaFunctionTable->CryptCATAdminReleaseContext(hAdmin, 0);
		return FALSE;
	}

	BOOL bCheckCatalog = IsLegitCatalog(catalogInf.wszCatalogFile);
	BetaFunctionTable->CryptCATAdminReleaseContext(hAdmin, 0);
	return bCheckCatalog;
}


std::mutex m;
void CScan::IsSignedFile(LPCWSTR c_wszFile, PBOOL bRet)
{
	__try {
		m.lock();
		 BOOL bNewRet = IsSignedFileEx(c_wszFile);
		*bRet = bNewRet;
		m.unlock();
	}
	__except (1) {
#ifdef _DEBUG
		LPLog->AddLog(-1, "Exception triggered on CScan::IsSignedFile: %ls\nException code: %u - Last error: %u", c_wszFile, GetExceptionCode(), GetLastError());
#endif
		*bRet = TRUE;
	}
}

