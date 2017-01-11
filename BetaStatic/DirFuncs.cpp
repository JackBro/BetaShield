#include "ProjectMain.h"
#include "dirent.h"
#include "CRC32.h"
#include "DirFuncs.h"
#include "DynamicWinapi.h"
#include "Functions.h"

#include "Threads.h"
#include "md5.h"
#include <boost/algorithm/string/predicate.hpp>
#include "CLog.h"


CDirFunctions* LPDirFunctions;
CDirFunctions::CDirFunctions()
{
}

CDirFunctions::~CDirFunctions()
{
}


inline bool CDirFunctions::is_file_exist(const std::string& szName) {
	KARMA_MACRO_2;
	struct stat buffer;
	auto method1 = (stat(szName.c_str(), &buffer) == 0);
	if (!method1) {
		DWORD dwAttrib =BetaFunctionTable->GetFileAttributesA(szName.c_str());
		return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}
	return method1;
}

std::string CDirFunctions::readFile(const std::string& filename) {
	KARMA_MACRO_2;
	ifstream in(filename.c_str(), ios_base::binary);
	in.exceptions(ios_base::badbit | ios_base::failbit | ios_base::eofbit);
	KARMA_MACRO_1;
	return std::string(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
}

void CDirFunctions::writeFile(char* filename, char* text){
	KARMA_MACRO_1;
	std::ofstream f(filename, std::ofstream::out | std::ofstream::app);
	f << text << std::endl;
	f.close();
	KARMA_MACRO_2;
}

bool CDirFunctions::dirExist(const std::string& dirName_in)
{
	KARMA_MACRO_1;
	DWORD ftyp = BetaFunctionTable->GetFileAttributesA(dirName_in.c_str());
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;

	return false;
}

int CDirFunctions::DeleteDirectory(const std::string &refcstrRootDirectory, bool bDeleteSubdirectories)
{
	KARMA_MACRO_1
	bool            bSubdirectory = false;       // Flag, indicating whether
	// subdirectories have been found
	HANDLE          hFile;                       // Handle to directory
	std::string     strFilePath;                 // Filepath
	std::string     strPattern;                  // Pattern
	WIN32_FIND_DATA FileInformation;             // File information
	KARMA_MACRO_2

	strPattern = refcstrRootDirectory + "\\*.*"; // todo: array
	hFile = ::BetaFunctionTable->FindFirstFileA(strPattern.c_str(), &FileInformation);
	KARMA_MACRO_2
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (FileInformation.cFileName[0] != '.')
			{
				strFilePath.erase();
				strFilePath = refcstrRootDirectory + "\\" + FileInformation.cFileName; // todo: array

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (bDeleteSubdirectories)
					{
						// Delete subdirectory
						int iRC = DeleteDirectory(strFilePath, bDeleteSubdirectories);
						if (iRC)
							return iRC;
					}
					else
						bSubdirectory = true;
				}
				else
				{
					// Set file attributes
					if (::BetaFunctionTable->SetFileAttributesA(strFilePath.c_str(),
						FILE_ATTRIBUTE_NORMAL) == FALSE)
						return ::BetaFunctionTable->GetLastError();

					// Delete file
					if (::BetaFunctionTable->DeleteFileA(strFilePath.c_str()) == FALSE)
						return ::BetaFunctionTable->GetLastError();
				}
			}
		} while (::BetaFunctionTable->FindNextFileA(hFile, &FileInformation) == TRUE);

		// Close handle
		::BetaFunctionTable->FindClose(hFile);

		DWORD dwError = ::BetaFunctionTable->GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return dwError;
		else
		{
			if (!bSubdirectory)
			{
				// Set directory attributes
				if (::BetaFunctionTable->SetFileAttributesA(refcstrRootDirectory.c_str(),
					FILE_ATTRIBUTE_NORMAL) == FALSE)
					return ::BetaFunctionTable->GetLastError();

				// Delete directory
				if (::BetaFunctionTable->RemoveDirectoryA(refcstrRootDirectory.c_str()) == FALSE)
					return ::BetaFunctionTable->GetLastError();
			}
		}
	}
	KARMA_MACRO_1
	return 0;
}

HANDLE CDirFunctions::CreateTempFile(std::string * pszName)
{
	TCHAR lpTempPathBuffer[MAX_PATH];
	DWORD dwRetVal = BetaFunctionTable->GetTempPathA(MAX_PATH, lpTempPathBuffer);
	if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		return 0;

	TCHAR szTempFileName[MAX_PATH];
	CHAR __bst[] = { 'b', 's', 't', 0x0 }; // bst
	UINT uRetVal = BetaFunctionTable->GetTempFileNameA(lpTempPathBuffer, __bst, 0, szTempFileName);
	if (uRetVal == 0)
		return 0;

	HANDLE hTempFile = BetaFunctionTable->CreateFileA(szTempFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTempFile == INVALID_HANDLE_VALUE)
		return 0;

	*pszName = szTempFileName;
	return hTempFile;
}

std::string CDirFunctions::WinPath() {
	KARMA_MACRO_1;
	char buffer[MAX_PATH];
	BetaFunctionTable->GetWindowsDirectoryA(buffer, MAX_PATH);
	KARMA_MACRO_2;
	return buffer;
}

std::string CDirFunctions::ExeName() {
	KARMA_MACRO_1;
	std::string szExeNameWithPath = ExeNameWithPath();
	std::string szExeNameWithoutPath = GetNameFromPath(szExeNameWithPath);
	KARMA_MACRO_2;
	return szExeNameWithoutPath;
}

std::string CDirFunctions::ExePath() {
	KARMA_MACRO_2;
	char buffer[MAX_PATH];
	BetaFunctionTable->GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");// todo: array
	KARMA_MACRO_1;
	return std::string(buffer).substr(0, pos);
}

std::string CDirFunctions::ExeNameWithPath(){
	KARMA_MACRO_1
	char buffer[MAX_PATH];
	BetaFunctionTable->GetModuleFileNameA(NULL, buffer, MAX_PATH);
	KARMA_MACRO_2
	return std::string(buffer);
}

bool CDirFunctions::IsBetaBox(std::string szThis)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "IsBetaBox started! Str: %s", szThis.empty() ? "NULL" : szThis.c_str());
#endif
	if (szThis.empty())
		return false;

	auto szLowerThis = LPFunctions->szLower(szThis);
	if (IsFromCurrentPath(szLowerThis) == true)
	{
		auto szExePath = ExePath();
		auto szLowerExePath = LPFunctions->szLower(ExePath());

		//CHAR __p1[] = { '/', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '/', 'b', 'e', 't', 'a', 'b', 'o', 'x', '.', 'e', 'x', 'e', 0x0 }; // /betashield/betabox.exe
		//auto szBox1 = szLowerExePath + __p1;
		//CHAR __p2[] = { '\\', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '\\', 'b', 'e', 't', 'a', 'b', 'o', 'x', '.', 'e', 'x', 'e', 0x0 }; // \betashield\betabox.exe
		//auto szBox2 = szLowerExePath + __p2;
		CHAR __p3[] = { '\\', 'b', 'e', 't', 'a', 'b', 'o', 'x', '.', 'e', 'x', 'e', 0x0 }; // \betabox.exe
		auto szBox3 = szLowerExePath + __p3;
		CHAR __p4[] = { '/', 'b', 'e', 't', 'a', 'b', 'o', 'x', '.', 'e', 'x', 'e', 0x0 }; // /betabox.exe
		auto szBox4 = szLowerExePath + __p4;

		//LPLog->AddLog(0, "P1: %s P2: %s P3: %s P4: %s Box: %s", 
		//	szBox1.c_str(), szBox2.c_str(), szBox3.c_str(), szBox4.c_str(), szLowerThis.c_str());

		if ( /*szBox1 == szLowerThis || szBox2 == szLowerThis || */ szBox3 == szLowerThis || szBox4 == szLowerThis)
			return true;
	}
	return false;
}

bool CDirFunctions::IsFromWindowsPath(std::string szPath)
{
	std::string szLowerWinPath = WinPath();
	transform(szLowerWinPath.begin(), szLowerWinPath.end(), szLowerWinPath.begin(), tolower);

	if (szPath.find(szLowerWinPath) != std::string::npos)
		return true;
	return false;
}

bool CDirFunctions::IsFromWindowsPath(std::wstring wszPath)
{
	CFunctions lpFuncs;
	std::string szPath = lpFuncs.WstringToUTF8(wszPath);
	return IsFromWindowsPath(szPath);
}

bool CDirFunctions::IsFromWindowsPath(const char* c_szPath)
{
	std::string szPath = c_szPath;
	return IsFromWindowsPath(szPath);
}

bool CDirFunctions::IsFromWindowsPath(const wchar_t* c_wszPath)
{
	std::wstring wszPath = c_wszPath;
	return IsFromWindowsPath(wszPath);
}


bool CDirFunctions::IsFromCurrentPath(std::string szPath)
{
	std::string szLowerExePath = ExePath();
	transform(szLowerExePath.begin(), szLowerExePath.end(), szLowerExePath.begin(), tolower);

	if (szPath.find(szLowerExePath) != std::string::npos)
		return true;
	return false;
}

bool CDirFunctions::IsFromCurrentPath(std::wstring wszPath)
{
	CFunctions lpFuncs;
	std::string szPath = lpFuncs.WstringToUTF8(wszPath);
	return IsFromCurrentPath(szPath);
}

bool CDirFunctions::IsFromCurrentPath(const char* c_szPath)
{
	std::string szPath = c_szPath;
	return IsFromCurrentPath(szPath);
}

bool CDirFunctions::IsFromCurrentPath(const wchar_t* c_wszPath)
{
	std::wstring wszPath = c_wszPath;
	return IsFromCurrentPath(wszPath);
}

std::string CDirFunctions::GetNameFromPath(std::string __szFileName)
{
	std::string szFileName = __szFileName;
	int iLastSlash = szFileName.find_last_of("\\/"); // TODO: Array
	szFileName = szFileName.substr(iLastSlash + 1, szFileName.length() - iLastSlash);
	return szFileName;
}

std::wstring CDirFunctions::GetNameFromPath(std::wstring __wszFileName)
{
	std::wstring wszFileName = __wszFileName;
	int iLastSlash = wszFileName.find_last_of(L"\\/"); // TODO: Array
	wszFileName = wszFileName.substr(iLastSlash + 1, wszFileName.length() - iLastSlash);
	return wszFileName;
}


__forceinline bool IsTrueExtensionForMiles(const char* c_szFileName) {
	CHAR __mss32[] = { 'm', 's', 's', '3', '2', '.', 'd', 'l', 'l', 0x0 }; //mss32.dll
	CHAR __mix[] = { '.', 'm', 'i', 'x', 0x0 }; //".mix"
	CHAR __asi[] = { '.', 'a', 's', 'i', 0x0 }; //".asi"
	CHAR __m3d[] = { '.', 'm', '3', 'd', 0x0 }; //".m3d"
	CHAR __flt[] = { '.', 'f', 'l', 't', 0x0 }; //".flt"

	return strstr(c_szFileName, __mss32) || strstr(c_szFileName, __mix) || strstr(c_szFileName, __asi) || strstr(c_szFileName, __m3d) || strstr(c_szFileName, __flt);
}

int CDirFunctions::GetDirFileCount(std::string szDir)
{
	KARMA_MACRO_1;
	struct dirent *de;
	const char* my_Dir = szDir.c_str();

	KARMA_MACRO_2;
	DIR *dir = opendir(my_Dir);
	if (!dir)
		return -1; // Probably dir is not exist

	KARMA_MACRO_1;
	int count = 0;
	while (de = readdir(dir)) {
		if (IsTrueExtensionForMiles(de->d_name)) {
			++count;
		}
	}

	KARMA_MACRO_2;
	closedir(dir);

	return count;
}

void CDirFunctions::MilesCountCheck()
{
	KARMA_MACRO_1
	CHAR __miles[] = { '\\', '\\', 'm', 'i', 'l', 'e', 's', '\\', '\\', 0x0 }; // "\\miles\\"
	int milessay = GetDirFileCount(ExePath() + __miles);
	if (milessay == -1)
		return;
	
	KARMA_MACRO_2
	if (milessay != 10)
	{
		/*
		if (milessay < 10)
		{
			CHAR __Missingfile[] = { 'M', 'i', 's', 's', 'i', 'n', 'g', ' ', 'f', 'i', 'l', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'M', 'I', 'L', 'E', 'S', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ',', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'u', 'n', ' ', 'a', 'u', 't', 'o', 'p', 'a', 't', 'c', 'h', 'e', 'r', '.', 0x0 }; // Missing file detected in MILES folder, Please run autopatcher.
			LPFunctions->CloseProcess(__Missingfile, false, "");
		}
		*/
		if (milessay > 10)
		{
			CHAR __Toomuchfile[] = { 'T', 'o', 'o', ' ', 'm', 'u', 'c', 'h', ' ', 'f', 'i', 'l', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'M', 'I', 'L', 'E', 'S', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ',', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'r', ' ', 'y', 'o', 'u', 'r', ' ', 'm', 'i', 'l', 'e', 's', ' ', 'f', 'o', 'l', 'd', 'e', 'r', '.', 0x0 }; // Too much file detected in MILES folder, Please clear your miles folder.
			LPFunctions->CloseProcess(__Toomuchfile, false, "");
		}
	}
	KARMA_MACRO_1
}


void CDirFunctions::CheckDirectory(string Directory)
{
	CFunctions lpFuncs;

	KARMA_MACRO_2;
	const string hedef = Directory;
	if (Directory.length() == 0)
		Directory = "*";
	else
		Directory = Directory + "\\*";

	KARMA_MACRO_1;

	WIN32_FIND_DATAA FindData;
	HANDLE Find = BetaFunctionTable->FindFirstFileA(Directory.c_str(), &FindData);

	KARMA_MACRO_2;

	int py = 0;
	int m3d = 0;
	int asi = 0;
	int flt = 0;
	int mix = 0;

	KARMA_MACRO_1

	// text list 
	CHAR __miles[] = { 'm', 'i', 'l', 'e', 's', 0x0 }; //__miles

	CHAR __logininfo[] = { 'l', 'o', 'g', 'i', 'n', 'i', 'n', 'f', 'o', '.', 'p', 'y', 0x0 }; //"logininfo.py"
	CHAR __mssa3d[] = { 'm', 's', 's', 'a', '3', 'd', '.', 'm', '3', 'd', 0x0 }; //"mssa3d.m3d"
	CHAR __mssds3d[] = { 'm', 's', 's', 'd', 's', '3', 'd', '.', 'm', '3', 'd', 0x0 }; //"mssds3d.m3d"
	CHAR __mssdx7[] = { 'm', 's', 's', 'd', 'x', '7', '.', 'm', '3', 'd', 0x0 }; //"mssdx7.m3d"
	CHAR __msseax[] = { 'm', 's', 's', 'e', 'a', 'x', '.', 'm', '3', 'd', 0x0 }; //"msseax.m3d"
	CHAR __mssrsx[] = { 'm', 's', 's', 'r', 's', 'x', '.', 'm', '3', 'd', 0x0 }; //"mssrsx.m3d"
	CHAR __msssoft[] = { 'm', 's', 's', 's', 'o', 'f', 't', '.', 'm', '3', 'd', 0x0 }; //"msssoft.m3d"
	CHAR __mssmp3[] = { 'm', 's', 's', 'm', 'p', '3', '.', 'a', 's', 'i', 0x0 }; //"mssmp3.asi"
	CHAR __mssvoice[] = { 'm', 's', 's', 'v', 'o', 'i', 'c', 'e', '.', 'a', 's', 'i', 0x0 }; //"mssvoice.asi"
	CHAR __mssdsp[] = { 'm', 's', 's', 'd', 's', 'p', '.', 'f', 'l', 't', 0x0 }; //"mssdsp.flt"

	CHAR __py[] = { '.', 'p', 'y', 0x0 }; //".py"
	CHAR __mix[] = { '.', 'm', 'i', 'x', 0x0 }; //".mix"
	CHAR __asi[] = { '.', 'a', 's', 'i', 0x0 }; //".asi"
	CHAR __m3d[] = { '.', 'm', '3', 'd', 0x0 }; //".m3d"
	CHAR __flt[] = { '.', 'f', 'l', 't', 0x0 }; //".flt"

	KARMA_MACRO_2

	if (hedef == __miles) {
		while (BetaFunctionTable->FindNextFileA(Find, &FindData) != 0) {
			if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				if (lpFuncs.szLower(FindData.cFileName).compare(__logininfo) == 0) { py = 1; break; }
				if (lpFuncs.szLower(FindData.cFileName).compare(__mssa3d) != 0 && \
					lpFuncs.szLower(FindData.cFileName).compare(__mssds3d) != 0 && \
					lpFuncs.szLower(FindData.cFileName).compare(__mssdx7) != 0 && \
					lpFuncs.szLower(FindData.cFileName).compare(__msseax) != 0 && \
					lpFuncs.szLower(FindData.cFileName).compare(__mssrsx) != 0 && \
					lpFuncs.szLower(FindData.cFileName).compare(__msssoft) != 0) {
					if (lpFuncs.szLower(FindData.cFileName).find(__m3d) != string::npos) { m3d = 1; break; }
				}
				if (lpFuncs.szLower(FindData.cFileName).compare(__mssmp3) != 0 && \
					lpFuncs.szLower(FindData.cFileName).compare(__mssvoice)) {
					if (lpFuncs.szLower(FindData.cFileName).find(__asi) != string::npos) { asi = 1; break; }
				}
				if (lpFuncs.szLower(FindData.cFileName).compare(__mssdsp)) {
					if (lpFuncs.szLower(FindData.cFileName).find(__flt) != string::npos) { flt = 1; break; }
				}
				if (lpFuncs.szLower(FindData.cFileName).find(__mix) != string::npos) { mix = 1; break; }
			}
		}
	}
	else {
		while (BetaFunctionTable->FindNextFileA(Find, &FindData) != 0) {
			if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				if (lpFuncs.szLower(FindData.cFileName).find(__m3d) != string::npos) { m3d = 1; break; }
				if (lpFuncs.szLower(FindData.cFileName).find(__asi) != string::npos) { asi = 1; break; }
				if (lpFuncs.szLower(FindData.cFileName).find(__flt) != string::npos) { flt = 1; break; }
				if (lpFuncs.szLower(FindData.cFileName).find(__mix) != string::npos) { mix = 1; break; }
				if (lpFuncs.szLower(FindData.cFileName).find(__py) != string::npos) { py = 1; break; }
			}
		}
	}

	KARMA_MACRO_1;

	if (!(py == 0 && m3d == 0 && asi == 0 && flt == 0 && mix == 0)) {
		string is;
		if (py == 1) is = __py;
		if (m3d == 1) is = __m3d;
		if (asi == 1) is = __asi;
		if (flt == 1) is = __flt;
		if (mix == 1) is = __mix;

		std::string szDetectedFile = Directory + is;
		CHAR __Badfiledetected[] = { 'B', 'a', 'd', ' ', 'f', 'i', 'l', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'e', 'm', 'o', 'v', 'e', ':', ' ', '%', 's', 0x0 }; // Bad file detected in game folder. Please remove: %s
		char tmpBuf[500];
		sprintf(tmpBuf, __Badfiledetected, szDetectedFile.c_str());

		lpFuncs.CloseProcess(tmpBuf, false, "");
	}
	KARMA_MACRO_2;
}

void CDirFunctions::MainFolderCheck()
{
	CFunctions lpFuncs;
	KARMA_MACRO_1

	CHAR __logininfo1[] = { 'l', 'o', 'g', 'i', 'n', 'i', 'n', 'f', 'o', '.', 'p', 'y', 0x0 }; //"logininfo.py"
	CHAR __logininfo2[] = { 'l', 'o', 'g', 'i', 'n', 'I', 'n', 'f', 'o', '.', 'p', 'y', 0x0 }; //"loginInfo.py"
	KARMA_MACRO_2
	CHAR __d3d8thkdef[] = { 'd', '3', 'd', '8', 't', 'h', 'k', '.', 'd', 'e', 'f', 0x0 }; // d3d8thk.def
	CHAR __d3d8thk64def[] = { 'd', '3', 'd', '8', 't', 'h', 'k', '6', '4', '.', 'd', 'e', 'f', 0x0 }; // d3d8thk64.def
	KARMA_MACRO_2

	if (is_file_exist(__logininfo1) || is_file_exist(__logininfo2)){
		CHAR __Logininfoinjection[] = { 'L', 'o', 'g', 'i', 'n', 'i', 'n', 'f', 'o', ' ', 'i', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // Logininfo injection detected.
		lpFuncs.CloseProcess(__Logininfoinjection, false, "");
	}

	KARMA_MACRO_1

	if (is_file_exist(__d3d8thkdef) || is_file_exist(__d3d8thk64def)) {
		CHAR __d3d8thkdefwarn[] = { 'U', 'n', 'a', 'l', 'l', 'o', 'w', 'e', 'd', ' ', 'f', 'i', 'l', 'e', ' ', 'd', '3', 'd', '8', 't', 'h', 'k', '.', 'd', 'e', 'f', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // Unallowed file d3d8thk.def detected!
		lpFuncs.CloseProcess(__d3d8thkdefwarn, false, "");
	}

	KARMA_MACRO_1
}

void CDirFunctions::PackCheck()
{
	CFunctions lpFuncs;
	KARMA_MACRO_1;

	CHAR __antiflydmg[] = { '\\', '\\', 'p', 'a', 'c', 'k', '\\', '\\', 'a', 'n', 't', 'i', 'f', 'l', 'y', 'd', 'm', 'g', '.', 'e', 'p', 'k', 0x0 }; // "\\pack\\antiflydmg.epk"
	CHAR __waitdmg[] = { '\\', '\\', 'p', 'a', 'c', 'k', '\\', '\\', 'w', 'a', 'i', 't', 'd', 'm', 'g', '.', 'e', 'p', 'k', 0x0 }; // "\\pack\\waitdmg.epk"
	CHAR __antifly[] = { '\\', '\\', 'p', 'a', 'c', 'k', '\\', '\\', 'a', 'n', 't', 'i', 'f', 'l', 'y', '.', 'e', 'p', 'k', 0x0 }; // "\\pack\\antifly.epk"
	CHAR __ymirpc[] = { 'd', ':', '\\', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', '\\', 'p', 'c', 0x0 }; // "d:\\ymir work\\pc"
	CHAR __ymirpc_2[] = { 'd', ':', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', 'p', 'c', 0x0 }; // "d:\\ymir work\\pc"
	CHAR __ymirpc2[] = { 'd', ':', '\\', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', '\\', 'p', 'c', '2', 0x0 }; // "d:\\ymir work\\pc2"
	CHAR __ymirpc2_2[] = { 'd', ':', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', 'p', 'c', '2', 0x0 }; // "d:\\ymir work\\pc2"
	CHAR __ymirpc3[] = { 'd', ':', '\\', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', '\\', 'p', 'c', '3', 0x0 }; // "d:\\ymir work\\pc3"
	CHAR __ymirpc3_2[] = { 'd', ':', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', 'p', 'c', '3', 0x0 }; // "d:\\ymir work\\pc3"
	CHAR __ymirmonster[] = { 'd', ':', '\\', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', '\\', 'm', 'o', 'n', 's', 't', 'e', 'r', 0x0 }; // d:/ymir work/monster
	CHAR __ymirmonster_2[] = { 'd', ':', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', 'm', 'o', 'n', 's', 't', 'e', 'r', 0x0 }; // d:/ymir work/monster
	CHAR __ymirmonster2[] = { 'd', ':', '\\', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', '\\', 'm', 'o', 'n', 's', 't', 'e', 'r', '2', 0x0 }; // d:/ymir work/monster2
	CHAR __ymirmonster2_2[] = { 'd', ':', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '\\', 'm', 'o', 'n', 's', 't', 'e', 'r', '2', 0x0 }; // d:/ymir work/monster2
	CHAR __ymir[] = { '\\', '\\', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', 0x0 }; // "\\ymir work"
	CHAR __pc[] = { '\\', '\\', 'p', 'c', 0x0 }; // "\\pc"
	CHAR __pc2[] = { '\\', '\\', 'p', 'c', '2', 0x0 }; // "\\pc2"
	CHAR __pc3[] = { '\\', '\\', 'p', 'c', '3', 0x0 }; // "\\pc3"

	KARMA_MACRO_2

	CHAR __Antiflydmg_warn[] = { 'A', 'n', 't', 'i', 'f', 'l', 'y', ' ', 'D', 'a', 'm', 'a', 'g', 'e', ' ', 'H', 'a', 'c', 'k', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // Antifly Damage Hack detected.
	CHAR __WaitDamage_warn[] = { 'W', 'a', 'i', 't', ' ', 'D', 'a', 'm', 'a', 'g', 'e', ' ', 'H', 'a', 'c', 'k', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // Wait Damage Hack detected.
	CHAR __Antifly_warn[] = { 'A', 'n', 't', 'i', 'f', 'l', 'y', ' ', 'H', 'a', 'c', 'k', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // Antifly Hack detected.
	CHAR __ymirworkpc_warn[] = { 'D', ':', '/', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '/', 'p', 'c', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // D:/ymir work/pc illegal folder detected.
	CHAR __ymirworkpc2_warn[] = { 'D', ':', '/', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '/', 'p', 'c', '2', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // D:/ymir work/pc2 illegal folder detected.
	CHAR __ymirworkpc3_warn[] = { 'D', ':', '/', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '/', 'p', 'c', '3', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // D:/ymir work/pc3 illegal folder detected.
	CHAR __ymirwork_warn[] = { 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // 'ymir work' illegal folder detected in game folder
	CHAR __pc_warn[] = { 'p', 'c', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // 'pc' illegal folder detected in game folder
	CHAR __pc2_warn[] = { 'p', 'c', '2', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // 'pc2' illegal folder detected in game folder
	CHAR __pc3_warn[] = { 'p', 'c', '3', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // 'pc3' illegal folder detected in game folder
	CHAR __ymirworkmonster_warn[] = { 'D', ':', '/', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '/', 'm', 'o', 'n', 's', 't', 'e', 'r', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // D:/ymir work/monster illegal folder detected.
	CHAR __ymirworkmonster2_warn[] = { 'D', ':', '/', 'y', 'm', 'i', 'r', ' ', 'w', 'o', 'r', 'k', '/', 'm', 'o', 'n', 's', 't', 'e', 'r', '2', ' ', 'i', 'l', 'l', 'e', 'g', 'a', 'l', ' ', 'f', 'o', 'l', 'd', 'e', 'r', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // D:/ymir work/monster2 illegal folder detected.

	KARMA_MACRO_1;
	std::string packyediiks = ExePath() + __antiflydmg;
	if (is_file_exist(packyediiks)){
		lpFuncs.CloseProcess(__Antiflydmg_warn, false, "");
	}

	KARMA_MACRO_2;
	std::string packyediiksiki = ExePath() + __waitdmg;
	if (is_file_exist(packyediiksiki)){
		lpFuncs.CloseProcess(__WaitDamage_warn, false, "");
	}

	KARMA_MACRO_1;
	std::string packyediiksuc = ExePath() + __antifly;
	if (is_file_exist(packyediiksuc)){
		lpFuncs.CloseProcess(__Antifly_warn, false, "");
	}
	KARMA_MACRO_2;
	if (dirExist(__ymirpc) || dirExist(__ymirpc_2)) {
		lpFuncs.CloseProcess(__ymirworkpc_warn, false, "");
	}
	KARMA_MACRO_1;
	if (dirExist(__ymirpc2) || dirExist(__ymirpc2_2)) {
		lpFuncs.CloseProcess(__ymirworkpc2_warn, false, "");
	}
	KARMA_MACRO_1;
	if (dirExist(__ymirpc3) || dirExist(__ymirpc3_2)) {
		lpFuncs.CloseProcess(__ymirworkpc3_warn, false, "");
	}
	KARMA_MACRO_2;
	if (dirExist(__ymirmonster) || dirExist(__ymirmonster_2)) {
		lpFuncs.CloseProcess(__ymirworkmonster_warn, false, "");
	}
	KARMA_MACRO_1;
	if (dirExist(__ymirmonster2) || dirExist(__ymirmonster2_2)) {
		lpFuncs.CloseProcess(__ymirworkmonster2_warn, false, "");
	}
	KARMA_MACRO_2;
	std::string exedizin = ExePath() + __ymir;
	if (dirExist(exedizin.c_str())) {
		lpFuncs.CloseProcess(__ymirwork_warn, false, "");
	}
	KARMA_MACRO_1;
	std::string pcdizin = ExePath() + __pc;
	if (dirExist(pcdizin.c_str())) {
		lpFuncs.CloseProcess(__pc_warn, false, "");
	}
	KARMA_MACRO_2;
	std::string pc2dizin = ExePath() + __pc2;
	if (dirExist(pc2dizin.c_str())) {
		lpFuncs.CloseProcess(__pc2_warn, false, "");
	}
	KARMA_MACRO_2;
	std::string pc3dizin = ExePath() + __pc3;
	if (dirExist(pc3dizin.c_str())) {
		lpFuncs.CloseProcess(__pc3_warn, false, "");
	}
	KARMA_MACRO_1;
}

int getdir(string dir, vector<string>& files)
{
	KARMA_MACRO_2
	DIR *dp;
	struct dirent *dirp;
	if ((dp = opendir(dir.c_str())) == NULL) {
		return errno;
	}

	while ((dirp = readdir(dp)) != NULL) {
		files.push_back(string(dirp->d_name));
	}
	closedir(dp);
	KARMA_MACRO_1
	return 0;
}

bool CDirFunctions::AntiMssExploit() {
	CFunctions lpFuncs;
	KARMA_MACRO_1

	string dir = string(".");
	vector<string> files = vector<string>();

	CHAR __dot[] = { '.', 0x0 }; //"."
	CHAR __py[] = { 'p', 'y', 0x0 }; //.py"
	CHAR __mix[] = { 'm', 'i', 'x', 0x0 }; //"mix"
	CHAR __asi[] = { 'a', 's', 'i', 0x0 }; //"asi"
	CHAR __m3d[] = { 'm', '3', 'd', 0x0 }; //"m3d"
	CHAR __flt[] = { 'f', 'l', 't', 0x0 }; //"flt"

	KARMA_MACRO_1

	CHAR __Mixwarn[] = { 'M', 'i', 'x', ' ', 'i', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '\n', '\n', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'r', ' ', 'y', 'o', 'u', 'r', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // Mix injection detected Please clear your game folder
	CHAR __Fltwarn[] = { 'F', 'l', 't', ' ', 'i', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '\n', '\n', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'r', ' ', 'y', 'o', 'u', 'r', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // Flt injection detected Please clear your game folder
	CHAR __Asiwarn[] = { 'A', 's', 'i', ' ', 'i', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '\n', '\n', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'r', ' ', 'y', 'o', 'u', 'r', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // Asi injection detected Please clear your game folder
	CHAR __M3dwarn[] = { 'M', '3', 'd', ' ', 'i', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '\n', '\n', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'r', ' ', 'y', 'o', 'u', 'r', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // M3d injection detected Please clear your game folder
	CHAR __pywarn[] = { '.', 'p', 'y', ' ', 'f', 'i', 'l', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '\n', '\n', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'r', ' ', 'y', 'o', 'u', 'r', ' ', 'g', 'a', 'm', 'e', ' ', 'f', 'o', 'l', 'd', 'e', 'r', 0x0 }; // .py file detected Please clear your game folder

	KARMA_MACRO_1
	getdir(dir, files);
	for (unsigned int i = 0; i < files.size(); i++) {
		string a = files[i];
		if (a.substr(a.find_last_of(__dot) + 1) == __mix) {
			const char* b = a.c_str();

			lpFuncs.CloseProcess(__Mixwarn, false, "");
		}
		else if (a.substr(a.find_last_of(__dot) + 1) == __flt) {
			const char* b = a.c_str();

			lpFuncs.CloseProcess(__Fltwarn, false, "");
		}
		else if (a.substr(a.find_last_of(__dot) + 1) == __m3d) {
			const char* b = a.c_str();

			lpFuncs.CloseProcess(__Asiwarn, false, "");
		}
		else if (a.substr(a.find_last_of(__dot) + 1) == __asi){
			const char* b = a.c_str();

			lpFuncs.CloseProcess(__M3dwarn, false, "");
		}
	}

	KARMA_MACRO_2
	return false;
}

DWORD CDirFunctions::GetFileSize(const char* c_szFileName) {
	HANDLE hFile = BetaFunctionTable->CreateFileA(c_szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwFileSize = hFile != INVALID_HANDLE_VALUE ? BetaFunctionTable->GetFileSize(hFile, NULL) : 0;
	return dwFileSize;
}
unsigned long CDirFunctions::GetFileCrc(const char* c_szFileName) {
	CCRC32 MyCRC32;
	MyCRC32.Initialize();

	return MyCRC32.FileCRC(c_szFileName);
}
char* CDirFunctions::GetFileMd5(char* c_szFileName) {
	MD5 md5;
	return md5.digestFile(c_szFileName);
}

void CDirFunctions::CheckFileSize(const char* c_szFileName, DWORD dwCorrectFileSize) {
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"File size check has been started");
#endif

	KARMA_MACRO_1

	HANDLE hFile = BetaFunctionTable->CreateFileA(c_szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return; //TODO: Add force check option
	DWORD dwFileSize = BetaFunctionTable->GetFileSize(hFile, NULL);

#ifdef _DEBUG
	LPLog->AddLog(0,"File size check event. File: %s Correct size: %u Current Size: %u IsCorrect: %d",
		c_szFileName, dwCorrectFileSize, dwFileSize, (int)(dwCorrectFileSize == dwFileSize));
#endif

	if (dwFileSize != dwCorrectFileSize) {
		CHAR __warn[] = { '%', 's', ' ', 'F', 'i', 'l', 'e', ' ', 'm', 'o', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'u', 'n', ' ', 'a', 'u', 't', 'o', 'p', 'a', 't', 'c', 'h', 'e', 'r', '.', '[', '0', 'x', '2', ']', 0x0 }; // %s File modification detected! Please run autopatcher.[0x2]

		char cTmpStr[250];
		sprintf(cTmpStr, __warn, c_szFileName);
		lpFuncs.CloseProcess(cTmpStr, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"File size check completed");
#endif
}

void CDirFunctions::CheckFileCrc(const char* c_szFileName, unsigned long ulFileHash)
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"File crc check has been started");
#endif

	KARMA_MACRO_1

	CCRC32 MyCRC32;
	MyCRC32.Initialize();
	unsigned long ulRightHash = MyCRC32.FileCRC(c_szFileName);
#ifdef _DEBUG
	LPLog->AddLog(0,"File crc check event. File: %s Correct crc: %lu Current crc: %lu IsCorrect: %d",
		c_szFileName, ulRightHash, ulFileHash, (BOOL)(ulRightHash == ulFileHash));
#endif

	if (ulRightHash != ulFileHash) {
		CHAR __warn[] = { '%', 's', ' ', 'F', 'i', 'l', 'e', ' ', 'm', 'o', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'u', 'n', ' ', 'a', 'u', 't', 'o', 'p', 'a', 't', 'c', 'h', 'e', 'r', '.', '[', '0', 'x', '1', ']', 0x0 }; // %s File modification detected! Please run autopatcher.[0x1]

		char cTmpStr[250];
		sprintf(cTmpStr, __warn, c_szFileName);
		lpFuncs.CloseProcess(cTmpStr, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"File crc check completed");
#endif
}

void CDirFunctions::CheckFileMd5(char* c_szFileName, const char* c_szFileHash)
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0,"File md5 check has been started");
#endif

	KARMA_MACRO_1

	MD5 md5;
	char* cRightHash = md5.digestFile(c_szFileName);
	bool bRet = boost::iequals(cRightHash, c_szFileHash);
#ifdef _DEBUG
	LPLog->AddLog(0,"File md5 check event. File: %s Correct md5: %s Current md5: %s IsCorrect: %d",
		c_szFileName, cRightHash, c_szFileHash, bRet);
#endif

	if (bRet == false) {
		CHAR __warn[] = { '%', 's', ' ', 'F', 'i', 'l', 'e', ' ', 'm', 'o', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'u', 'n', ' ', 'a', 'u', 't', 'o', 'p', 'a', 't', 'c', 'h', 'e', 'r', '.', '[', '0', 'x', '3', ']', 0x0 }; // %s File modification detected! Please run autopatcher.[0x3]

		char cTmpStr[250];
		sprintf(cTmpStr, __warn, c_szFileName);
		lpFuncs.CloseProcess(cTmpStr, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"File md5 check completed");
#endif
}

DWORD WINAPI InitializeFolderCheckEx(LPVOID)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Folder check event has been started");
#endif

	if (LPData->GetGameCode() == TEST_CONSOLE) {
#ifdef _DEBUG
		LPLog->AddLog(0, "Folder check skipped on test console");
#endif
	}

	KARMA_MACRO_1

	CHAR __miles[] = { 'm', 'i', 'l', 'e', 's', 0x0 }; //miles
	CHAR __mssa3d[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'a', '3', 'd', '.', 'm', '3', 'd', 0x0 }; //"mssa3d.m3d"
	CHAR __mssds3d[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'd', 's', '3', 'd', '.', 'm', '3', 'd', 0x0 }; //"mssds3d.m3d"
	CHAR __mssdx7[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'd', 'x', '7', '.', 'm', '3', 'd', 0x0 }; //"mssdx7.m3d"
	CHAR __msseax[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'e', 'a', 'x', '.', 'm', '3', 'd', 0x0 }; //"msseax.m3d"
	CHAR __mssrsx[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'r', 's', 'x', '.', 'm', '3', 'd', 0x0 }; //"mssrsx.m3d"
	CHAR __msssoft[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 's', 'o', 'f', 't', '.', 'm', '3', 'd', 0x0 }; //"msssoft.m3d"
	CHAR __mssmp3[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'm', 'p', '3', '.', 'a', 's', 'i', 0x0 }; //"mssmp3.asi"
	CHAR __mssvoice[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'v', 'o', 'i', 'c', 'e', '.', 'a', 's', 'i', 0x0 }; //"mssvoice.asi"
	CHAR __mssdsp[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', 'd', 's', 'p', '.', 'f', 'l', 't', 0x0 }; //"mssdsp.flt"
	CHAR __miles_mss32[] = { 'm', 'i', 'l', 'e', 's', '/', '/', 'm', 's', 's', '3', '2', '.', 'd', 'l', 'l', 0x0 }; // miles//mss32.dll
	CHAR __mss32[] = { 'm', 's', 's', '3', '2', '.', 'd', 'l', 'l', 0x0 }; //mss32.dll
	CHAR __devildll[] = { 'd', 'e', 'v', 'i', 'l', '.', 'd', 'l', 'l', 0x0 }; // devil.dll

	KARMA_MACRO_1
	if (LPData->GetGameCode() == METIN2_GAME)
	{
		LPDirFunctions->CheckFileCrc(__miles_mss32, 0x6c5812e3);
		LPDirFunctions->CheckFileCrc(__mssa3d, 0x6c0abc4c);
		LPDirFunctions->CheckFileCrc(__mssds3d, 0xa134de04);
		LPDirFunctions->CheckFileCrc(__mssdsp, 0xc88f11bb);
		LPDirFunctions->CheckFileCrc(__mssdx7, 0xe173609);
		LPDirFunctions->CheckFileCrc(__msseax, 0xbe7c43f7);
		LPDirFunctions->CheckFileCrc(__mssmp3, 0x48b4e4d5);
		LPDirFunctions->CheckFileCrc(__mssrsx, 0x20d6c7b7);
		LPDirFunctions->CheckFileCrc(__msssoft, 0xff5f14f8);
		LPDirFunctions->CheckFileCrc(__mssvoice, 0x53ebe0e8);
		LPDirFunctions->CheckFileCrc(__mss32, 0x6c5812e3);
		
		auto dwDevilCrc = LPDirFunctions->GetFileCrc(__devildll);
		if (dwDevilCrc != 0x90f088b8 && dwDevilCrc != 0x68f0df33)
			LPDirFunctions->CheckFileCrc(__devildll, 0); // basic wrapper for close & warn
	}

#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event step1 completed");
#endif

	KARMA_MACRO_2
	LPDirFunctions->MilesCountCheck();
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event step2 completed");
#endif

	KARMA_MACRO_1
	LPDirFunctions->CheckDirectory("");
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event step3 completed");
#endif

	KARMA_MACRO_1
	LPDirFunctions->CheckDirectory(__miles);
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event step4 completed");
#endif

	KARMA_MACRO_2
	LPDirFunctions->MainFolderCheck();
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event step5 completed");
#endif

	KARMA_MACRO_1
	LPDirFunctions->PackCheck();
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event step6 completed");
#endif

	KARMA_MACRO_2
	LPDirFunctions->AntiMssExploit();
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check event completed");
#endif

	KARMA_MACRO_1

	return 0;
}

HANDLE CDirFunctions::InitializeFolderCheck()
{
#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check thread creation has been started!");
#endif

	KARMA_MACRO_1

	HANDLE hThread = LPThreads->_CreateThread((LPTHREAD_START_ROUTINE)InitializeFolderCheckEx, 0, 3);
	if (!hThread) {
		CHAR __warn[] = { 'E', 'R', 'R', 'O', 'R', '!', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'c', 'r', 'e', 'a', 't', 'i', 'o', 'n', ' ', 'f', 'a', 'i', 'l', 'e', 'd', ',', ' ', 'T', 'h', 'r', 'e', 'a', 'd', ' ', 'C', 'o', 'd', 'e', ' ', '0', 'x', '3', '!', 0x0 }; /* ERROR! Thread creation failed, Thread Code 0x3! */
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0,"Folder check thread creation completed!");
#endif
	return hThread;
}
