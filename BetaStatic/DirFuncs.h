#pragma once

class CDirFunctions {
	public:
		CDirFunctions();
		virtual ~CDirFunctions();


		HANDLE InitializeFolderCheck();

		inline bool is_file_exist(const std::string& name);
		std::string readFile(const std::string& filename);
		void writeFile(char* filename, char* text);

		bool dirExist(const std::string& dirName_in);
		int DeleteDirectory(const std::string &refcstrRootDirectory, bool bDeleteSubdirectories = true);

		HANDLE CreateTempFile(std::string * szName);

		std::string ExeName();
		std::string ExePath();;
		std::string ExeNameWithPath();
		std::string WinPath();

		bool IsBetaBox(std::string szThis);

		bool IsFromWindowsPath(std::string szPath);
		bool IsFromWindowsPath(std::wstring wszPath);
		bool IsFromWindowsPath(const char* c_szPath);
		bool IsFromWindowsPath(const wchar_t* c_wszPath);

		bool IsFromCurrentPath(std::string szPath);
		bool IsFromCurrentPath(std::wstring wszPath);
		bool IsFromCurrentPath(const char* c_szPath);
		bool IsFromCurrentPath(const wchar_t* c_wszPath);

		std::string GetNameFromPath(std::string __wszFileName);
		std::wstring GetNameFromPath(std::wstring __wszFileName);

		int GetDirFileCount(std::string wat);
		void CheckDirectory(string Directory);

		void MilesCountCheck();
		void MainFolderCheck();
		void PackCheck();
		bool AntiMssExploit();

		DWORD GetFileSize(const char* c_szFileName);
		unsigned long GetFileCrc(const char* c_szFileName);
		char* GetFileMd5(char* c_szFileName);

		void CheckFileSize(const char* c_szFileName, DWORD dwCorrectFileSize);
		void CheckFileCrc(const char* c_szFileName, unsigned long ulFileHash);
		void CheckFileMd5(char* c_szFileName, const char* c_szFileHash);
};
extern CDirFunctions* LPDirFunctions;
