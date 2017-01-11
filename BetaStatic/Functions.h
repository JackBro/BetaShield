#pragma once
#include "ProjectMain.h"
#include "DynamicWinapi.h"

class CFunctions {
	public:
		CFunctions();
		virtual ~CFunctions();

		void OpenConsoleWindow();
		void fMessageBox(HWND wind, DWORD dwTimeout, const char* title, const char* cArgFormat, ...);
		void CsrssMessageBox(const wchar_t* c_wszMessage, const wchar_t* c_wszTitle);
		void TrayBaloon(const wchar_t* c_wszTitle, const wchar_t* c_wszMessage);
		void CloseProcess(const char* c_szLog, bool bIsDebugger, const char* c_szFaqPage, bool bEncrypted = false, DWORD dwLastError = LPWinapi->LastError());

		std::wstring UTF8ToWstring(const std::string& str);
		std::string WstringToUTF8(const std::wstring& str);
		std::string szLower(std::string String);
		std::wstring wszLower(std::wstring String);

		std::string FixBuildDate();
		std::string GetFirstArgument(bool bLower = true);
		bool IsSysWow64();
		bool IsX64System();

		void DecryptBuffer(LPBYTE lpBuf, DWORD dwSize, BYTE byKey);
		void EncryptBuffer(LPBYTE lpBuf, DWORD dwSize, BYTE byKey);

		std::string NtPathToWin32Path(std::string ntPath);
		std::string DosDevicePath2LogicalPath(LPCTSTR lpszDosPath);

		HWND FindWindowFromProcessId(DWORD dwProcessId);
		bool IsMainWindow(HWND hWnd);

		std::string GetProcessFileName(DWORD dwPID);
		std::string GetProcessFullName(HANDLE hProcess);
		DWORD GetProcessParentProcessId(DWORD dwMainProcessId);
		std::string GetProcessNameFromProcessId(DWORD dwProcessId);
		DWORD GetProcessIdFromProcessName(const char* c_szProcessName);
		int ProcessIsItAlive(DWORD dwProcessId);
		DWORD GetProcessIdNative(HANDLE hProcess);

		float GetEntropy(BYTE* Buffer, DWORD length);
		bool IsPackedProcess(std::string szName);
		bool IsCreatedFromItself();
		void InitSelfRestart(std::string szCorrectArg);

		bool IsInModuleRange(HMODULE hModule, DWORD dwAddress);
		bool IsInModuleRange(const char* c_szModuleName, DWORD dwAddress);
		bool IsInAnticheatModuleRange(DWORD dwAddress);
		std::string GetAnticheatFilename();

		DWORD FindPattern(DWORD dwAddress, DWORD dwSize, BYTE* lpBytes, int iPatternSize);
		DWORD FindPatternClassic(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask);
		int GetTextSectionInformation(LPDWORD dwOffset, LPDWORD dwLen);

#ifdef SCRENSHOT_FEATURE
		void SendScreenshotToServer();
#endif

		void InitShadowEx(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
		void RunShadow(DWORD dwProcessId);

};
extern CFunctions* LPFunctions;
