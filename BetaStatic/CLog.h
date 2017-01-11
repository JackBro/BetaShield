#pragma once

#include <string>
class CLog
{
	public:
		CLog();
		virtual ~CLog();

		void InitLog(std::string szLogFileName, bool bIsCrypted, std::string szCryptKey);

		void AddLog(int iLevel, const char* c_szFormat, ...);
		void FileLog(int iLevel, const char* c_szFormat, ...);
		void ConsoleLog(int iLevel, const char* c_szFormat, ...);
		void DebugLog(int iLevel, const char* c_szFormat, ...);
		void ErrorLog(int iLevel, const char* c_szFormat, ...);
		void M2HashLog(int iLevel, const char* c_szFormat, ...);
#ifdef _DEBUG
		void DetourLog(int iLevel, const char* c_szFormat, ...);
#endif

	protected:
		std::string GetDate();

	private:
		std::string m_szLogFileName;
#ifdef _DEBUG
		std::string m_szDetourLogFileName;
#endif

		bool m_bIsFirstLog;
#ifdef _DEBUG
		bool m_bIsFirstDetourLog;
#endif

		bool m_bIsCrypted;
		std::string	 m_szCryptKey;
};
extern CLog* LPLog;
