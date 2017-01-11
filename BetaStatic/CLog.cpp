#include "ProjectMain.h"
#include "CLog.h"
#include "XOR.h"

CLog* LPLog;
CLog::CLog()
{
	m_szLogFileName = "";
#ifdef _DEBUG
	m_szDetourLogFileName = "";
#endif

	m_bIsFirstLog = true;
#ifdef _DEBUG
	m_bIsFirstDetourLog = true;
#endif

	m_bIsCrypted = false;
	m_szCryptKey = "";
}

CLog::~CLog()
{
}

void CLog::InitLog(std::string szLogFileName, bool bIsCrypted, std::string szCryptKey)
{
	m_szLogFileName = szLogFileName;
#ifdef _DEBUG
	m_szDetourLogFileName = XOR("syserr2_detours.txt");
#endif

	m_bIsCrypted = bIsCrypted;
	m_szCryptKey = szCryptKey;

	std::ofstream f(m_szLogFileName, std::ofstream::out | std::ofstream::app);
	f << XOR("++++++++++++++++++++") << GetDate().c_str() << XOR("++++++++++++++++++++") << XOR("\n") << std::endl;
	f.close();
}

std::string CLog::GetDate()
{
	SYSTEMTIME sysTime;
	GetSystemTime(&sysTime);

	CHAR __timeformat[] = { '%', '0', '2', 'd', ':', '%', '0', '2', 'd', ':', '%', '0', '2', 'd', ' ', '-', ' ', '%', '0', '2', 'd', ':', '%', '0', '2', 'd', ':', '%', 'd', ' ', ':', ':', ' ', 0x0 }; // %02d:%02d:%02d - %02d:%02d:%d :: 
	char szTimeBuf[1024];
	sprintf(szTimeBuf, XOR(__timeformat), sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wDay, sysTime.wMonth, sysTime.wYear);
	return szTimeBuf;
}

void CLog::AddLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8192];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	if (iLevel >= 0) {
		DebugLog(iLevel, cTmpString);
		ConsoleLog(iLevel, cTmpString);
	}
	FileLog(iLevel, cTmpString);
}

void CLog::DebugLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8000];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	char szmpStr[8192];
	sprintf(szmpStr, XOR("%s :: %s"), GetDate().c_str(), cTmpString);
	OutputDebugStringA(szmpStr);
}

void CLog::ConsoleLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8000];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	char szmpStr[8192];
	sprintf(szmpStr, XOR("%s :: %s\n"), GetDate().c_str(), cTmpString);
	fputs(szmpStr, stdout);
}


void CLog::FileLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8000];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	std::ofstream f(m_szLogFileName, std::ofstream::out | std::ofstream::app);
	f << GetDate().c_str() << " " << cTmpString << XOR("\n") << std::endl;
	f.close();
}


void CLog::ErrorLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8000];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	char CLastString[8192];
	sprintf(CLastString, XOR("[ERROR] - %s :: %s \n"), GetDate().c_str(), cTmpString);

	DebugLog(iLevel, CLastString);
	ConsoleLog(iLevel, CLastString);
	FileLog(iLevel, CLastString);
}


void CLog::M2HashLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8192];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	std::ofstream f(XOR("HashLog.txt"), std::ofstream::out | std::ofstream::app);
	f << cTmpString << XOR("\n") << std::endl;
	f.close();
}

#ifdef _DEBUG
void CLog::DetourLog(int iLevel, const char* c_szFormat, ...)
{
	char cTmpString[8192];
	va_list vaArgList;
	va_start(vaArgList, c_szFormat);
	vsnprintf(cTmpString, c_szFormat, vaArgList);
	va_end(vaArgList);

	std::ofstream f(m_szDetourLogFileName, std::ofstream::out | std::ofstream::app);
	f << GetDate().c_str() << " " << cTmpString << XOR("\n") << std::endl;
	f.close();
}
#endif

