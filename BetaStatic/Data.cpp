#include "ProjectMain.h"
#include "Data.h"


#pragma optimize("", off )
bool				m_bMainIsInitialized	= false;
bool				m_bAPISisInitialized	= false;

bool				m_bWatchdogFirstChecked	= false;

HMODULE				m_hAntiModule			= nullptr;
PANTI_MODULE_INFO	m_hAntiModuleInfo		= new ANTI_MODULE_INFO;

std::string			m_szLicenseCode			= "";
char**				m_cpLicensedIPs			= nullptr;
size_t				m_szLicenseCount		= NULL;

std::string			m_szPatcherName			= "";

int					m_iGameCode				= NULL;

HMODULE				m_hPythonHandle			= nullptr;
std::string			m_szPythonName			= "";

bool				m_bIsPacked				= false;

bool				m_bIsShadow				= false;
#pragma optimize("", on )


CData* LPData;
CData::CData()
{
}

CData::~CData()
{

}

#pragma optimize("", off )
void CData::SetInitializedMain(bool bFlag)
{
	m_bMainIsInitialized = bFlag;
}
bool CData::MainIsInitialized()
{
	return m_bMainIsInitialized;
}

void CData::SetDynamicAPIsInitialized()
{
	m_bAPISisInitialized = true;
}
bool CData::DynamicAPIsIsInitialized()
{
	return m_bAPISisInitialized;
}

void CData::SetWatchdogFirstCheck()
{
	m_bWatchdogFirstChecked = true;
}
bool CData::WatchdogIsFirstChecked()
{
	return m_bWatchdogFirstChecked;
}

void CData::SetAntiModule(HMODULE hModule)
{
	m_hAntiModule = hModule;
}
HMODULE	CData::GetAntiModule()
{
	return m_hAntiModule;
}

void CData::SetAntiModuleInformations(const char* lpModuleInfo)
{
	if (lpModuleInfo)
	{
		PANTI_MODULE_INFO p = (PANTI_MODULE_INFO)lpModuleInfo;
		memcpy(m_hAntiModuleInfo, p, sizeof(ANTI_MODULE_INFO));
	}
}
const char* CData::GetAntiModuleInformations()
{
	const char* lpAntiInfo = (const char*)m_hAntiModuleInfo;
	return lpAntiInfo;
}

std::string CData::GetLicenseCode()
{
	return m_szLicenseCode;
}
void CData::SetLicenseCode(std::string tszLicenseCode)
{
	m_szLicenseCode = tszLicenseCode;
}

char** CData::GetLicensedIPArray()
{
	return m_cpLicensedIPs;
}
size_t CData::GetLicensedIPCount()
{
	return m_szLicenseCount;
}
void CData::SetLicensedIPs(char* cIpList[], int iIpCount)
{
	m_cpLicensedIPs = cIpList;
	m_szLicenseCount = iIpCount;
}

std::string	CData::GetPatcherName()
{
	return m_szPatcherName;
}
void CData::SetPatcherName(std::string tszPatcherName)
{
	m_szPatcherName = tszPatcherName;
}

int CData::GetGameCode()
{
	return m_iGameCode;
}
void CData::SetGameCode(int iCode)
{
	m_iGameCode = iCode;
}

HMODULE CData::GetPythonHandle()
{
	return m_hPythonHandle;
}
void CData::SetPythonHandle(HMODULE hModule)
{
	m_hPythonHandle = hModule;
}

std::string CData::GetPythonName()
{
	return m_szPythonName;
}
void CData::SetPythonName(std::string szName)
{
	m_szPythonName = szName;
}

bool CData::IsPackedProcess()
{
	return m_bIsPacked;
}
void CData::SetPackedProcess(bool bRet)
{
	m_bIsPacked = bRet;
}

bool CData::IsShadowInitialized()
{
	return m_bIsShadow;
}
void CData::SetShadowInitialized(bool bRet)
{
	m_bIsShadow = bRet;
}
#pragma optimize("", on )
