#include "ProjectMain.h"
#include "Main.h"
#include "InternetAPI.h"
#include "DynamicWinapi.h"

#include "Functions.h"
#include "DirFuncs.h"
#include "VersionHelpers.h"
#include "XOR.h"
#include "CLog.h"
#include <winsock2.h>

#include <boost/algorithm/string/predicate.hpp>

static const char* c_szWebAgent = XOR("BetaShieldAgent");

CInternetAPI* LPInternetAPI;
CInternetAPI::CInternetAPI()
{
}

CInternetAPI::~CInternetAPI()
{
}

void etchosts_check()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Hosts check event has been started!");
#endif
	KARMA_MACRO_1

	CHAR __file[] = { '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'd', 'r', 'i', 'v', 'e', 'r', 's', '\\', 'e', 't', 'c', '\\', 'h', 'o', 's', 't', 's', 0x0 }; // \System32\drivers\etc\hosts
	CHAR __address[] = { 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', 0x0 }; // betashield.org
	CHAR __address_ip[] = { '1', '9', '4', '.', '1', '6', '9', '.', '2', '1', '1', '.', '6', '0', 0x0 }; // 194.169.211.60
	CHAR __warn[] = { 'H', 'o', 's', 't', 's', ' ', 'f', 'i', 'l', 'e', ' ', 'm', 'o', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 }; // Hosts file modification detected

	std::string szHosts = LPDirFunctions->WinPath() + __file;
	if (LPDirFunctions->is_file_exist(szHosts))
	{
		if (LPDirFunctions->readFile(szHosts).find(__address) != std::string::npos ||
			LPDirFunctions->readFile(szHosts).find(__address_ip) != std::string::npos)
		{
			LPFunctions->CloseProcess(__warn, false, "");
		}
	}

	KARMA_MACRO_2
#ifdef _DEBUG
	LPLog->AddLog(0,"Hosts check event completed!");
#endif
}

__forceinline int WebStatusCheck(const char* c_szAddress)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Web status check has been started!");
#endif
	etchosts_check();

	DWORD statCodeLen = sizeof(DWORD);
	DWORD statCode = 0;

	HINTERNET hInternet = BetaFunctionTable->InternetOpenA(c_szWebAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, NULL);
	if (!hInternet) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Web api error! InternetOpenA fail. Error: %u", LPWinapi->LastError());
#endif
		return -1;
	}

	HINTERNET hRequestHandle = BetaFunctionTable->InternetOpenUrlA(hInternet, c_szAddress, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
	if (!hRequestHandle) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Web api error! InternetOpenUrlA fail. Error: %u", LPWinapi->LastError());
#endif
		BetaFunctionTable->InternetCloseHandle(hInternet);
		return -2;
	}

	BOOL hQuery = BetaFunctionTable->HttpQueryInfoA(hRequestHandle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statCode, &statCodeLen, NULL);
	if (!hQuery) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Web api error! HttpQueryInfoA fail. Error: %u", LPWinapi->LastError());
#endif
		BetaFunctionTable->InternetCloseHandle(hInternet);
		BetaFunctionTable->InternetCloseHandle(hRequestHandle);
		return -3;
	}

	BetaFunctionTable->InternetCloseHandle(hInternet);
	BetaFunctionTable->InternetCloseHandle(hRequestHandle);

#ifdef _DEBUG
	LPLog->AddLog(0, "Web status check completed!");
#endif
	return statCode;
}

std::string CInternetAPI::ReadUrl(std::string szAddress, size_t* pszSize)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Read url event has been started. Address: %s", szAddress.c_str());
#endif

	std::string szResult = "";
	char szBuffer[4096 + 1] = { 0 };
	std::vector<BYTE> vTempdata;
	DWORD dwBytesRead = 1;

	auto iWebStat = WebStatusCheck(szAddress.c_str());
	if (iWebStat != 200) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Read url event returned with unknown web status. Address: %s Status: %d", szAddress.c_str(), iWebStat);
#endif
		return XOR("666");
	}

	HINTERNET hOpen = BetaFunctionTable->InternetOpenA(c_szWebAgent, NULL, NULL, NULL, NULL);
	if (!hOpen) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Read url event InternetOpenA failed. Error: %u", LPWinapi->LastError());
#endif
		return szResult;
	}

	HINTERNET hFile = BetaFunctionTable->InternetOpenUrlA(hOpen, szAddress.c_str(), NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
	if (!hFile) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Read url event InternetOpenUrlA failed. Error: %u", LPWinapi->LastError());
#endif
		BetaFunctionTable->InternetCloseHandle(hOpen);
		return szResult;
	}

	size_t szTempSize = 0;
	while (dwBytesRead)
	{
		if (BetaFunctionTable->InternetReadFile(hFile, szBuffer, 4096, &dwBytesRead))
		{
			szTempSize = vTempdata.size();
			vTempdata.resize(vTempdata.size() + dwBytesRead);
			memcpy(vTempdata.data() + szTempSize, szBuffer, dwBytesRead);
		}
	}

	BYTE* byData = new BYTE[vTempdata.size() + 1];
	byData[vTempdata.size()] = 0x00;

	memcpy(byData, vTempdata.data(), vTempdata.size());

	for (size_t i = 0; i < vTempdata.size(); i++)
		byData[i] = vTempdata[i];

	BetaFunctionTable->InternetCloseHandle(hFile);
	BetaFunctionTable->InternetCloseHandle(hOpen);

	if (pszSize) {
		*pszSize = vTempdata.size();
		const char* c_szReadResult = reinterpret_cast<const char*>(byData);
		szResult = c_szReadResult;
		delete[] byData;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Read url event completed. Address: %s Result: %s", szAddress.c_str(), szResult.c_str());
#endif
	return szResult;
}

bool CInternetAPI::IsManipulatedConnection()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "IsManipulatedConnection event has been started");
#endif

	size_t szSize = 0;
	auto originalDate = LPInternetAPI->ReadUrl(XOR("http://www.timeapi.org/utc/now?\\Y\\m\\d"), &szSize);
	if (originalDate.empty()) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsManipulatedConnection event return is NULL! Passed..");
#endif
		return false;
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "IsManipulatedConnection event completed. Size: %d Correct Size: 8", szSize);
#endif
	return (szSize != 0 && originalDate != XOR("666") && szSize != 8);
}

bool CInternetAPI::IsCorrectIPAddressOfWebsite(std::string szWebsite, std::string szIPAddress)
{
#ifdef _DEBUG
	LPLog->AddLog(0, "IsCorrectIPAddressOfWebsite event has been started");
#endif

	in_addr addr;

	WSADATA2 wsaData;
	int iResult = BetaFunctionTable->WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCorrectIPAddressOfWebsite event WSAStartup failed: %d", iResult);
#endif
		return true;
	}

	hostent *remoteHost;
	remoteHost = BetaFunctionTable->gethostbyname(szWebsite.c_str());
	if(!remoteHost)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "IsCorrectIPAddressOfWebsite event gethostbyname failed: %d", BetaFunctionTable->WSAGetLastError());
#endif
		return true;
	}
	BetaFunctionTable->WSACleanup();

	if (remoteHost && remoteHost->h_addrtype == AF_INET)
	{
		int i = 0;
		while (remoteHost->h_addr_list[i] != 0)
		{
			addr.s_addr = *(DWORD*)remoteHost->h_addr_list[i++];
#ifdef _DEBUG
			LPLog->AddLog(0, "IsCorrectIPAddressOfWebsite event new addr detected. Addr: %s Correct addr: %s", BetaFunctionTable->inet_ntoa(addr), szIPAddress.c_str());
#endif
			if (boost::iequals(szIPAddress.c_str(), BetaFunctionTable->inet_ntoa(addr)))
				return true;
		}
	}

#ifdef _DEBUG
	LPLog->ErrorLog(0, "IsCorrectIPAddressOfWebsite failed! Remotehost: %p Addrtype: %d", remoteHost, remoteHost->h_addrtype);
	LPLog->AddLog(0, "IsCorrectIPAddressOfWebsite event completed");
#endif
	return false;
}


#ifdef SCRENSHOT_FEATURE
bool CInternetAPI::PostData(LPCSTR Host, LPCSTR url, const char* filename, unsigned char* data, size_t datasize)
{	
	CHAR __formname[] = { 'u', 'p', 'l', 'o', 'a', 'd', 'e', 'd', 'f', 'i', 'l', 'e', 0x0 }; // uploadedfile
	CHAR __formfilename[] = { 'L', 'o', 'g', '.', 't', 'x', 't', 0x0 }; // Log.txt
	CHAR __boundary[] = { 'M', 'D', '5', '_', '0', 'b', 'e', '6', '3', 'c', 'd', 'a', '3', 'b', 'f', '4', '2', '1', '9', '3', 'e', '4', '3', '0', '3', 'd', 'b', '2', 'c', '5', 'a', 'c', '3', '1', '3', '8', 0x0 }; // MD5_0be63cda3bf42193e4303db2c5ac3138
	std::string boundary(__boundary);

	static std::string hdrs = XOR("Content-Type: multipart/form-data; boundary=") + boundary;
	std::ostringstream head;
	head << XOR("--") << boundary << XOR("\r\n");
	head << XOR("Content-Disposition: form-data; name=\"") << __formname << XOR("\"; filename=\"") << __formfilename << XOR("\"\r\n");
	head << XOR("Content-Type: application/octet-stream\r\n");
	head << XOR("Content-Transfer-Encoding: binary\r\n");
	head << XOR("\r\n");
	static std::string tail = XOR("\r\n--") + boundary + XOR("--\r\n");

	CHAR __POST[] = { 'P', 'O', 'S', 'T', 0x0 }; // POST
	CHAR __HTTPtype[] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', 0x0 }; // HTTP/1.1
	CHAR __httpUseragent[] = { 'B', 'e', 't', 'a', 'S', 'h', 'i', 'e', 'l', 'd', 'V', '2', ' ', 'A', 'n', 't', 'i', 'c', 'h', 'e', 'a', 't', ' ', 'W', 'e', 'b', ' ', 'A', 'g', 'e', 'n', 't', 0x0 }; // BetaShieldV2 Anticheat Web Agent

	try {

		HINTERNET internet = BetaFunctionTable->InternetOpenA(__httpUseragent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (internet == NULL) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: InternetOpenA fail! Error code: %u", LPWinapi->LastError());
#endif
			return false;
		}

		HINTERNET connect = BetaFunctionTable->InternetConnectA(internet, Host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
		if (connect == NULL) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: InternetConnectA fail! Error code: %u", LPWinapi->LastError());
#endif
			BetaFunctionTable->InternetCloseHandle(internet);
			return false;
		}

		HINTERNET request = BetaFunctionTable->HttpOpenRequestA(connect, __POST, url, __HTTPtype, NULL, NULL,
			INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
			INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
			INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP |
			INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
			INTERNET_FLAG_NO_AUTH |
			INTERNET_FLAG_NO_CACHE_WRITE |
			INTERNET_FLAG_NO_UI |
			INTERNET_FLAG_PRAGMA_NOCACHE |
			INTERNET_FLAG_RELOAD, NULL);

		if (request == NULL) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: HttpOpenRequestA fail! Error code: %u", LPWinapi->LastError());
#endif
			BetaFunctionTable->InternetCloseHandle(connect);
			BetaFunctionTable->InternetCloseHandle(internet);
			return false;
		}

		BOOL addReqHeaders = BetaFunctionTable->HttpAddRequestHeadersA(request, hdrs.c_str(), -1, HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);
		if (addReqHeaders == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: HttpAddRequestHeadersA fail! Error code: %u", LPWinapi->LastError());
#endif
			BetaFunctionTable->InternetCloseHandle(request);
			BetaFunctionTable->InternetCloseHandle(connect);
			BetaFunctionTable->InternetCloseHandle(internet);
			return false;
		}

		INTERNET_BUFFERS bufferIn;
		memset(&bufferIn, 0, sizeof(INTERNET_BUFFERS));

		bufferIn.dwStructSize = sizeof(INTERNET_BUFFERS);
		bufferIn.dwBufferTotal = head.str().size() + datasize + tail.size();

		BOOL sendReq = BetaFunctionTable->HttpSendRequestExA(request, &bufferIn, NULL, HSR_INITIATE, 0);
		if (sendReq == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: HttpSendRequestExA fail! Error code: %u", LPWinapi->LastError());
#endif
			BetaFunctionTable->InternetCloseHandle(request);
			BetaFunctionTable->InternetCloseHandle(connect);
			BetaFunctionTable->InternetCloseHandle(internet);
			return false;
		}

		DWORD bytesWritten = 0;
		if (
			FALSE == BetaFunctionTable->InternetWriteFile(request, (const void*)head.str().c_str(), head.str().size(), &bytesWritten) ||
			FALSE == BetaFunctionTable->InternetWriteFile(request, (const void*)data, datasize, &bytesWritten) ||
			FALSE == BetaFunctionTable->InternetWriteFile(request, (const void*)tail.c_str(), tail.size(), &bytesWritten)
		) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: InternetWriteFile fail! Error code: %u", LPWinapi->LastError());
#endif
			BetaFunctionTable->InternetCloseHandle(request);
			BetaFunctionTable->InternetCloseHandle(connect);
			BetaFunctionTable->InternetCloseHandle(internet);
			return false;
		}

		if (BetaFunctionTable->HttpEndRequestA(request, NULL, HSR_INITIATE, 0) == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "PostData: HttpEndRequestA fail! Error code: %u", LPWinapi->LastError());
#endif
			BetaFunctionTable->InternetCloseHandle(request);
			BetaFunctionTable->InternetCloseHandle(connect);
			BetaFunctionTable->InternetCloseHandle(internet);
			return false;
		}


		BetaFunctionTable->InternetCloseHandle(request);
		BetaFunctionTable->InternetCloseHandle(connect);
		BetaFunctionTable->InternetCloseHandle(internet);
#ifdef _DEBUG
		LPLog->AddLog(0, "PostData: File succesfully sended to server!");
#endif
		return true;
	}
	catch (std::exception& e)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Exception triggered on PostData. Info: %s", e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif
		return 0;
	}
	catch (DWORD dwError) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Exception2 triggered on PostData Error: %u", dwError);
#else
		UNREFERENCED_PARAMETER(dwError);
#endif
	}
	catch (...)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Exception3 triggered on PostData");
#endif
	}

	return false;
}

#endif

void CInternetAPI::CheckInternetStatus()
{
	CHAR __google[] = { 'h', 't', 't', 'p', ':', '/', '/', 'w', 'w', 'w', '.', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0x0 }; // http://www.google.com
	CHAR __warn[] = { 'I', 'n', 't', 'e', 'r', 'n', 'e', 't', ' ', 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'a', 'c', 't', 'i', 'v', 'e', ' ', 'o', 'r', ' ', 'h', 'a', 'v', 'e', ' ', 'a', ' ', 's', 'o', 'm', 'e', ' ', 'p', 'r', 'o', 'b', 'l', 'e', 'm', 's', ',', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'd', 'i', 's', 'a', 'b', 'l', 'e', ' ', 'a', 'n', 't', 'i', 'v', 'i', 'r', 'u', 's', ' ', 'a', 'n', 'd', ' ', 't', 'r', 'y', ' ', 'a', 'g', 'a', 'i', 'n', '.', 0x0 }; // Internet connection is not active or have a some problems, Please disable antivirus and try again.

	BOOL bConnect = BetaFunctionTable->InternetCheckConnectionA(__google, FLAG_ICC_FORCE_CONNECTION, 0);
	if (bConnect == FALSE)
		LPFunctions->CloseProcess(__warn, false, "");
}

void FtpUpload(char* file, char* IPAdr, char* usernm, char* sifre)
{
	/*
	HINTERNET hInternet;
	HINTERNET hFtpSession;
	hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	hFtpSession = InternetConnect(hInternet, IPAdr, INTERNET_DEFAULT_FTP_PORT, usernm, sifre, INTERNET_SERVICE_FTP, 0, 0);
	if (FtpPutFileA(hFtpSession, file, UserName(), FTP_TRANSFER_TYPE_BINARY, 0)) 
	{
		//cout << "Upload Ok!" << endl;
		InternetCloseHandle(hFtpSession);
		InternetCloseHandle(hInternet);
	}
	*/
}

