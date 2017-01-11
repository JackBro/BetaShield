#pragma once
#include "Services.h"

#ifdef SCRENSHOT_FEATURE
enum EReqMethods {
	GET,
	POST
};
#endif

class CInternetAPI {
	public:
		CInternetAPI();
		virtual ~CInternetAPI();

		std::string ReadUrl(std::string szAddress, size_t* pszSize);
		bool IsManipulatedConnection();
		bool IsCorrectIPAddressOfWebsite(std::string szWebsite, std::string szIPAddress);
		void CheckInternetStatus();

#ifdef SCRENSHOT_FEATURE
		bool PostData(LPCSTR Host, LPCSTR url, const char* filename, unsigned char* data, size_t datasize);
#endif

		bool IsLicensedIp(std::string szThis);
		HANDLE InitLicenseCheck();
};
extern CInternetAPI* LPInternetAPI;
