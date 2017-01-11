#pragma once

class CFile_Verification {
	public:
		CFile_Verification();
		virtual ~CFile_Verification();

		void CheckFileVerification(const char* c_szIpAddress);
};
extern CFile_Verification* LPFile_Verification;
