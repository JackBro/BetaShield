#include "ProjectMain.h"
#include "AntiDebug.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "XOR.h"
#include "VersionHelpers.h"
#include "CLog.h"


VOID AntiCuckoo()
{
	KARMA_MACRO_1
	LPDWORD pOld, pFake;

	pFake = (LPDWORD)malloc(4096 * 100);
	memset(pFake, 1, 4096 * 100);
	__asm
	{
		mov eax, fs:[0x44]		// save old value
		mov pOld, eax

		mov eax, pFake			// replace with fake value
		mov fs : [0x44], eax
	}

	// this will not be logged nor executed.
	BetaFunctionTable->CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, (LPVOID)1000, 0, NULL);

	__asm
	{
		mov eax, pOld		// restore old value, not reached if cuckoo
		mov fs : [0x44], eax
	}

	free(pFake);
	KARMA_MACRO_2;
}

void CAntiDebug::AntiAnalysis()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti analysis check has been started");
#endif
	KARMA_MACRO_2

	/* Cuckoo sandbox */
	AntiCuckoo();
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti analysis check step1 completed");
#endif

	/* Username scan */
	char cUserName[128];
	DWORD dwSize = sizeof(cUserName);
	BetaFunctionTable->GetUserNameA(cUserName, &dwSize);
	const char* c_szLowerUserName = LPFunctions->szLower(cUserName).c_str();

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti analysis check step2 completed");
#endif

	KARMA_MACRO_1

#define is_username(x) !strcmp(c_szLowerUserName, x)
	CHAR x0[] = { 'm', 'a', 'l', 't', 'e', 's', 't', 0x0 }; // MALTEST
	CHAR x1[] = { 's', 'a', 'n', 'd', 'b', 'o', 'x', 0x0 }; // SANDBOX
	CHAR x2[] = { 'v', 'i', 'r', 'u', 's', 0x0 }; // VIRUS
	CHAR x3[] = { 'm', 'a', 'l', 'w', 'a', 'r', 'e', 0x0 }; // MALWARE
	CHAR x4[] = { 't', 'e', 'q', 'u', 'i', 'l', 'a', 'b', 'o', 'o', 'm', 'b', 'o', 'o', 'm', 0x0 }; // TEQUILABOOMBOOM
	CHAR x5[] = { 'c', 'u', 'c', 'k', 'o', 'o', 0x0 }; // cuckoo
	CHAR x6[] = { 'n', 'm', 's', 'd', 'b', 'o', 'x', 0x0 }; // nmsdbox
	CHAR x7[] = { 'x', 'x', 'x', 'x', '-', 'o', 'x', 0x0 }; // xxxx-ox
	CHAR x8[] = { 'c', 'w', 's', 'x', 0x0 }; // cwsx
	CHAR x9[] = { 'w', 'i', 'l', 'b', 'e', 'r', 't', '-', 's', 'c', 0x0 }; // wilbert-sc
	CHAR x10[] = { 'x', 'p', 'a', 'm', 'a', 's', 't', '-', 's', 'c', 0x0 }; // xpamast-sc

	if (is_username(x0) || is_username(x1) || is_username(x2) || is_username(x3) || is_username(x4) || is_username(x5) ||
		is_username(x6) || is_username(x7) || is_username(x8) || is_username(x9) || is_username(x10))
	{
		CHAR _warn[] = { 'A', 'n', 'a', 'l', 'y', 's', 'i', 's', ' ', 't', 'o', 'o', 'l', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', 0x0 }; // Analysis tool detected
		LPFunctions->CloseProcess(_warn, true, "");
	}

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti analysis check completed");
#endif
	KARMA_MACRO_2
}

