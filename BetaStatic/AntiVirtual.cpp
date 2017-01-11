#include "ProjectMain.h"
#include "Functions.h"
#include "DynamicWinapi.h"
#include "Threads.h"

#include "CLog.h"
#include "XOR.h"
#include "AntiDebug.h"


// IsInsideVPC's exception filter
DWORD __forceinline IsInsideVPC_exceptionFilter(LPEXCEPTION_POINTERS ep)
{
	PCONTEXT ctx = ep->ContextRecord;

	ctx->Ebx = -1; // Not running VPC
	ctx->Eip += 4; // skip past the "call VPC" opcodes
	return EXCEPTION_CONTINUE_EXECUTION;
	// we can safely resume execution since we skipped faulty instruction
}

// High level language friendly version of IsInsideVPC()
bool IsInsideVPC()
{
	bool rc = false;

	__try
	{
		_asm push ebx
		_asm mov  ebx, 0 // It will stay ZERO if VPC is running
		_asm mov  eax, 1 // VPC function number

						 // call VPC
		_asm __emit 0Fh
		_asm __emit 3Fh
		_asm __emit 07h
		_asm __emit 0Bh

		_asm test ebx, ebx
		_asm setz[rc]
			_asm pop ebx
	}
	// The except block shouldn't get triggered if VPC is running!!
	__except (IsInsideVPC_exceptionFilter(GetExceptionInformation()))
	{
	}

	return rc;
}

bool IsInsideVMWare()
{
	bool rc = true;

	__try
	{
		__asm
		{
			push   edx
			push   ecx
			push   ebx

			mov    eax, 'VMXh'
			mov    ebx, 0 // any value but not the MAGIC VALUE
			mov    ecx, 10 // get VMWare version
			mov    edx, 'VX' // port number

			in     eax, dx // read port
						   // on return EAX returns the VERSION
						   cmp    ebx, 'VMXh' // is it a reply from VMWare?
						   setz[rc] // set return value

						   pop    ebx
						   pop    ecx
						   pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		rc = false;
	}

	return rc;
}

void AntiVPC()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtual pc check has been started!");
#endif

	KARMA_MACRO_1

	CHAR __vmcheckdll[] = { 'v', 'm', 'c', 'h', 'e', 'c', 'k', '.', 'd', 'l', 'l', 0x0 }; // vmcheck.dll
	if (IsInsideVPC() || BetaFunctionTable->GetModuleHandleA(__vmcheckdll)) {
		CHAR __warn[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'C', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtual pc check completed!");
#endif
}

void AntiVMware()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti vmware check has been started!");
#endif

	KARMA_MACRO_1

	if (IsInsideVMWare()) {
		CHAR __warn[] = { 'V', 'm', 'w', 'a', 'r', 'e', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti vmware check completed!");
#endif
}

void AntiSandBoxie()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti sandboxie check has been started!");
#endif

	KARMA_MACRO_2

	CHAR _SandboxDll[] = { 'S', 'b', 'i', 'e', 'D', 'l', 'l', '.', 'd', 'l', 'l', 0x0 }; //"SbieDll.dll"
	HMODULE sandbox = BetaFunctionTable->GetModuleHandleA(_SandboxDll);

	if (sandbox) {
		CHAR __warn[] = { 'S', 'a', 'n', 'd', 'b', 'o', 'x', 'i', 'e', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti sandboxie check completed!");
#endif
}

void AntiVirtualMachine()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtual machine check has been started!");
#endif

	KARMA_MACRO_1

	unsigned int reax = 0;

	__asm
	{
		mov eax, 0xCCCCCCCC;
		smsw eax;
		mov DWORD PTR[reax], eax;
	}

	if ((((reax >> 24) & 0xFF) == 0xcc) && (((reax >> 16) & 0xFF) == 0xcc)) {
		CHAR __warn[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'M', 'a', 'c', 'h', 'i', 'n', 'e', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtual machine check completed!");
#endif
}


void AntiVirtualBox()
{
	CFunctions lpFuncs;
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtual box check has been started!");
#endif

	KARMA_MACRO_1

	unsigned long pnsize = 0x1000;
	char* provider = (char*)BetaFunctionTable->LocalAlloc(LMEM_ZEROINIT, pnsize);

	int retv = BetaFunctionTable->WNetGetProviderNameA(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
	if (retv == NO_ERROR) {
		CHAR virtualboxfoldername[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'B', 'o', 'x', ' ', 'S', 'h', 'a', 'r', 'e', 'd', ' ', 'F', 'o', 'l', 'd', 'e', 'r', 's', '!', 0x0 };
		if (BetaFunctionTable->lstrcmpA(provider, virtualboxfoldername) == 0) {
			CHAR __warn[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'B', 'o', 'x', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
			LPFunctions->CloseProcess(__warn, false, "");
		}
	}
	if (provider)
		BetaFunctionTable->LocalFree(provider);

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtual box check completed!");
#endif
}


void AntiSunbeltSandBox()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti sunbelt sandbox check has been started!");
#endif

	KARMA_MACRO_1

	CHAR szFileName[MAX_PATH];
	BetaFunctionTable->GetModuleFileNameA(NULL, szFileName, MAX_PATH);

	CHAR sandboxfile[] = { 'C', ':', '\\', '\\', 'f', 'i', 'l', 'e', '.', 'e', 'x', 'e', 0x0 };
	CHAR __pstorecdll[] = { 'p', 's', 't', 'o', 'r', 'e', 'c', '.', 'd', 'l', 'l', 0x0 }; // pstorec.dll
	if (!strcmp(szFileName, sandboxfile) || BetaFunctionTable->GetModuleHandleA(__pstorecdll)) {
		CHAR __warn[] = { 'S', 'a', 'n', 'd', 'b', 'o', 'x', '2', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti sunbelt sandbox check completed!");
#endif
}


void AntiWPEPro()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti wpe check has been started!");
#endif

	KARMA_MACRO_1

	CHAR __wpespydll[] = { 'w', 'p', 'e', 's', 'p', 'y', '.', 'd', 'l', 'l', 0x0 }; // wpespy.dll
	if (BetaFunctionTable->GetModuleHandleA(__wpespydll)) {
		CHAR __warn[] = { 'W', 'P', 'E', ' ', 'P', 'r', 'o', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '.', 0x0 }; // WPE Pro detected.
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti wpe check completed!");
#endif
}

void AntiWine()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti wine check has been started!");
#endif

	KARMA_MACRO_2

	CHAR __wine_get_unix_file_name[] = { 'w', 'i', 'n', 'e', '_', 'g', 'e', 't', '_', 'u', 'n', 'i', 'x', '_', 'f', 'i', 'l', 'e', '_', 'n', 'a', 'm', 'e', 0x0 }; // wine_get_unix_file_name
	if (BetaFunctionTable->_GetProcAddress(BetaModuleTable->hKernel32, __wine_get_unix_file_name)) {
		CHAR __warn[] = { 'W', 'i', 'n', 'e', ' ', 'v', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'm', 'a', 'c', 'h', 'i', 'n', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // Wine virtual machine detected!
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti wine check completed!");
#endif
}

void Anticuckoomon()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti cuckoomon check has been started!");
#endif

	KARMA_MACRO_1

	CHAR __cuckoomondll[] = { 'c', 'u', 'c', 'k', 'o', 'o', 'm', 'o', 'n', '.', 'd', 'l', 'l', 0x0 }; // cuckoomon.dll
	if (BetaFunctionTable->GetModuleHandleA(__cuckoomondll)) {
		CHAR __warn[] = { 'C', 'u', 'c', 'k', 'o', 'o', 'm', 'o', 'n', ' ', 'v', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'm', 'a', 'c', 'h', 'i', 'n', 'e', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 }; // Cuckoomon virtual machine detected!
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti cuckoomon check completed!");
#endif
}

void AntiSandbox()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti sandbox check has been started!");
#endif

	KARMA_MACRO_1

	HWND hwSandbox = BetaFunctionTable->FindWindowExA(0, 0, XOR("Progman"), XOR("Program Manager"));
	if (!hwSandbox) {
		CHAR __warn[] = { 'S', 'a', 'n', 'd', 'b', 'o', 'x', '3', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}

	KARMA_MACRO_2

	HWND hwSandbox2 = BetaFunctionTable->FindWindowExA(0, 0, XOR("SandboxieControlWndClass"), 0);
	if (hwSandbox2) {
		CHAR __warn[] = { 'S', 'a', 'n', 'd', 'b', 'o', 'x', '4', ' ', 'D', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', 0x0 };
		LPFunctions->CloseProcess(__warn, false, "");
	}
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti sandbox check completed!");
#endif
}

void CheckRegistry_DiscEnum()
{
	char RegKey[_MAX_PATH] = { 0 };
	DWORD BufSize = _MAX_PATH;
	DWORD dataType = REG_SZ;

	HKEY hKey;
	CHAR __regpath[] = { 'S', 'Y', 'S', 'T', 'E', 'M', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'S', 'e', 't', '\\', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', '\\', 'D', 'i', 's', 'k', '\\', 'E', 'n', 'u', 'm', 0x0 }; // SYSTEM\CurrentControlSet\Services\Disk\Enum
	long lError = BetaFunctionTable->RegOpenKeyExA(HKEY_LOCAL_MACHINE, __regpath, NULL, KEY_QUERY_VALUE, &hKey);
	if (lError == ERROR_SUCCESS)
	{
		long lVal = BetaFunctionTable->RegQueryValueExA(hKey, "0" /* column */, NULL, &dataType, (LPBYTE)&RegKey, &BufSize);
		if (lVal == ERROR_SUCCESS)
		{
			CHAR __warn[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 's', 'y', 's', 't', 'e', 'm', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', '!', ' ', '%', 's', ' ', 'i', 's', ' ', 'n', 'o', 't', ' ', 'a', 'l', 'l', 'o', 'w', 'e', 'd', '!', 0x0 }; // Virtual system detected! %s is not allowed!

			CHAR __vmware[] = { 'v', 'm', 'w', 'a', 'r', 'e', 0x0 }; // vmware
			CHAR __virtual[] = { 'v', 'i', 'r', 't', 'u', 'a', 'l', 0x0 }; // virtual
			CHAR __vbox[] = { 'v', 'b', 'o', 'x', 0x0 }; // vbox
			CHAR __qemu[] = { 'q', 'e', 'm', 'u', 0x0 }; // qemu
			CHAR __xen[] = { 'x', 'e', 'n', 0x0 }; // xen

			std::string szRegKey = RegKey;
			if (strstr(LPFunctions->szLower(szRegKey).c_str(), __vmware))
			{
				CHAR __type[] = { 'V', 'M', 'W', 'a', 'r', 'e', 0x0 }; // VMWare
				char szWarn[1024];
				sprintf(szWarn, __warn, __type);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
			if (strstr(LPFunctions->szLower(szRegKey).c_str(), __virtual))
			{
				CHAR __type[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'P', 'C', 0x0 }; // Virtual PC
				char szWarn[1024];
				sprintf(szWarn, __warn, __type);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
			if (strstr(LPFunctions->szLower(szRegKey).c_str(), __vbox))
			{
				CHAR __type[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'B', 'o', 'x', 0x0 }; // Virtual Box
				char szWarn[1024];
				sprintf(szWarn, __warn, __type);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
			if (strstr(LPFunctions->szLower(szRegKey).c_str(), __qemu))
			{
				CHAR __type[] = { 'Q', 'E', 'M', 'U', 0x0 }; // QEMU
				char szWarn[1024];
				sprintf(szWarn, __warn, __type);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
			if (strstr(LPFunctions->szLower(szRegKey).c_str(), __xen))
			{
				CHAR __type[] = { 'X', 'e', 'n', 0x0 }; // Xen
				char szWarn[1024];
				sprintf(szWarn, __warn, __type);
				LPFunctions->CloseProcess(szWarn, false, "");
			}
		}
		BetaFunctionTable->RegCloseKey(hKey);
	}
}

void CheckRdtsc()
{
	CHAR __warn[] = { 'T', 'i', 'm', 'e', 'o', 'u', 't', ' ', 'o', 'n', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 't', 'r', 'y', ' ', 'a', 'g', 'a', 'i', 'n', '.', 0x0 }; // Timeout on initilization! Please try again.

	unsigned int time1 = 0;
	unsigned int time2 = 0;
	__asm
	{
		RDTSC
		MOV time1, EAX
		RDTSC
		MOV time2, EAX
	}
	if ((time2 - time1) > 200) {
#ifdef _DEBUG
		LPLog->ErrorLog(0, "Rdtsc timeout! Diff: %u bigger than 200!", time2 - time1);
#endif
		LPFunctions->CloseProcess(__warn, false, "");
	}
}

void CAntiDebug::AntiVirtualize()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtualize event has been started!");
#endif

	KARMA_MACRO_2
	AntiVPC();
	AntiVMware();
	AntiSandBoxie();
	AntiSandbox();
	AntiVirtualMachine();
	AntiVirtualBox();
	AntiSunbeltSandBox();
	AntiWPEPro();
	AntiWine();
	Anticuckoomon();
	CheckRegistry_DiscEnum();
	CheckRdtsc();
	KARMA_MACRO_2

#ifdef _DEBUG
	LPLog->AddLog(0, "Anti virtualize event completed!");
#endif
}

