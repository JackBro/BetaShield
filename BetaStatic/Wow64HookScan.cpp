#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"

#include "BasePointers.h"
#include "CLog.h"


inline wchar_t* GetBaseName(wchar_t* string)
{
	KARMA_MACRO_2
	unsigned long i = __STRLENW__(string);
	KARMA_MACRO_1
	while (string[i - 1] != '\\') i--;
	KARMA_MACRO_1
	return &string[i];
}

unsigned short cs_ = 0;
unsigned char* WOW32Reserved = 0;
unsigned long PEB64 = 0;
__forceinline void GetWow32ReservedInfo()
{
	__asm
	{
		pushad
			mov eax, dword ptr fs : [0xC0]
			mov WOW32Reserved, eax
			mov eax, dword ptr fs : [0x30]
			add eax, 0x1000
			mov PEB64, eax
			mov cs_, cs
			popad
	}
}

__forceinline bool Wow32ReservedIsHooked()
{
	KARMA_MACRO_2
	bool bIsHooked = false;

	if (LPFunctions->IsSysWow64() == false) {
#ifdef _DEBUG
		LPLog->AddLog(0, "IsSysWow64 returned as false, Skipped Wow32reserved hook check");
#endif
		return bIsHooked;
	}

	KARMA_MACRO_1

	GetWow32ReservedInfo();
	KARMA_MACRO_1

	if (!WOW32Reserved){
#ifdef _DEBUG
		LPLog->AddLog(0, "WOW32Reserved returned as false, Skipped Wow32reserved hook check");
#endif
		return bIsHooked;  //not 64-bit system
	}

	KARMA_MACRO_1
	if ((*WOW32Reserved == 0xEA) && (*(unsigned short*)(WOW32Reserved + 5) != cs_))
	{
		KARMA_MACRO_2
		unsigned long CpupReturnFromSimulatedCode = *(unsigned long*)(WOW32Reserved + 1);
		MEMORY_BASIC_INFORMATION MBI = { 0 };
		BetaFunctionTable->VirtualQuery((void*)CpupReturnFromSimulatedCode, &MBI, sizeof(MBI));

		KARMA_MACRO_1
		if (MBI.Type == MEM_IMAGE)
		{
			KARMA_MACRO_1
			char* p = (char*)BetaFunctionTable->LocalAlloc(LMEM_ZEROINIT, 0x1000);
			if (NT_SUCCESS(BetaFunctionTable->NtQueryVirtualMemory(NtCurrentProcess, (void*)CpupReturnFromSimulatedCode, MemoryMappedFilenameInformation /*filename*/, p, 0x1000, 0) >= 0))
			{
				if (((UNICODE_STRING*)p)->Length)
				{
					WCHAR __wow64cpu[] { L'w', L'o', L'w', L'6', L'4', L'c', L'p', L'u', L'.', L'd', L'l', L'l', L'\0' };
					if (lstrcmpiW(__wow64cpu, GetBaseName(((UNICODE_STRING*)p)->Buffer)) == 0)
					{
						KARMA_MACRO_2
						BetaFunctionTable->LocalFree(p);
						return bIsHooked; // not hooked
					}
				}
			}
			KARMA_MACRO_2
			BetaFunctionTable->LocalFree(p);
		}
	}

	KARMA_MACRO_1
	return bIsHooked; // hooked
}


void CScan::AntiWow32ReservedHook()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "AntiWow32ReservedHook event started!");
#endif

	KARMA_MACRO_2
	if (Wow32ReservedIsHooked()) {
		CHAR warn[] = { 'F', 'a', 't', 'a', 'l', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'o', 'n', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'i', 'n', 'i', 't', 'i', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'c', 'o', 'd', 'e', ':', ' ', '8', 0x0 }; // Fatal Error on process initilization! Error code: 8
		LPFunctions->CloseProcess(warn, false, "");
	}
	KARMA_MACRO_1

#ifdef _DEBUG
	LPLog->AddLog(0, "AntiWow32ReservedHook event completed!");
#endif
}
