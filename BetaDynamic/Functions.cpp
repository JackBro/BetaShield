#include "main.h"
#include "Functions.h"


__declspec(naked) PLDR_DATA_ENTRY GetLdrDataEntry() {
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax + 0x0C]
			mov eax, [eax + 0x1C]
			retn
	}
}
inline PPEB_DUMMY __declspec(naked) GetPEB(void)
{
	_asm
	{
		mov eax, fs:[0x30];
		retn;
	}
}

bool CFunctions::CreateInfoData(PANTI_MODULE_INFO pami, HMODULE hModule)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->LoaderData->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->LoaderData->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if ((PVOID)hModule == Current->DllBase)
		{			
			pami->BaseAddress = Current->DllBase;
			pami->EntryPoint = Current->EntryPoint;
			pami->SizeOfImage = Current->SizeOfImage;

			pami->BaseDllName.Buffer = Current->BaseDllName.Buffer;
			pami->BaseDllName.Length = Current->BaseDllName.Length;
			pami->BaseDllName.MaximumLength = Current->BaseDllName.MaximumLength;

			pami->FullDllName.Buffer = Current->FullDllName.Buffer;
			pami->FullDllName.Length = Current->FullDllName.Length;
			pami->FullDllName.MaximumLength = Current->FullDllName.MaximumLength;
			return true;
		}

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}

void CFunctions::DestroyIAT(HMODULE hModule)
{
	PIMAGE_THUNK_DATA pFirstThunkMirror, pOrigThunkMirror;

	IMAGE_DOS_HEADER* pDOS = (IMAGE_DOS_HEADER *)hModule;
	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS *)(hModule + pDOS->e_lfanew);

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		IMAGE_IMPORT_DESCRIPTOR* pIID = (PIMAGE_IMPORT_DESCRIPTOR)(hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pIID->Characteristics)
		{
			pOrigThunkMirror = (PIMAGE_THUNK_DATA)(hModule + pIID->OriginalFirstThunk);
			pFirstThunkMirror = (PIMAGE_THUNK_DATA)(hModule + pIID->FirstThunk);

			pFirstThunkMirror->u1.Function = 0;
			pFirstThunkMirror->u1.AddressOfData = 0;
			pFirstThunkMirror->u1.Ordinal = 0;

			while (pOrigThunkMirror->u1.AddressOfData)
			{
				pOrigThunkMirror->u1.Function = 0;
				pOrigThunkMirror->u1.AddressOfData = 0;
				pOrigThunkMirror->u1.Ordinal = 0;

				pOrigThunkMirror++;
				pFirstThunkMirror++;
			}

			pIID++;
		}
		
		pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	}
}

void CFunctions::DestroySections(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(hModule + pImageDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pImageSectionHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

	for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; ++i)
	{
		pImageSectionHeader[i].VirtualAddress = 0;
		pImageSectionHeader[i].SizeOfRawData = 0;
		pImageSectionHeader[i].PointerToRelocations = 0;
		pImageSectionHeader[i].Misc.PhysicalAddress = 0;
		pImageSectionHeader[i].Misc.VirtualSize = 0;
	}
}

DWORD CFunctions::HideModuleLinks(HMODULE Base)
{
	PLDR_DATA_ENTRY cursor = GetLdrDataEntry();
	DWORD ret = 1;

	while (cursor->BaseAddress)
	{
		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
		if (cursor->BaseAddress == Base)
		{
			PLDR_DATA_ENTRY prev = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Blink;
			cursor->BaseDllName = prev->BaseDllName;
			cursor->FullDllName = prev->FullDllName;

			cursor->SizeOfImage = 0;
			cursor->EntryPoint = 0;
		}

		ret++;
	}

	return ret;
}

void CFunctions::AddToLog(const char* cArgFormat, ...)
{
	char cTmpString[2000];
	CHAR _Filename[] = { 's', 'y', 's', 'e', 'r', 'r', '2', '.', 't', 'x', 't', 0x0 };

	va_list vaArgList;
	va_start(vaArgList, cArgFormat);
	wvsprintfA(cTmpString, cArgFormat, vaArgList);
	va_end(vaArgList);

#ifdef _DEBUG
	OutputDebugStringA(cTmpString);

	char cTmpStr[1024];
	sprintf(cTmpStr, "%s\n", cTmpString);
	fputs(cTmpStr, stdout);
#endif

#if 0
	time_t ct = time(0);
	struct tm ctm = *localtime(&ct);

	CHAR __timeformat[] = { '%', '0', '2', 'd', ':', '%', '0', '2', 'd', ':', '%', '0', '2', 'd', ' ', '-', ' ', '%', '0', '2', 'd', ':', '%', '0', '2', 'd', ':', '%', 'd', ' ', ':', ':', ' ', 0x0 }; // %02d:%02d:%02d - %02d:%02d:%d :: 
	char cTimeBuf[1250];
	sprintf(cTimeBuf, __timeformat,
		ctm.tm_hour,
		ctm.tm_min,
		ctm.tm_sec,
		ctm.tm_mday,
		ctm.tm_mon + 1,
		1900 + ctm.tm_year);
#endif

	std::ofstream f(_Filename, std::ofstream::out | std::ofstream::app);
	f << /* cTimeBuf << */ cTmpString << '\n' << std::endl;
	f.close();
}
