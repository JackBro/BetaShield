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
		}

		ret++;
	}

	return ret;
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

