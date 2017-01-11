#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "Access.h"
#include "CLog.h"
#include "Threads.h"


typedef struct _module_info
{
	std::wstring wszModuleName;
	PVOID lpDllBase;
	PVOID lpEntryPoint;
	DWORD dwSizeOfImage;
	DWORD dwCheckSum;
	DWORD dwTimeStamp;
} SModuleInfo, *PModuleInfo;


PLDR_DATA_TABLE_ENTRY GetNextNode(PCHAR nNode, int Offset)
{
	nNode -= sizeof(LIST_ENTRY) * Offset;
	return (PLDR_DATA_TABLE_ENTRY)nNode;
}

void CheckModule(PModuleInfo mod_info)
{
	printf("%p-%p(%p) %ld %ld\n'%ls'\n",
		mod_info->lpDllBase, mod_info->lpEntryPoint, (LPVOID)mod_info->dwSizeOfImage,
		mod_info->dwCheckSum, mod_info->dwTimeStamp,
		mod_info->wszModuleName.c_str()
	);
}

void CScan::ScanModules()
{
	std::wstring wszFullDllName;
	PROCESS_BASIC_INFORMATION PBI = { 0 };

	if (NT_SUCCESS(BetaFunctionTable->NtQueryInformationProcess(NtCurrentProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), NULL)))
	{
		LDR_DATA_TABLE_ENTRY LdrModule;
		PPEB_LDR_DATA pLdrData = nullptr;

		PBYTE LdrDataOffset = (PBYTE)(PBI.PebBaseAddress) + offsetof(struct _PEB, Ldr);
		BetaFunctionTable->ReadProcessMemory(NtCurrentProcess, LdrDataOffset, &pLdrData, sizeof(PPEB_LDR_DATA), NULL);


		PEB_LDR_DATA LdrData;
		BetaFunctionTable->ReadProcessMemory(NtCurrentProcess, pLdrData, &LdrData, sizeof(PEB_LDR_DATA), NULL);


		PBYTE address = (PBYTE)LdrData.InMemoryOrderModuleList.Flink;
		address -= sizeof(LIST_ENTRY) * 1;

		PLDR_DATA_TABLE_ENTRY Head = (PLDR_DATA_TABLE_ENTRY)address;
		PLDR_DATA_TABLE_ENTRY Node = Head;


		do
		{
			if (BetaFunctionTable->ReadProcessMemory(NtCurrentProcess, Node, &LdrModule, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
			{

				wszFullDllName = std::wstring(LdrModule.FullDllName.Length / sizeof(WCHAR), 0);
				BetaFunctionTable->ReadProcessMemory(NtCurrentProcess, LdrModule.FullDllName.Buffer, &wszFullDllName[0], LdrModule.FullDllName.Length, NULL);

				wszFullDllName.push_back('\0');


				SModuleInfo modInfo;
				modInfo.lpDllBase = LdrModule.DllBase;
				modInfo.lpEntryPoint = LdrModule.EntryPoint;
				modInfo.dwSizeOfImage = LdrModule.SizeOfImage;
				modInfo.dwCheckSum = LdrModule.CheckSum;
				modInfo.dwTimeStamp = LdrModule.TimeDateStamp;
				modInfo.wszModuleName = wszFullDllName;

				CheckModule(&modInfo);
			}

			Node = GetNextNode((PCHAR)LdrModule.InMemoryOrderLinks.Flink, 1);
		} while (Head != Node);
	}
}

