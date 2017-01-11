#include "BasePointers.h"
#include <Windows.h>
#include <winternl.h>
#include "XOR.h"

#define CONTAINING_RECORD(address, type, field) ((type *)( (PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))

BOOL __ISLOWER(__in CHAR c) { return ('a' <= c) && (c <= 'z'); };
BOOL __ISLOWER__(__in CHAR* c) {
	int iCount = 0;
	for (size_t i = 0; i <= strlen(c); i++)
		iCount += __ISLOWER(c[i]);
	return iCount == 0;
}
BOOL __ISLOWERW(__in WCHAR c) { return (L'a' <= c) && (c <= L'z'); };
BOOL __ISLOWERW__(__in WCHAR* c) {
	int iCount = 0;
	for (int i = 0; i <= lstrlenW(c); i++)
		iCount += __ISLOWERW(c[i]);
	return iCount == 0;
}

BOOL __ISUPPER(__in CHAR c) { return ('A' <= c) && (c <= 'Z'); };
BOOL __ISUPPER__(__in CHAR* c) {
	int iCount = 0;
	for (size_t i = 0; i <= strlen(c); i++)
		iCount += __ISUPPER(c[i]);
	return iCount == 0;
}
BOOL __ISUPPERW(__in WCHAR c) { return (L'A' <= c) && (c <= L'Z'); };
BOOL __ISUPPERW__(__in WCHAR* c) {
	int iCount = 0;
	for (int i = 0; i <= lstrlenW(c); i++)
		iCount += __ISUPPERW(c[i]);
	return iCount == 0;
}

CHAR __TOLOWER__(__in CHAR c) { return __ISUPPER(c) ? c - 'A' + 'a' : c; };
CHAR __TOLOWERW__(__in WCHAR c) { return __ISUPPERW(c) ? c - L'A' + L'a' : c; };
CHAR __TOUPPER__(__in CHAR c) { return __ISLOWER(c) ? c - 'a' + 'A' : c; };

UINT __STRLEN__(__in LPSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != 0x0)
		i++;

	return i;
}
UINT __STRLEN__(__in LPCSTR lpStr1)
{
	return __STRLEN__((LPSTR)lpStr1);
}

UINT __STRLENW__(__in LPWSTR lpStr1)
{
	UINT i = 0;
	while (lpStr1[i] != L'\0')
		i++;

	return i;
}

LPSTR __STRSTRI__(__in LPSTR lpStr1, __in LPSTR lpStr2)
{
	CHAR c = __TOLOWER__((lpStr2++)[0]);
	if (!c)
		return lpStr1;

	UINT dwLen = __STRLEN__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__((lpStr1++)[0]);
			if (!sc)
				return NULL;
		} while (sc != c);
	} while (__STRNCMPI__(lpStr1, lpStr2, dwLen) != 0);

	return (lpStr1 - 1); // FIXME: -0?
}

LPCSTR __STRSTRI__(__in LPCSTR lpStr1, __in LPCSTR lpStr2)
{
	return (LPCSTR)__STRSTRI__((LPSTR)lpStr1, (LPSTR)lpStr2);
}

LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
{
	CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
	if (!c)
		return lpStr1;

	UINT dwLen = __STRLENW__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
			if (!sc)
				return NULL;
		} while (sc != c);
	} while (__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);

	return (lpStr1 - 1); // FIXME -2 ?
}

INT __STRCMPI__(
	__in LPSTR lpStr1,
	__in LPSTR lpStr2)
{
	int  v;
	CHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
	return v;
}

INT __STRCMPI__(
	__in LPCSTR lpStr1,
	__in LPCSTR lpStr2)
{
	return __STRCMPI__((LPSTR)lpStr1, (LPSTR)lpStr2);
}

INT __STRCMPIW__(
	__in LPWSTR lpStr1,
	__in LPWSTR lpStr2)
{
	int  v;
	WCHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT)__TOLOWERW__(c1) - (UINT)__TOLOWERW__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0'));
	return v;
}

INT __STRCMPIW__(
	__in LPCWSTR lpStr1,
	__in LPCWSTR lpStr2)
{
	return __STRCMPIW__((LPWSTR)lpStr1, (LPWSTR)lpStr2);
}

INT __STRNCMPI__(
	__in LPSTR lpStr1,
	__in LPSTR lpStr2,
	__in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do
	{
		dwLen--;
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != '\0') && (c2 != '\0') && dwLen > 0);
	return v;
}

INT __STRNCMPIW__(
	__in LPWSTR lpStr1,
	__in LPWSTR lpStr2,
	__in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do {
		dwLen--;
		c1 = ((PCHAR)lpStr1++)[0];
		c2 = ((PCHAR)lpStr2++)[0];
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT)__TOLOWER__(c1) - (UINT)__TOLOWER__(c2);
	} while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);

	return v;
}

LPSTR __STRCAT__(
	__in LPSTR	strDest,
	__in LPSTR strSource)
{
	LPSTR d = strDest;
	LPSTR s = strSource;

	while (*d) d++;

	do { *d++ = *s++; } while (*s);
	*d = 0x0;

	return strDest;
}


LPWSTR __STRCATW__(
	__in LPWSTR	strDest,
	__in LPWSTR strSource)
{
	LPWSTR d = strDest;
	LPWSTR s = strSource;

	while (*d != L'\0') d++;
	do { *d++ = *s++; } while (*s != L'\0');
	*d = L'\0';

	return strDest;
}

DWORD GetStringHash(
	__in LPVOID lpBuffer,
	__in BOOL bUnicode,
	__in UINT uLen)
{
	DWORD dwHash = 0;
	LPSTR strBuffer = (LPSTR)lpBuffer;

	while (uLen--)
	{
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += (DWORD)*strBuffer++;

		if (bUnicode)
			strBuffer++;
	}
	return dwHash;
}

HANDLE BasePointers::GetKernel32Handle()
{
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
	PPEB lpPeb = (PPEB)__readfsdword(0x30);

	PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;

	while (pListEntry != pListHead)
	{
		PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (pModEntry->FullDllName.Length)
		{
			DWORD dwLen = pModEntry->FullDllName.Length;
			PWCHAR strName = (pModEntry->FullDllName.Buffer + (dwLen / sizeof(WCHAR))) - 13;

			if (GetStringHash(strName, TRUE, 13) == 0x8fecdbff || GetStringHash(strName, TRUE, 13) == 0x6e2bcfd7 || GetStringHash(strName, TRUE, 13) == 0x6f2bd7f7)
			{
				hKernel32 = pModEntry->DllBase;
				break;
			}
		}
		pListEntry = pListEntry->Flink;
	}

	return hKernel32;
}

BOOL BasePointers::GetPointers(
	__out PGETPROCADDRESS fpGetProcAddress,
	__out PLOADLIBRARYA fpLoadLibraryA,
	__out PGETMODULEHANDLEA fpGetModuleHandleA
	)
{
	HANDLE hKernel32 = GetKernel32Handle();
	if (hKernel32 == INVALID_HANDLE_VALUE)
		return FALSE;

	LPBYTE lpBaseAddr = (LPBYTE)hKernel32;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER)lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)(lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD)(lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray = (LPWORD)(lpBaseAddr + pExportDir->AddressOfNameOrdinals);

	*fpGetProcAddress = NULL;
	*fpLoadLibraryA = NULL;
	*fpGetModuleHandleA = NULL;


	CHAR strLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0 };
	CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };
	CHAR strGetModuleHandleA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0 };

	for (UINT i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPSTR pFuncName = (LPSTR)(lpBaseAddr + pNameArray[i]);

		if (!__STRCMPI__(pFuncName, XOR(strGetProcAddress)))
			*fpGetProcAddress = (GETPROCADDRESS)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		else if (!__STRCMPI__(pFuncName, XOR(strLoadLibraryA)))
			*fpLoadLibraryA = (LOADLIBRARYA)(lpBaseAddr + pAddrArray[pOrdArray[i]]);
		else if (!__STRCMPI__(pFuncName, XOR(strGetModuleHandleA)))
			*fpGetModuleHandleA = (GETMODULEHANDLEA)(lpBaseAddr + pAddrArray[pOrdArray[i]]);

		if (*fpGetProcAddress && *fpLoadLibraryA && *fpGetModuleHandleA)
			return TRUE;
	}

	return FALSE;
}

BOOL BasePointers::GetBasePointers(__out PVTABLE lpTable) {
	if (!GetPointers(&lpTable->GetProcAddress, &lpTable->LoadLibraryA, &lpTable->GetModuleHandleA))
		return FALSE;
	return TRUE;
}

