#pragma once
#include <Windows.h>

extern BOOL __ISLOWER__(__in CHAR* c);
extern BOOL __ISUPPER__(__in CHAR* c);
extern UINT __STRLEN__(__in LPSTR lpStr1);
extern UINT __STRLEN__(__in LPCSTR lpStr1);
extern UINT __STRLENW__(__in LPWSTR lpStr1);
extern LPSTR __STRSTRI__(__in LPSTR lpStr1, __in LPSTR lpStr2);
extern LPCSTR __STRSTRI__(__in LPCSTR lpStr1, __in LPCSTR lpStr2);
extern LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2);
extern INT __STRCMPI__(__in LPSTR lpStr1, __in LPSTR lpStr2);
extern INT __STRCMPI__(__in LPWSTR lpStr1, __in LPWSTR lpStr2);
extern INT __STRCMPI__(__in LPCSTR lpStr1, __in LPCSTR lpStr2);
extern INT __STRCMPIW__(__in LPCWSTR lpStr1, __in LPCWSTR lpStr2);
extern INT __STRNCMPI__(__in LPSTR lpStr1, __in LPSTR lpStr2, __in DWORD dwLen);
extern INT __STRNCMPIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2, __in DWORD dwLen);
extern LPSTR __STRCAT__(__in LPSTR	strDest, __in LPSTR strSource);
extern LPWSTR __STRCATW__(__in LPWSTR strDest, __in LPWSTR strSource);
extern DWORD GetStringHash(__in LPVOID lpBuffer, __in BOOL bUnicode, __in UINT uLen);


typedef HMODULE(WINAPI *LOADLIBRARYA)(__in LPCSTR lpFileName);
typedef LOADLIBRARYA *PLOADLIBRARYA;
typedef FARPROC(WINAPI *GETPROCADDRESS)(__in HMODULE hModule, __in LPCSTR lpProcName);
typedef GETPROCADDRESS *PGETPROCADDRESS;
typedef HMODULE(WINAPI *GETMODULEHANDLEA)(_In_opt_ LPCTSTR lpModuleName);
typedef GETMODULEHANDLEA *PGETMODULEHANDLEA;

typedef struct _VTABLE
{
	GETPROCADDRESS GetProcAddress;
	LOADLIBRARYA LoadLibraryA;
	GETMODULEHANDLEA GetModuleHandleA;
} VTABLE, *PVTABLE;

class BasePointers {
	public:
		HANDLE GetKernel32Handle();

		BOOL GetPointers(
			PGETPROCADDRESS fpGetProcAddress,
			PLOADLIBRARYA fpLoadLibraryA,
			PGETMODULEHANDLEA fpGetModuleHandleA);

		BOOL GetBasePointers(__out PVTABLE lpTable);
};
