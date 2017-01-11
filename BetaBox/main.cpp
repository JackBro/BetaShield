#include "main.h"
#include "..\BetaStatic\XOR.h"

typedef DWORD(WINAPI* lpGetLastError)(void);
lpGetLastError _GetLastError;
typedef BOOL(WINAPI* lpCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
lpCreateProcessA _CreateProcessA;
typedef HANDLE(WINAPI* lpCreateFile)(__in LPCSTR lpFileName, __in DWORD dwDesiredAccess, __in DWORD dwShareMode, __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in DWORD dwCreationDisposition, __in DWORD dwFlagsAndAttributes, __in_opt HANDLE hTemplateFile);
lpCreateFile _CreateFileA;
typedef DWORD(WINAPI* lpGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
lpGetFileSize _GetFileSize;
typedef LPVOID(WINAPI* lpVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
lpVirtualAlloc _VirtualAlloc;
typedef BOOL(WINAPI* lpReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
lpReadFile _ReadFile;
typedef NTSTATUS(NTAPI* lpNtClose)(HANDLE);
lpNtClose _NtClose;
typedef NTSTATUS(NTAPI* lpNtGetContextThread)(IN HANDLE ThreadHandle, OUT PCONTEXT pContext);
lpNtGetContextThread _NtGetContextThread;
typedef NTSTATUS(NTAPI* lpNtSetContextThread)(IN HANDLE ThreadHandle, IN PCONTEXT ThreadContext);
lpNtSetContextThread _NtSetContextThread;
typedef NTSTATUS(NTAPI* lpNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
lpNtReadVirtualMemory _NtReadVirtualMemory;
typedef NTSTATUS(NTAPI* lpNtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
lpNtWaitForSingleObject _NtWaitForSingleObject;
typedef LONG(WINAPI* lpNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
lpNtUnmapViewOfSection _NtUnmapViewOfSection;
typedef NTSTATUS(NTAPI* lpNtWriteVirtualMemory)(HANDLE, PVOID, CONST VOID *, SIZE_T, PSIZE_T);
lpNtWriteVirtualMemory _NtWriteVirtualMemory;
typedef NTSTATUS(NTAPI* lpNtResumeThread)(IN HANDLE ThreadHandle, OUT PULONG SuspendCount OPTIONAL);
lpNtResumeThread _NtResumeThread;
typedef NTSTATUS(NTAPI* lpNtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
lpNtTerminateProcess _NtTerminateProcess;
typedef NTSTATUS(NTAPI* lpRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
lpRtlAdjustPrivilege _RtlAdjustPrivilege;



void BindFunctionTable()
{
	int iErrCode = 0;


	_GetLastError = (lpGetLastError)GetProcAddress(GetModuleHandleA("kernel32.dll"), XOR("GetLastError"));
	if (!_GetLastError)
		iErrCode = 1;

	_CreateProcessA = (lpCreateProcessA)GetProcAddress(GetModuleHandleA("kernel32.dll"), XOR("CreateProcessA"));
	if (!_CreateProcessA)
		iErrCode = 2;

	_CreateFileA = (lpCreateFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), XOR("CreateFileA"));
	if (!_CreateFileA)
		iErrCode = 3;

	_GetFileSize = (lpGetFileSize)GetProcAddress(GetModuleHandleA("kernel32.dll"), XOR("GetFileSize"));
	if (!_GetFileSize)
		iErrCode = 4;

	_VirtualAlloc = (lpVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), XOR("VirtualAlloc"));
	if (!_VirtualAlloc)
		iErrCode = 5;

	_ReadFile = (lpReadFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), XOR("ReadFile"));
	if (!_ReadFile)
		iErrCode = 6;

	_NtClose = (lpNtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtClose"));
	if (!_NtClose)
		iErrCode = 7;

	_NtGetContextThread = (lpNtGetContextThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtGetContextThread"));
	if (!_NtGetContextThread)
		iErrCode = 8;

	_NtSetContextThread = (lpNtSetContextThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtSetContextThread"));
	if (!_NtSetContextThread)
		iErrCode = 9;

	_NtReadVirtualMemory = (lpNtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtReadVirtualMemory"));
	if (!_NtReadVirtualMemory)
		iErrCode = 10;

	_NtWaitForSingleObject = (lpNtWaitForSingleObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtWaitForSingleObject"));
	if (!_NtWaitForSingleObject)
		iErrCode = 11;

	_NtUnmapViewOfSection = (lpNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtUnmapViewOfSection"));
	if (!_NtUnmapViewOfSection)
		iErrCode = 12;

	_NtWriteVirtualMemory = (lpNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtWriteVirtualMemory"));
	if (!_NtWriteVirtualMemory)
		iErrCode = 13;

	_NtResumeThread = (lpNtResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtResumeThread"));
	if (!_NtResumeThread)
		iErrCode = 14;

	_NtTerminateProcess = (lpNtTerminateProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("NtTerminateProcess"));
	if (!_NtTerminateProcess)
		iErrCode = 15;

	_RtlAdjustPrivilege = (lpRtlAdjustPrivilege)GetProcAddress(GetModuleHandleA("ntdll.dll"), XOR("RtlAdjustPrivilege"));
	if (!_RtlAdjustPrivilege)
		iErrCode = 16;


	if (iErrCode) {
		CHAR __warn[] = { 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'A', 'P', 'I', ' ', 'c', 'a', 'l', 'l', ' ', 'f', 'a', 'i', 'l', 'e', 'd', '!', ' ', 'E', 'r', 'r', 'o', 'r', ' ', 'C', 'o', 'd', 'e', ':', ' ', '%', 'd', 0x0 }; // Windows API call failed! Error Code: %d

		char cTmpStr[1024];
		sprintf(cTmpStr, __warn, iErrCode);

		std::ofstream f("syserr2.txt", std::ofstream::out | std::ofstream::app);
		f << cTmpStr << XOR("\n") << std::endl;
		f.close();

		MessageBoxA(0, cTmpStr, 0, 0);
		ExitProcess(EXIT_SUCCESS);
	}
}


HANDLE hChildProcessHandle = nullptr;
DWORD dwLastError = 0;

__forceinline void Initialize(LPSTR from, LPSTR to)
{
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	
	HANDLE hFile = CreateFileA(to, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); // Open the replacement executable
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	DWORD dwSizeOfFile = GetFileSize(hFile, NULL);
	if (dwSizeOfFile == INVALID_FILE_SIZE)
		return;

	LPVOID lpMemory = VirtualAlloc(NULL, dwSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dwLastError)
		return;

	DWORD dwReadedNumberOfBytes = 0;
	if (!ReadFile(hFile, lpMemory, dwSizeOfFile, &dwReadedNumberOfBytes, NULL))
		return;

	if (!NT_SUCCESS(_NtClose(hFile)))
		return;


	PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;
	PIMAGE_SECTION_HEADER ISH;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	PCONTEXT CTX;
	PDWORD dwImageBase;
	LPVOID pImageBase;
	int Count;
	IDH = PIMAGE_DOS_HEADER(lpMemory);

	if (IDH->e_magic != IMAGE_DOS_SIGNATURE)
		goto skip;

	INH = PIMAGE_NT_HEADERS(DWORD(lpMemory) + IDH->e_lfanew);
	if (INH->Signature != IMAGE_NT_SIGNATURE)
		goto skip;
	
	RtlZeroMemory(&SI, sizeof(SI));
	RtlZeroMemory(&PI, sizeof(PI));
	if (!CreateProcessA(from, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
		goto skip;
	
	CTX = PCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
	CTX->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
		goto skip;
	
	ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&dwImageBase), 4, NULL);
	if (DWORD(dwImageBase) == INH->OptionalHeader.ImageBase)
		_NtUnmapViewOfSection(PI.hProcess, PVOID(dwImageBase));

	pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(INH->OptionalHeader.ImageBase), INH->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
	if (!pImageBase)
		goto skip;
	
	WriteProcessMemory(PI.hProcess, pImageBase, lpMemory, INH->OptionalHeader.SizeOfHeaders, NULL);
	for (Count = 0; Count < INH->FileHeader.NumberOfSections; Count++)
	{
		ISH = PIMAGE_SECTION_HEADER(DWORD(lpMemory) + IDH->e_lfanew + 248 + (Count * 40));
		WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + ISH->VirtualAddress), LPVOID(DWORD(lpMemory) + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
	}

	WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&INH->OptionalHeader.ImageBase), 4, NULL);
	CTX->Eax = DWORD(pImageBase) + INH->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(PI.hThread, LPCONTEXT(CTX));

skip:
	VirtualFree(lpMemory, 0, MEM_RELEASE);
	ResumeThread(PI.hThread);
}


int main(int argc, char** argv)
{
	BindFunctionTable();

	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);

	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	std::string szPath = std::string(buffer).substr(0, pos);

	if (argc < 2) {
		CHAR __targetwarn[] = { 'T', 'a', 'r', 'g', 'e', 't', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', ' ', 'c', 'a', 'n', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', '!', 0x0 }; // Target process can not found!

		std::ofstream f("syserr2.txt", std::ofstream::out | std::ofstream::app);
		f << __targetwarn << XOR("\n") << std::endl;
		f.close();

		MessageBoxA(0, __targetwarn, 0, 0);
		ExitProcess(EXIT_SUCCESS);
	}


	BOOLEAN boAdjustPrivRet;
	NTSTATUS ntStat = _RtlAdjustPrivilege(20, TRUE, FALSE, &boAdjustPrivRet);
	if (!NT_SUCCESS(ntStat)) {
		CHAR __accesswarn[] = { 'S', 'e', 'l', 'f', ' ', 'a', 'c', 'c', 'e', 's', 's', ' ', 'a', 'd', 'j', 'u', 's', 't', ' ', 'f', 'a', 'i', 'l', '!', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'r', 'u', 'n', ' ', 'a', 's', ' ', 'a', 'd', 'm', 'i', 'n', 'i', 's', 't', 'r', 'a', 't', 'o', 'r', 0x0 }; // Self access adjust fail! Please run as administrator

		std::ofstream f("syserr2.txt", std::ofstream::out | std::ofstream::app);
		f << __accesswarn << XOR("\n") << std::endl;
		f.close();

		MessageBoxA(0, __accesswarn, 0, 0);
		ExitProcess(EXIT_SUCCESS);
	}


	std::string szFrom = buffer;
	std::string sTarget = argv[1];
	std::string szTo = szPath + "\\" + sTarget;

	Initialize((char*)szFrom.c_str(), (char*)szTo.c_str());


	return 0;
}

