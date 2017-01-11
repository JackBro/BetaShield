#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#pragma warning(disable: 4091)
#include <Windows.h>
#include <windowsx.h>
#include <iostream>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <conio.h>
#include <sys/stat.h>
#include <Vector>
#include <cstdlib>
#include <sddl.h>
#include <Locale>
#include <Sstream>
#include <cstring>
#include <stdio.h>
#include "AccCtrl.h"
#include "Aclapi.h"
#include <algorithm>
#include <Psapi.h>
#include <assert.h>
#include <intrin.h>
#include <excpt.h>
#include <Iphlpapi.h>
#include <algorithm>
#include <comdef.h>
#include <ShlObj.h>
#include <mscat.h>
#include <crtdbg.h>
#include <WinTrust.h>
#include <DbgHelp.h>
#include <io.h>
#include <mutex>
#include <WinInet.h>
#include <memory>
#include "ProtectorSupport.h"
#include <gdiplus.h>
#include <wbemidl.h>
#include <atlbase.h>
#include <ShellAPI.h>
#include <winevt.h>


using namespace std;
using namespace Gdiplus;

#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#define STATUS_RESOURCE_NAME_NOT_FOUND   ((NTSTATUS)0xC000008B)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)
#define STATUS_NOT_ALL_ASSIGNED          ((NTSTATUS)0x00000106L)
#define NT_SUCCESS(Status)			(((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define ACCESS_DENIED				(NTSTATUS)0xC0000022
#define NtCurrentProcess			((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread				((HANDLE)(LONG_PTR)-2)

#define ISOLATIONAWARE_MANIFEST_RESOURCE_ID_W ((LPWSTR)((ULONG_PTR)((WORD)(2))))
#define ISOLATIONAWARE_MANIFEST_RESOURCE_ID_A ((LPSTR)((ULONG_PTR)((WORD)(2))))


#define DIRECTORY_QUERY           (0x0001)
#define OBJ_CASE_INSENSITIVE    0x00000040L

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


#include "NktHookLib.h"
#define sprintf(lpDest, szFormatA, ...)			NktHookLibHelpers::sprintf_s(lpDest, 8192, szFormatA, __VA_ARGS__)
#define vsnprintf(lpDest, szFormatA, lpArgList)	NktHookLibHelpers::vsnprintf(lpDest, 8192, szFormatA, lpArgList)

#define nkt_malloc(nSize)						NktHookLibHelpers::MemAlloc(nSize)
#define nkt_mfree(lpPtr)						NktHookLibHelpers::MemFree(lpPtr)

#define nkt_memset(lpDest, nVal, nCount)		NktHookLibHelpers::MemSet(lpDest, nVal, nCount)
#define nkt_memcopy(lpDest, lpSrc, nCount)		NktHookLibHelpers::MemCopy(lpDest, lpSrc, nCount)
#define nkt_memmove(lpDest, lpSrc, nCount)		NktHookLibHelpers::MemMove(lpDest, lpSrc, nCount)
#define nkt_memcmp(lpBuf1, lpBuf2, nCount)		NktHookLibHelpers::MemCompare(lpBuf1, lpBuf2, nCount)


/* struct list */
namespace {
	typedef LONG KPRIORITY;

	enum EGameCodes {
		TEST_CONSOLE = 999,
		METIN2_GAME = 1903,
	};

	enum SECTION_INHERIT
	{
		ViewShare = 1,
		ViewUnmap = 2
	};

	typedef struct WSAData2 {
		WORD                    wVersion;
		WORD                    wHighVersion;
		char                    szDescription[256 + 1];
		char                    szSystemStatus[128 + 1];
		unsigned short          iMaxSockets;
		unsigned short          iMaxUdpDg;
		char FAR *              lpVendorInfo;
	} WSADATA2, FAR * LPWSADATA2;

	enum {
		MEM_EXECUTE_OPTION_DISABLE = 0x01,
		MEM_EXECUTE_OPTION_ENABLE = 0x02,
		MEM_EXECUTE_OPTION_PERMANENT = 0x08
	};

	struct handle_data {
		unsigned long process_id;
		HWND best_handle;
	};

	typedef struct _UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _module_info {
		PVOID                   BaseAddress;
		PVOID                   EntryPoint;
		ULONG                   SizeOfImage;
		UNICODE_STRING          FullDllName;
		UNICODE_STRING          BaseDllName;
	} ANTI_MODULE_INFO, *PANTI_MODULE_INFO;

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
	typedef struct _PEB_LDR_DATA
	{
		ULONG           Length;
		BOOLEAN         Initialized;
		PVOID           SsHandle;
		LIST_ENTRY      InLoadOrderModuleList;
		LIST_ENTRY      InMemoryOrderModuleList;
		LIST_ENTRY      InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;
	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
	} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
	typedef struct _PEB {
		BYTE                          Reserved1[2];
		BYTE                          BeingDebugged;
		BYTE                          Reserved2[1];
		PVOID                         Reserved3[2];
		PPEB_LDR_DATA                 Ldr;
		PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
		BYTE                          Reserved4[104];
		PVOID                         Reserved5[52];
		/* PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;*/
		BYTE                          Reserved6[128];
		PVOID                         Reserved7[1];
		ULONG                         SessionId;
	} PEB, *PPEB;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PPEB PebBaseAddress;
		ULONG_PTR AffinityMask;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

	typedef struct _CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef struct RTL_ACTIVATION_CONTEXT_STACK_FRAME*
		PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

	struct RTL_ACTIVATION_CONTEXT_STACK_FRAME
	{
		PRTL_ACTIVATION_CONTEXT_STACK_FRAME Previous;
		_ACTIVATION_CONTEXT* ActivationContext;
		ULONG Flags;
	};

	struct ACTIVATION_CONTEXT_STACK
	{
		PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
		LIST_ENTRY FrameListCache;
		ULONG Flags;
		ULONG NextCookieSequenceNumber;
		ULONG StackId;
	};

	typedef ACTIVATION_CONTEXT_STACK* PACTIVATION_CONTEXT_STACK;

	struct GDI_TEB_BATCH
	{
		ULONG Offset;
		ULONG HDC;
		ULONG Buffer[310];
	};

	struct TEB_ACTIVE_FRAME_CONTEXT
	{
		ULONG Flags;
		CHAR* FrameName;
	};

	typedef TEB_ACTIVE_FRAME_CONTEXT* PTEB_ACTIVE_FRAME_CONTEXT;

	typedef struct TEB_ACTIVE_FRAME* PTEB_ACTIVE_FRAME;

	struct TEB
	{
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		PEB* ProcessEnvironmentBlock;
		ULONG LastErrorValue;
		ULONG CountOfOwnedCriticalSections;
		PVOID CsrClientThread;
		PVOID Win32ThreadInfo;
		ULONG User32Reserved[26];
		ULONG UserReserved[5];
		PVOID WOW32Reserved;
		ULONG CurrentLocale;
		ULONG FpSoftwareStatusRegister;
		VOID* SystemReserved1[54];
		LONG ExceptionCode;
		PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
		UCHAR SpareBytes1[36];
		ULONG TxFsContext;
		GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		PVOID GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		ULONG Win32ClientInfo[62];
		VOID* glDispatchTable[233];
		ULONG glReserved1[29];
		PVOID glReserved2;
		PVOID glSectionInfo;
		PVOID glSection;
		PVOID glTable;
		PVOID glCurrentRC;
		PVOID glContext;
		ULONG LastStatusValue;
		UNICODE_STRING StaticUnicodeString;
		WCHAR StaticUnicodeBuffer[261];
		PVOID DeallocationStack;
		VOID* TlsSlots[64];
		LIST_ENTRY TlsLinks;
		PVOID Vdm;
		PVOID ReservedForNtRpc;
		VOID* DbgSsReserved[2];
		ULONG HardErrorMode;
		VOID* Instrumentation[9];
		GUID ActivityId;
		PVOID SubProcessTag;
		PVOID EtwLocalData;
		PVOID EtwTraceData;
		PVOID WinSockData;
		ULONG GdiBatchCount;
		UCHAR SpareBool0;
		UCHAR SpareBool1;
		UCHAR SpareBool2;
		UCHAR IdealProcessor;
		ULONG GuaranteedStackBytes;
		PVOID ReservedForPerf;
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		PVOID SavedPriorityState;
		ULONG SoftPatchPtr1;
		PVOID ThreadPoolData;
		VOID** TlsExpansionSlots;
		ULONG ImpersonationLocale;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		ULONG HeapVirtualAffinity;
		PVOID CurrentTransactionHandle;
		PTEB_ACTIVE_FRAME ActiveFrame;
		PVOID FlsData;
		PVOID PreferredLanguages;
		PVOID UserPrefLanguages;
		PVOID MergedPrefLanguages;
		ULONG MuiImpersonation;
		WORD CrossTebFlags;
		ULONG SpareCrossTebBits : 16;
		WORD SameTebFlags;
		ULONG DbgSafeThunkCall : 1;
		ULONG DbgInDebugPrint : 1;
		ULONG DbgHasFiberData : 1;
		ULONG DbgSkipThreadAttach : 1;
		ULONG DbgWerInShipAssertCode : 1;
		ULONG DbgRanProcessInit : 1;
		ULONG DbgClonedThread : 1;
		ULONG DbgSuppressDebugMsg : 1;
		ULONG SpareSameTebBits : 8;
		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		ULONG ProcessRundown;
		UINT64 LastSwitchTime;
		UINT64 TotalSwitchOutTime;
		LARGE_INTEGER WaitReasonBitMap;
	};
	typedef enum _THREADINFOCLASS
	{
		ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
		ThreadTimes, // q: KERNEL_USER_TIMES
		ThreadPriority, // s: KPRIORITY
		ThreadBasePriority, // s: LONG
		ThreadAffinityMask, // s: KAFFINITY
		ThreadImpersonationToken, // s: HANDLE
		ThreadDescriptorTableEntry,
		ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
		ThreadEventPair,
		ThreadQuerySetWin32StartAddress, // q: PVOID
		ThreadZeroTlsCell, // 10
		ThreadPerformanceCount, // q: LARGE_INTEGER
		ThreadAmILastThread, // q: ULONG
		ThreadIdealProcessor, // s: ULONG
		ThreadPriorityBoost, // qs: ULONG
		ThreadSetTlsArrayAddress,
		ThreadIsIoPending, // q: ULONG
		ThreadHideFromDebugger, // s: void, BOOLEAN
		ThreadBreakOnTermination, // qs: ULONG
		ThreadSwitchLegacyState,
		ThreadIsTerminated, // 20, q: ULONG
		ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
		ThreadIoPriority, // qs: ULONG
		ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
		ThreadPagePriority, // q: ULONG
		ThreadActualBasePriority,
		ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
		ThreadCSwitchMon,
		ThreadCSwitchPmu,
		ThreadWow64Context, // q: WOW64_CONTEXT
		ThreadGroupInformation, // 30, q: GROUP_AFFINITY
		ThreadUmsInformation,
		ThreadCounterProfiling,
		ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
		ThreadCpuAccountingInformation, // since WIN8
		ThreadSuspendCount, // since WINBLUE
		MaxThreadInfoClass
	} THREADINFOCLASS;
	typedef enum _PROCESSINFOCLASS
	{
		ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
		ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
		ProcessIoCounters, // q: IO_COUNTERS
		ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
		ProcessTimes, // q: KERNEL_USER_TIMES
		ProcessBasePriority, // s: KPRIORITY
		ProcessRaisePriority, // s: ULONG
		ProcessDebugPort, // q: HANDLE
		ProcessExceptionPort, // s: HANDLE
		ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
		ProcessLdtInformation, // 10
		ProcessLdtSize,
		ProcessDefaultHardErrorMode, // qs: ULONG
		ProcessIoPortHandlers, // (kernel-mode only)
		ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
		ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
		ProcessUserModeIOPL,
		ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
		ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
		ProcessWx86Information,
		ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
		ProcessAffinityMask, // s: KAFFINITY
		ProcessPriorityBoost, // qs: ULONG
		ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
		ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
		ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
		ProcessWow64Information, // q: ULONG_PTR
		ProcessImageFileName, // q: UNICODE_STRING
		ProcessLUIDDeviceMapsEnabled, // q: ULONG
		ProcessBreakOnTermination, // qs: ULONG
		ProcessDebugObjectHandle, // 30, q: HANDLE
		ProcessDebugFlags, // qs: ULONG
		ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
		ProcessIoPriority, // qs: ULONG
		ProcessExecuteFlags, // qs: ULONG
		ProcessResourceManagement,
		ProcessCookie, // q: ULONG
		ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
		ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
		ProcessPagePriority, // q: ULONG
		ProcessInstrumentationCallback, // 40
		ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
		ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
		ProcessImageFileNameWin32, // q: UNICODE_STRING
		ProcessImageFileMapping, // q: HANDLE (input)
		ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
		ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
		ProcessGroupInformation, // q: USHORT[]
		ProcessTokenVirtualizationEnabled, // s: ULONG
		ProcessConsoleHostProcess, // q: ULONG_PTR
		ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
		ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
		ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
		ProcessDynamicFunctionTableInformation,
		ProcessHandleCheckingMode,
		ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
		ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
		ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
		ProcessHandleTable, // since WINBLUE
		ProcessCheckStackExtentsMode,
		ProcessCommandLineInformation, // 60, q: UNICODE_STRING
		ProcessProtectionInformation, // q: PS_PROTECTION
		MaxProcessInfoClass
	} PROCESSINFOCLASS;
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
		SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
		SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
		SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
		SystemPathInformation, // not implemented
		SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
		SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
		SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
		SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
		SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
		SystemCallTimeInformation, // 10, not implemented
		SystemModuleInformation, // q: RTL_PROCESS_MODULES
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation, // not implemented
		SystemNonPagedPoolInformation, // not implemented
		SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
		SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
		SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
		SystemVdmInstemulInformation, // q
		SystemVdmBopInformation, // 20, not implemented
		SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
		SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
		SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
		SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
		SystemFullMemoryInformation, // not implemented
		SystemLoadGdiDriverInformation, // s (kernel-mode only)
		SystemUnloadGdiDriverInformation, // s (kernel-mode only)
		SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
		SystemSummaryMemoryInformation, // not implemented
		SystemMirrorMemoryInformation, // 30, s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege)
		SystemPerformanceTraceInformation, // s
		SystemObsolete0, // not implemented
		SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
		SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
		SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
		SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
		SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
		SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
		SystemPrioritySeperation, // s (requires SeTcbPrivilege)
		SystemVerifierAddDriverInformation, // 40, s (requires SeDebugPrivilege)
		SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
		SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
		SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
		SystemCurrentTimeZoneInformation, // q
		SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
		SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
		SystemSessionCreate, // not implemented
		SystemSessionDetach, // not implemented
		SystemSessionInformation, // not implemented
		SystemRangeStartInformation, // 50, q
		SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
		SystemVerifierThunkExtend, // s (kernel-mode only)
		SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
		SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
		SystemNumaProcessorMap, // q
		SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
		SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
		SystemRecommendedSharedDataAlignment, // q
		SystemComPlusPackage, // q; s
		SystemNumaAvailableMemory, // 60
		SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
		SystemEmulationBasicInformation, // q
		SystemEmulationProcessorInformation,
		SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
		SystemLostDelayedWriteInformation, // q: ULONG
		SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
		SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
		SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
		SystemHotpatchInformation, // q; s
		SystemObjectSecurityMode, // 70, q
		SystemWatchdogTimerHandler, // s (kernel-mode only)
		SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
		SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
		SystemWow64SharedInformationObsolete, // not implemented
		SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
		SystemFirmwareTableInformation, // not implemented
		SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
		SystemVerifierTriageInformation, // not implemented
		SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
		SystemMemoryListInformation, // 80, q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege)
		SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
		SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
		SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
		SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
		SystemProcessorPowerInformationEx, // not implemented
		SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
		SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
		SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
		SystemErrorPortInformation, // s (requires SeTcbPrivilege)
		SystemBootEnvironmentInformation, // 90, q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION
		SystemHypervisorInformation, // q; s (kernel-mode only)
		SystemVerifierInformationEx, // q; s
		SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
		SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
		SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
		SystemPrefetchPatchInformation, // not implemented
		SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
		SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
		SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
		SystemProcessorPerformanceDistribution, // 100, q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
		SystemNumaProximityNodeInformation, // q
		SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
		SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
		SystemProcessorMicrocodeUpdateInformation, // s
		SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
		SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
		SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
		SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
		SystemStoreInformation, // q; s // SmQueryStoreInformation
		SystemRegistryAppendString, // 110, s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
		SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
		SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
		SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
		SystemNativeBasicInformation, // not implemented
		SystemSpare1, // not implemented
		SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
		SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
		SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
		SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
		SystemSystemPtesInformationEx, // 120, q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes)
		SystemNodeDistanceInformation, // q
		SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
		SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
		SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
		SystemSessionBigPoolInformation, // since WIN8
		SystemBootGraphicsInformation,
		SystemScrubPhysicalMemoryInformation,
		SystemBadPageInformation,
		SystemProcessorProfileControlArea,
		SystemCombinePhysicalMemoryInformation, // 130
		SystemEntropyInterruptTimingCallback,
		SystemConsoleInformation,
		SystemPlatformBinaryInformation,
		SystemThrottleNotificationInformation,
		SystemHypervisorProcessorCountInformation,
		SystemDeviceDataInformation,
		SystemDeviceDataEnumerationInformation,
		SystemMemoryTopologyInformation,
		SystemMemoryChannelInformation,
		SystemBootLogoInformation, // 140
		SystemProcessorPerformanceInformationEx, // since WINBLUE
		SystemSpare0,
		SystemSecureBootPolicyInformation,
		SystemPageFileInformationEx,
		SystemSecureBootInformation,
		SystemEntropyInterruptTimingRawInformation,
		SystemPortableWorkspaceEfiLauncherInformation,
		SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
		SystemKernelDebuggerInformationEx,
		SystemBootMetadataInformation, // 150
		SystemSoftRebootInformation,
		SystemElamCertificateInformation,
		SystemOfflineDumpConfigInformation,
		SystemProcessorFeaturesInformation,
		SystemRegistryReconciliationInformation,
		SystemEdidInformation,
		MaxSystemInfoClass
	} SYSTEM_INFORMATION_CLASS;
	typedef struct _THREAD_BASIC_INFORMATION {
		NTSTATUS                ExitStatus;
		PVOID                   TebBaseAddress;
		CLIENT_ID               ClientId;
		KAFFINITY               AffinityMask;
		KPRIORITY               Priority;
		KPRIORITY               BasePriority;
	} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;
	typedef enum _DEBUGOBJECTINFOCLASS {
		DebugObjectFlags = 1,
		MaxDebugObjectInfoClass
	} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

	typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
		ULONG Flags;                    //Reserved.  
		PUNICODE_STRING FullDllName;   //The full path name of the DLL module.  
		PUNICODE_STRING BaseDllName;   //The base file name of the DLL module.  
		PVOID DllBase;                  //A pointer to the base address for the DLL in memory.  
		ULONG SizeOfImage;              //The size of the DLL image, in bytes.  
	} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

	typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
		ULONG Flags;                    //Reserved.  
		PUNICODE_STRING FullDllName;   //The full path name of the DLL module.  
		PUNICODE_STRING BaseDllName;   //The base file name of the DLL module.  
		PVOID DllBase;                  //A pointer to the base address for the DLL in memory.  
		ULONG SizeOfImage;              //The size of the DLL image, in bytes.  
	} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

	typedef union _LDR_DLL_NOTIFICATION_DATA {
		LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
		LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
	} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;
	typedef const PLDR_DLL_NOTIFICATION_DATA PCLDR_DLL_NOTIFICATION_DATA;


	typedef struct _STRING {
		USHORT Length;
		USHORT MaximumLength;
		PCHAR Buffer;
	} STRING;
	typedef STRING *PSTRING;
	typedef PSTRING PANSI_STRING;


	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		union {
			LIST_ENTRY HashLinks;
			struct {
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union {
			struct {
				ULONG TimeDateStamp;
			};
			struct {
				PVOID LoadedImports;
			};
		};
		struct _ACTIVATION_CONTEXT * EntryPointActivationContext;

		PVOID PatchInformation;

	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	typedef struct _SYSTEM_HANDLE
	{
		ULONG ProcessId;
		BYTE ObjectTypeNumber;
		BYTE Flags;
		USHORT Handle;
		PVOID Object;
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG HandleCount;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
	{
		BOOLEAN KernelDebuggerEnabled;
		BOOLEAN KernelDebuggerNotPresent;
	} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	typedef struct _LDR_MODULE
	{
		LIST_ENTRY      InLoadOrderModuleList;
		LIST_ENTRY      InMemoryOrderModuleList;
		LIST_ENTRY      InInitializationOrderModuleList;
		PVOID           BaseAddress;
		PVOID           EntryPoint;
		ULONG           SizeOfImage;
		UNICODE_STRING  FullDllName;
		UNICODE_STRING  BaseDllName;
		ULONG           Flags;
		SHORT           LoadCount;
		SHORT           TlsIndex;
		LIST_ENTRY      HashTableEntry;
		ULONG           TimeDateStamp;
	} LDR_MODULE, *PLDR_MODULE;
	enum MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation,
		MemoryWorkingSetInformation, /* MemoryWorkingSetList, */
		MemoryMappedFilenameInformation, /* MemorySectionName, */
		MemoryRegionInformation, /* MemoryBasicVlmInformation, */
		MemoryWorkingSetExInformation, /* MemoryWorkingSetExList, */
		MemorySharedCommitInformation /* MEMORY_SHARED_COMMIT_INFORMATION */
	};
	typedef struct _MEMORY_SECTION_NAME
	{
		UNICODE_STRING	SectionFileName;
	} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;
	typedef struct _OBJECT_TYPE_INFORMATION
	{
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccessMask;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		ULONG PoolType;
		ULONG DefaultPagedPoolCharge;
		ULONG DefaultNonPagedPoolCharge;
	} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
	typedef struct _OBJECT_TYPES_INFORMATION
	{
		ULONG NumberOfTypes;
		OBJECT_TYPE_INFORMATION TypeInformation[1];
	} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;
	typedef enum _OBJECT_INFORMATION_CLASS
	{
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectTypesInformation, //OBJECT_TYPES_INFORMATION
		ObjectHandleFlagInformation, //OBJECT_HANDLE_FLAG_INFORMATION
		ObjectSessionInformation,
		MaxObjectInfoClass  // MaxObjectInfoClass should always be the last enum
	} OBJECT_INFORMATION_CLASS;

	typedef struct _SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		ULONG WaitReason;
	} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
	{
		SYSTEM_THREAD_INFORMATION ThreadInfo;
		PVOID StackBase;
		PVOID StackLimit;
		PVOID Win32StartAddress;
		PVOID TebAddress; /* This is only filled in on Vista and above */
		ULONG_PTR Reserved2;
		ULONG_PTR Reserved3;
		ULONG_PTR Reserved4;
	} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
		SYSTEM_THREAD_INFORMATION Threads[1];
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
	typedef struct _MEMORY_BASIC_VLM_INFORMATION {
		ULONGLONG ImageBase;
		struct {
			ULONG Protection;
			ULONG Type;
		};
		ULONGLONG SizeOfImage;
		ULONGLONG Unknown;
	}MEMORY_BASIC_VLM_INFORMATION, *PMEMORY_BASIC_VLM_INFORMATION;
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	typedef struct _DIRECTORY_BASIC_INFORMATION {
		UNICODE_STRING ObjectName;
		UNICODE_STRING ObjectTypeName;
	} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

}
namespace MitigationStructs
{
	typedef struct _PROCESS_MITIGATION_ASLR_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD EnableBottomUpRandomization : 1;
				DWORD EnableForceRelocateImages : 1;
				DWORD EnableHighEntropy : 1;
				DWORD DisallowStrippedImages : 1;
				DWORD ReservedFlags : 28;
			};
		};
	} PROCESS_MITIGATION_ASLR_POLICY, *PPROCESS_MITIGATION_ASLR_POLICY;
	typedef struct _PROCESS_MITIGATION_DEP_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD Enable : 1;
				DWORD DisableAtlThunkEmulation : 1;
				DWORD ReservedFlags : 30;
			};
		};
		BOOLEAN Permanent;
	} PROCESS_MITIGATION_DEP_POLICY, *PPROCESS_MITIGATION_DEP_POLICY;

	typedef struct _PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD RaiseExceptionOnInvalidHandleReference : 1;
				DWORD HandleExceptionsPermanentlyEnabled : 1;
				DWORD ReservedFlags : 30;
			};
		};
	} PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY, *PPROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY;
	typedef struct _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD DisallowWin32kSystemCalls : 1;
				DWORD ReservedFlags : 31;
			};
		};
	} PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY, *PPROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY;
	typedef struct _PROCESS_MITIGATION_DYNAMIC_CODE_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD ProhibitDynamicCode : 1;
				DWORD ReservedFlags : 31;
			};
		};
	} PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, *PPROCESS_MITIGATION_DYNAMIC_CODE_POLICY;
	typedef struct _PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
		union {
			DWORD Flags;
			struct {
				DWORD MicrosoftSignedOnly : 1;
				DWORD ReservedFlags : 31;
			};
		};
	} PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, *PPROCESS_MITIGATION_BINARY_SIGNATURE_POLICY;
	typedef struct _PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY {
		union {
			DWORD  Flags;
			struct {
				DWORD EnableControlFlowGuard : 1;
				DWORD ReservedFlags : 31;
			};
		};
	} PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY, *PPROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY;
	typedef struct _PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
		union {
			DWORD  Flags;
			struct {
				DWORD NoRemoteImages : 1;
				DWORD NoLowMandatoryLabelImages : 1;
				DWORD PreferSystem32Images : 1;
				DWORD ReservedFlags : 29;
			};
		};
	} PROCESS_MITIGATION_IMAGE_LOAD_POLICY, *PPROCESS_MITIGATION_IMAGE_LOAD_POLICY;
	typedef struct _PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY {
		union {
			DWORD  Flags;
			struct {
				DWORD DisableExtensionPoints : 1;
				DWORD ReservedFlags : 31;
			};
		};
	} PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, *PPROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY;


	typedef enum _PROCESS_MITIGATION_POLICY {
		ProcessDEPPolicy,
		ProcessASLRPolicy,
		ProcessDynamicCodePolicy,
		ProcessStrictHandleCheckPolicy,
		ProcessSystemCallDisablePolicy,
		ProcessMitigationOptionsMask,
		ProcessExtensionPointDisablePolicy,
		ProcessControlFlowGuardPolicy,
		ProcessSignaturePolicy,
		ProcessFontDisablePolicy,
		ProcessImageLoadPolicy,
		MaxProcessMitigationPolicy
	} PROCESS_MITIGATION_POLICY, *PPROCESS_MITIGATION_POLICY;


	typedef struct _VM_COUNTERS {
		SIZE_T	PeakVirtualSize;
		SIZE_T	VirtualSize;
		ULONG	PageFaultCount;
		SIZE_T	PeakWorkingSetSize;
		SIZE_T	WorkingSetSize;
		SIZE_T	QuotaPeakPagedPoolUsage;
		SIZE_T	QuotaPagedPoolUsage;
		SIZE_T	QuotaPeakNonPagedPoolUsage;
		SIZE_T	QuotaNonPagedPoolUsage;
		SIZE_T	PagefileUsage;
		SIZE_T	PeakPagefileUsage;
	} VM_COUNTERS;
	typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		ULONG UniqueProcessId;
		ULONG InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		PVOID PageDirectoryBase;
		VM_COUNTERS VirtualMemoryCounters;
		SIZE_T PrivatePageCount;
		IO_COUNTERS IoCounters;
		SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
	} SYSTEM_EXTENDED_PROCESS_INFORMATION, *PSYSTEM_EXTENDED_PROCESS_INFORMATION;

};


static inline TEB* GetCurrentTeb() {
	return reinterpret_cast<TEB*>(__readfsdword(offsetof(NT_TIB, Self)));
}
static inline PEB* GetCurrentPEB() {
	return reinterpret_cast<PEB*>(__readfsdword(0x30));
}



/*
import re
strings = [
	"process hacker",
	"process explorer"
]

def _write(x):
	a = open("strings.txt", "a")
	a.write(x + "\n")
	a.close()

for i in strings :
	_write("CHAR __%s[] = { %s, 0x0 }; // %s" % (i, str(map(str, i)).replace("[", "").replace("]", ""), i))
*/
