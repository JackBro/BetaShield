#include "ProjectMain.h"
#include "Main.h"
#include "Scan.h"
#include "DynamicWinapi.h"
#include "Functions.h"
#include "DirFuncs.h"
#include "Threads.h"
#include "XOR.h"
#include "CLog.h"
#include "VersionHelpers.h"


typedef struct _DNS_CACHE_ENTRY {
	struct _DNS_CACHE_ENTRY* pNext;
	PWSTR pszName;
	unsigned short wType;
	unsigned short wDataLength;
	unsigned long dwFlags;
} DNSCACHEENTRY, *PDNSCACHEENTRY;

void CScan::ScanDNSHistory()
{
	if (IsWindows7OrGreater() == false)
		return;

	DNSCACHEENTRY * pEntry = (PDNSCACHEENTRY)nkt_malloc(sizeof(DNSCACHEENTRY));
	if (!pEntry)
		return;

	CHAR __DnsApiFree[] = { 'D', 'n', 's', 'A', 'p', 'i', 'F', 'r', 'e', 'e', 0x0 };
	typedef void(WINAPI* lpDnsApiFree)(PVOID pData);
	lpDnsApiFree pDnsApiFree = (lpDnsApiFree)BetaFunctionTable->GetProcAddress(BetaModuleTable->hDnsapi, __DnsApiFree);

	CHAR __DnsGetCacheDataTable[] = { 'D', 'n', 's', 'G', 'e', 't', 'C', 'a', 'c', 'h', 'e', 'D', 'a', 't', 'a', 'T', 'a', 'b', 'l', 'e', 0x0 };
	typedef int(WINAPI* lpDnsGetCacheDataTable)(PDNSCACHEENTRY);
	lpDnsGetCacheDataTable DnsGetCacheDataTable = (lpDnsGetCacheDataTable)BetaFunctionTable->GetProcAddress(BetaModuleTable->hDnsapi, __DnsGetCacheDataTable);


	auto iTableStat = DnsGetCacheDataTable(pEntry);
	pEntry = pEntry->pNext;

	int iCount = 0;
	bool bBobIsDetected = false;
	while (pEntry) {
		++iCount;

		const WCHAR* w_szData = pEntry->pszName;
		_bstr_t bstr_Data(w_szData);
		const char* c_szData = bstr_Data;

		CHAR __bob_patcher[] = { 'n', 'i', '8', '7', '1', '0', '5', '0', '_', '1', 0x0 };
		//CHAR __bob[] = { 'm', '2', 'b', 'o', 'b', 0x0 };
		if (strstr(c_szData, __bob_patcher) /* || strstr(c_szData, __bob) */)
			bBobIsDetected = true;

		pEntry = pEntry->pNext;
	}

	//if (iCount == 0) {
	//	// open dns service
	//}

	if (bBobIsDetected) {
		CHAR __warn[] = { 'M', '2', 'b', 'o', 'b', ' ', 'd', 'e', 't', 'e', 'c', 't', 'e', 'd', ' ', 'i', 'n', ' ', 'y', 'o', 'u', 'r', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '.', ' ', 'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'e', 'a', 'n', ' ', 'a', 'n', 'd', ' ', 'r', 'e', 's', 't', 'a', 'r', 't', ' ', 'y', 'o', 'u', 'r', ' ', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r', '.', 0x0 }; // M2bob detected in your computer. Please clean and restart your computer.
		LPFunctions->CloseProcess(__warn, true, "");
	}

	nkt_mfree(pEntry);
}
