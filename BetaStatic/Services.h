#pragma once
/// define list in here

#define TEST_MODE
// #define BLOCK_CONNECTIONS
// #define TERMINATE_HOOK
#define PASSIVE_MODE
// #define SCRENSHOT_FEATURE
#define LICENSE_CHECK
#define ENABLE_MITIGATION_POLICYS
// #define USE_BETABOX

#define USE_CODE_VIRTUALIZER_SDK	0
#define USE_SHIELDEN_SDK			0
#define USE_THEMIDA_SDK				0
#define USE_VMPROTECT_SDK			0


#ifdef _DEBUG
#include "CLog.h"
static void PrintActiveFlags()
{
#ifdef TEST_MODE
	LPLog->AddLog(0, "* Test mode is ACTIVE! *");
#endif
#ifdef BLOCK_CONNECTIONS
	LPLog->AddLog(0, "* Connection block mode is ACTIVE! *");
#endif
#ifdef TERMINATE_HOOK
	LPLog->AddLog(0, "* Terminate block mode is ACTIVE! *");
#endif
#ifdef PASSIVE_MODE
	LPLog->AddLog(0, "* Passive mode is ACTIVE! *");
#endif
#ifdef SCRENSHOT_FEATURE
	LPLog->AddLog(0, "* Screenshot feature is ACTIVE! *");
#endif
#ifdef ENABLE_MITIGATION_POLICYS
	LPLog->AddLog(0, "* Mitigation policys is ACTIVE! *");
#endif
#ifdef USE_BETABOX
	LPLog->AddLog(0, "* BetaBox module is ACTIVE! *");
#endif

#if USE_CODE_VIRTUALIZER_SDK == 1
	LPLog->AddLog(0, "* Code virtualizer SDK is ACTIVE! *");
#endif
#if USE_SHIELDEN_SDK == 1
	LPLog->AddLog(0, "* Shielden SDK is ACTIVE! *");
#endif
#if USE_THEMIDA_SDK == 1
	LPLog->AddLog(0, "* Themida SDK is ACTIVE! *");
#endif
#if USE_VMPROTECT_SDK == 1
	LPLog->AddLog(0, "* VMProtect SDK is ACTIVE! *");
#endif
}
#endif

