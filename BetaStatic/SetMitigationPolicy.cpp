#include "ProjectMain.h"
#include "Access.h"
#include "DynamicWinapi.h"
#include "VersionHelpers.h"

#include "CLog.h"


void CAccess::SetMitigationPolicys()
{
#ifdef _DEBUG
	LPLog->AddLog(0, "Set Mitigation Policy event has been started!");

	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	if (BetaFunctionTable->RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo) == 0)
		LPLog->AddLog(0, "Target OS; Major: %u Minor: %u Build: %u", verInfo.dwMajorVersion, verInfo.dwMinorVersion, verInfo.dwBuildNumber);
#endif
	KARMA_MACRO_1

	MitigationStructs::PROCESS_MITIGATION_DEP_POLICY depPolicy = { 0 }; // 8
	depPolicy.Enable = 1;
	depPolicy.Permanent = TRUE;
	BOOL bDepPolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::PROCESS_MITIGATION_POLICY::ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
#ifdef _DEBUG
	if (bDepPolicyRet)
		LPLog->AddLog(0, "Dep Mitigation policy succesfully enabled!");
	else
		LPLog->ErrorLog(0, "Dep Mitigation policy can NOT Enabled!");
#endif

	MitigationStructs::PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 }; // 8
	aslrPolicy.EnableForceRelocateImages = 1;
	BOOL bAslrPolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::PROCESS_MITIGATION_POLICY::ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));
#ifdef _DEBUG
	if (bAslrPolicyRet)
		LPLog->AddLog(0, "ASLR Mitigation policy succesfully enabled!");
	else
		LPLog->ErrorLog(0, "ASLR Mitigation policy can NOT Enabled!");
#endif

	MitigationStructs::PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPolicy = { 0 }; // 8
	extensionPolicy.DisableExtensionPoints = 1;
	BOOL bExtensionPolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::PROCESS_MITIGATION_POLICY::ProcessExtensionPointDisablePolicy, &extensionPolicy, sizeof(extensionPolicy));
#ifdef _DEBUG
	if (bExtensionPolicyRet)
		LPLog->AddLog(0, "Extension Point Mitigation policy succesfully enabled!");
	else
		LPLog->ErrorLog(0, "Extension Point Mitigation policy can NOT Enabled!");
#endif


	MitigationStructs::PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicy = { 0 }; // 8
	strictHandlePolicy.HandleExceptionsPermanentlyEnabled = 1;
	strictHandlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
	BOOL bStrictHandlePolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::PROCESS_MITIGATION_POLICY::ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy));
#ifdef _DEBUG
	if (bStrictHandlePolicyRet)
		LPLog->AddLog(0, "Strict Handle Mitigation policy succesfully enabled!");
	else
		LPLog->ErrorLog(0, "Strict Handle Mitigation policy can NOT Enabled!");
#endif
	
	
	if (IsWindows8Point1OrGreater())
	{
		MitigationStructs::PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 }; // 8.1
		cfgPolicy.EnableControlFlowGuard = 1;
		BOOL bCfgPolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::PROCESS_MITIGATION_POLICY::ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy));
#ifdef _DEBUG
		if (bCfgPolicyRet)
			LPLog->AddLog(0, "CFG Mitigation policy succesfully enabled!");
		else
			LPLog->ErrorLog(0, "CFG Mitigation policy can NOT Enabled!");
#endif
	}

	
	if (IsWindows10OrGreater())
	{
		MitigationStructs::PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = { 0 }; // 10
		imageLoadPolicy.NoLowMandatoryLabelImages = 1;
		imageLoadPolicy.NoRemoteImages = 1;
		imageLoadPolicy.PreferSystem32Images = 1;
		BOOL bImageLoadPolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy));
#ifdef _DEBUG
		if (bImageLoadPolicyRet)
			LPLog->AddLog(0, "Image Load Mitigation policy succesfully enabled!");
		else
			LPLog->ErrorLog(0, "Image Load Mitigation policy can NOT Enabled!");
#endif

		MitigationStructs::PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 }; // 10
		signaturePolicy.MicrosoftSignedOnly = 1;
		BOOL bSignaturePolicyRet = BetaFunctionTable->SetProcessMitigationPolicy(MitigationStructs::PROCESS_MITIGATION_POLICY::ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy));
#ifdef _DEBUG
		if (bSignaturePolicyRet)
			LPLog->AddLog(0, "Binary Signature Mitigation policy succesfully enabled!");
		else
			LPLog->ErrorLog(0, "Binary Signature Mitigation policy can NOT Enabled!");
#endif
	}
	

	KARMA_MACRO_1
#ifdef _DEBUG
	LPLog->AddLog(0, "Set Mitigation Policy event completed!");
#endif
}

