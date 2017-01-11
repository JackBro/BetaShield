#pragma once

class CAntiDebug {
	public:
		CAntiDebug();
		virtual ~CAntiDebug();

		void PebCheck();
		void IsDebugger();
		void RemoteDebugCheck();
		void SetFakeImageSize();
		void CrashDebugger();
		void DebugPort();
		void DetachFromDebuggerProcess();
		void ParentCheck(const char* c_szPatcherName);
		void CheckKernelDebugInformation();
		void AntiSoftice();
		void Antisyser();
		void CheckCloseHandle();
		void FlagsCheck();
		void PrefixCheck();
		void Int2DCheck();
		void Int3Check();
		void CheckGlobalFlagsClearInProcess();
		void CheckDebugObjects();
		void ThreadBreakOnTerminationCheck();
		void AntiHyperVisor();
		void CheckShareCount();
		void CheckStrongOD();
		void CheckSeDebugPriv();
		void CloseProtectedHandle();
		void VehIntoBreak();

		void InitAntiDebug();


		void AntiAnalysis();
		void AntiVirtualize();

		void AntiEmulation();
		void InitTimeChecks();
		int GetManipulationType();
};
extern CAntiDebug* LPAntiDebug;
