#pragma once
#include <Windows.h>

class CAccess {
	public:
		CAccess();
		virtual ~CAccess();

		BOOL IsRunAsAdmin();
		BOOL IsProcessElevated();

		void SetPermissions();
		BOOL SetDACLRulesToProcess();
		BOOL SetDACLRulesToThread(HANDLE hThread);
		bool BlockAccess();
		void SetMitigationPolicys();

		bool EnableDebugPrivileges();
		bool DisableDebugPrivileges();

		void EnablePermanentDep();
		void EnableNullPageProtection();

		bool IsAccessibleImage(MEMORY_BASIC_INFORMATION mbi);
		bool IsAccessibleMemory(MEMORY_BASIC_INFORMATION mbi);

		HANDLE InitBlockHandles();
		HANDLE InitAdjustPrivThread();
};
extern CAccess* LPAccess;
