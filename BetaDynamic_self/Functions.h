#pragma once

class CFunctions {
	public:
		static bool CreateInfoData(PANTI_MODULE_INFO pami, HMODULE hModule);
		static void DestroyIAT(HMODULE hMod);
		static void DestroySections(HMODULE hModule);
		static DWORD HideModuleLinks(HMODULE Base);
};

