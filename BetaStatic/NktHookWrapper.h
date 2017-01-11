#pragma once

class NktHelper {
	public:
		PVOID GetModuleBaseAddress_A(const char* c_szModuleName);
		PVOID GetModuleBaseAddress_W(const wchar_t* c_wszModuleName);

		PVOID GetProcAddress_A(HMODULE hModule, const char* c_szProcName);
		PVOID GetProcAddress_W(HMODULE hModule, const wchar_t* c_wszProcName);
};
