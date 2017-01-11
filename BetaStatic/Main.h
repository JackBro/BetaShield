#pragma once

class CMain {
	public:
		CMain();
		virtual ~CMain();

		void InitClasses();
		void InitMain(DWORD dwCaller);

		bool InitializeSEH();
		bool InitializeVEH();

		bool ManualMapIsReady();
		HANDLE CheckModuleModifications();
};
extern CMain* LPMain;
