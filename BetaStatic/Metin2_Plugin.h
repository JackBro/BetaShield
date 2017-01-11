#pragma once

enum EPluginTriggerTypes {
	TRIGGER_NONE,
	TRIGGER_SYSERR, /* Test */
	TRIGGER_ETERPACK_ISEXIST,
	TRIGGER_PYTHONPLAYER_GETNAME,
	TRIGGER_NETWORKSTREAM_GETPHASE,
	TRIGGER_NETWORKSTREAM_SENDHACK,
	TRIGGER_NETWORKSTREAM_GETHASHFROMMAPPEDFILE,
};

class CPluginMetin2 {
	public:
		CPluginMetin2();
		virtual ~CPluginMetin2();


		void			GameFunctionTrigger(DWORD dwCaller, void * lpTarget, int iType);

		bool			G_IsInitialized();
		void			G_SetInitialized(bool bType);

		void			G_Syserr(const char* c_szFormat, ...);
		bool			G_isExist(const char* c_szFileName);
		const char*		G_GetName();
		std::string		G_GetPhase();
		DWORD			G_GetMappedFileHash(const char* c_szFileName);
		void			G_SendHack(const char* c_szMsg);


#ifdef _DEBUG
		void			DumpRealHashes();
#endif
		void			CheckIngameHashes();
		void			CheckIngameHashes_map();


		HANDLE			InitCheckIngame();

};
extern CPluginMetin2* LPPluginMetin2;
