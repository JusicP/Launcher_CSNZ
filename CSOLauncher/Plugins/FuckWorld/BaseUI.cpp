#include <metahook.h>
#include <IBaseUI.h>
#include "BaseUI.h"
//#include "util.h"
#include "base.h"
#include "VGUI\IScheme.h"

HINTERFACEMODULE g_hVGUI2;

void (__fastcall *g_pfnCBaseUI_Initialize)(void *pthis, int, CreateInterfaceFn *factories, int count);
void (__fastcall *g_pfnCBaseUI_Start)(void *pthis, int, struct cl_enginefuncs_s *engineFuncs, int interfaceVersion);
void (__fastcall *g_pfnCBaseUI_Shutdown)(void *pthis, int);
int (__fastcall *g_pfnCBaseUI_Key_Event)(void *pthis, int, int down, int keynum, const char *pszCurrentBinding);
void (__fastcall *g_pfnCBaseUI_CallEngineSurfaceProc)(void *pthis, int, void *hwnd, unsigned int msg, unsigned int wparam, long lparam);
void (__fastcall *g_pfnCBaseUI_Paint)(void *pthis, int, int x, int y, int right, int bottom);
void (__fastcall *g_pfnCBaseUI_HideGameUI)(void *pthis, int);
void (__fastcall *g_pfnCBaseUI_ActivateGameUI)(void *pthis, int);
bool (__fastcall *g_pfnCBaseUI_IsGameUIVisible)(void *pthis, int);
void (__fastcall *g_pfnCBaseUI_HideConsole)(void *pthis, int);
void (__fastcall *g_pfnCBaseUI_ShowConsole)(void *pthis, int);

class CBaseUI : public IBaseUI
{
public:
	virtual void Initialize(CreateInterfaceFn *factories, int count);
	virtual void Start(struct cl_enginefuncs_s *engineFuncs, int interfaceVersion);
	virtual void Shutdown(void);
	virtual int Key_Event(int down, int keynum, const char *pszCurrentBinding);
	virtual void CallEngineSurfaceProc(void *hwnd, unsigned int msg, unsigned int wparam, long lparam);
	virtual void Paint(int x, int y, int right, int bottom);
	virtual void HideGameUI(void);
	virtual void ActivateGameUI(void);
	virtual bool IsGameUIVisible(void);
	virtual void HideConsole(void);
	virtual void ShowConsole(void);
};


IBaseUI *g_pBaseUI;
vgui::IPanel *g_pPanel;

vgui::ISurface *g_pSurface;
vgui::ILocalize *g_pLocalize;
IFileSystem *g_pFileSystem;
vgui::ISchemeManager *g_pSchemeManager;

void CBaseUI::Initialize(CreateInterfaceFn *factories, int count)
{
	g_pfnCBaseUI_Initialize(this, 0, factories, count);
	g_hVGUI2 = (HINTERFACEMODULE)GetModuleHandle("vgui2.dll");


	if (g_hVGUI2)
	{
		CreateInterfaceFn fnVGUI2CreateInterface = Sys_GetFactory(g_hVGUI2);
		CreateInterfaceFn fnEngineCreateInterface = g_pMetaHookAPI->GetEngineFactory();

		vgui::ISurface *pSurface = (vgui::ISurface *)fnEngineCreateInterface(VGUI_SURFACE_INTERFACE_VERSION, NULL);
		vgui::ILocalize *pLocalize = (vgui::ILocalize *)fnVGUI2CreateInterface(VGUI_LOCALIZE_INTERFACE_VERSION, NULL);
		vgui::ISchemeManager *pSchemeManager = (vgui::ISchemeManager *)fnVGUI2CreateInterface(VGUI_SCHEME_INTERFACE_VERSION, NULL);

		g_pSurface = pSurface;
		g_pLocalize = pLocalize;
		g_pSchemeManager = pSchemeManager;
		g_pFileSystem = g_pInterface->FileSystem;
		if(g_pSurface) LogToFile("已初始化VGUI2图形接口");
		if(g_pLocalize) LogToFile("已初始化VGUI2本地化接口");


		g_pLocalize->AddFile(g_pFileSystem,"Resource/csbte_%language%.txt");
		
		PlayAudio_Init();
		PlayAudio_Frame();
		//LogToFile(UnicodeToANSI(g_pLocalize->Find("CSBTE")));
		
	}
}

void CBaseUI::Start(struct cl_enginefuncs_s *engineFuncs, int interfaceVersion)
{
	g_pfnCBaseUI_Start(this, 0, engineFuncs, interfaceVersion);
}

void CBaseUI::Shutdown(void)
{
	g_pfnCBaseUI_Shutdown(this, 0);
}

int CBaseUI::Key_Event(int down, int keynum, const char *pszCurrentBinding)
{
	return g_pfnCBaseUI_Key_Event(this, 0, down, keynum, pszCurrentBinding);
}

void CBaseUI::CallEngineSurfaceProc(void *hwnd, unsigned int msg, unsigned int wparam, long lparam)
{
	g_pfnCBaseUI_CallEngineSurfaceProc(this, 0, hwnd, msg, wparam, lparam);
}

void CBaseUI::Paint(int x, int y, int right, int bottom)
{
	g_pfnCBaseUI_Paint(this, 0, x, y, right, bottom);
}

void CBaseUI::HideGameUI(void)
{
	g_pfnCBaseUI_HideGameUI(this, 0);
}

void CBaseUI::ActivateGameUI(void)
{
	g_pfnCBaseUI_ActivateGameUI(this, 0);
}

bool CBaseUI::IsGameUIVisible(void)
{
	return g_pfnCBaseUI_IsGameUIVisible(this, 0);
}

void CBaseUI::HideConsole(void)
{
	g_pfnCBaseUI_HideConsole(this, 0);
}

void CBaseUI::ShowConsole(void)
{
	g_pfnCBaseUI_ShowConsole(this, 0);
}

DWORD g_dwEngineBase, g_dwEngineSize;

struct model_s *(*g_pfnCL_GetModelByIndex)(int index);
hook_t *g_phCL_GetModelByIndex;
void (*g_pfnCL_AddToResourceList)(resource_t *pResource, resource_t *pList);
hook_t *g_phCL_AddToResourceList;

char g_szModelPrecache[512][MAX_QPATH];
int g_iModelPrecacheNums;

struct model_s *CL_GetModelByIndex(int index)
{
	if (index == -1)
		return NULL;

	if (index >= 512)
		return IEngineStudio.Mod_ForName(g_szModelPrecache[index - 512], false);

	return g_pfnCL_GetModelByIndex(index);
}

void CL_AddToResourceList(resource_t *pResource, resource_t *pList)
{	
	if (pResource->type == t_model)
	{
		if(strstr(pResource->szFileName, "models/v_") || strstr(pResource->szFileName, "models/p_")/* || strstr(pResource->szFileName, "models/bte_wpn/v_") || strstr(pResource->szFileName, "models/bte_wpn/p_")*/)
		{				
			for (int i = 0; i < 512; i++)
			{
				if (!strcmp(g_szModelPrecache[i], pResource->szFileName))
					return;
			}

			char name[64], text[64];
			strcpy(name, pResource->szFileName + 9);
			name[strlen(name)-4] = 0;

			sprintf(text,"gfx\\vgui\\%s", name);
			FindTexture(name);

			sprintf(text, "CSBTE_%s", name);
			Fonts_LoadString(GetLangUni(text));

			model_t *model = IEngineStudio.Mod_ForName(pResource->szFileName, false);
			strcpy(g_szModelPrecache[g_iModelPrecacheNums++], pResource->szFileName);

			studiohdr_t	*pstudio;
			mstudiotexture_t	*ptexture;
			pstudio = (studiohdr_t*)IEngineStudio.Mod_Extradata(model);
			ptexture = (mstudiotexture_t *)(((byte *)pstudio) + pstudio->textureindex);	
			for(int i = 0; i < pstudio->numtextures; i++ )
			{
				if(ptexture[i].name[0] == '#' && pResource->szFileName[7] == 'p')
				{
					//if(strstr(pResource->szFileName, "models/v_")/* || ptexture[i].height > 4 || ptexture[i].width > 4*/) continue;
					
					char name[64];
					int tid;
					sprintf(name, "models\\texture\\%s", ptexture[i].name);

					tid = DrawBmpGetID(name);
					if (!g_MHTga[tid].height) continue;
					ptexture[i].index = g_MHTga[tid].texid;
					ptexture[i].height = g_MHTga[tid].height;
					ptexture[i].width = g_MHTga[tid].width;

#if 0
					if (strstr(ptexture[i].name, "512"))
					{
						tid = DrawBmpGetID(name);
						if (!g_MHTga[tid].height) continue;
						ptexture[i].index = g_MHTga[tid].texid;
						ptexture[i].height = g_MHTga[tid].height;
						ptexture[i].width = g_MHTga[tid].width;
					}
					else
					{
						name[strlen(name)-4] = 0;
						tid = FindTexture(name);
						ptexture[i].index = g_Texture[tid].iTexture;
						ptexture[i].height = g_Texture[tid].iHeight;
						ptexture[i].width = g_Texture[tid].iWidth;
					}
#endif
				}
				/*if(ptexture[i].name[0] == '#' && pResource->szFileName[7] == 'v')
				{

				}*/
			}
			return;
		}
	}

	g_pfnCL_AddToResourceList(pResource, pList);
}

#define CL_GETMODELBYINDEX_SIG "\x83\xEC\x10\x56\x57\x8B\x7C\x24\x1C\x8B\x34\xBD\x2A\x2A\x2A\x2A\x85\xF6"
#define CL_ADDTORESOURCELIST_SIG "\x8B\x44\x24\x04\x8B\x88\x84\x00\x00\x00\x85\xC9"

void MemPatch_WideScreenLimit(void)
{
/*	if (g_dwEngineBuildnum >= 5953)
		return;*/

	unsigned char data[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	DWORD addr = (DWORD)g_pMetaHookAPI->SearchPattern((void *)g_dwEngineBase, g_dwEngineSize, "\x8B\x51\x08\x8B\x41\x0C\x8B\x71\x54\x8B\xFA\xC1\xE7\x04", 14);

	if (!addr)
	{
		MessageBox(NULL, "WideScreenLimit patch failed!", "Warning", MB_ICONWARNING);
		return;
	}

	DWORD addr2 = addr + 11;
	DWORD addr3 =  (DWORD)g_pMetaHookAPI->SearchPattern((void *)addr, 0x60, "\xB1\x01\x8B\x7C\x24\x14", 6);

	if (addr3)
	{
		g_pMetaHookAPI->WriteMemory((void *)addr2, data, addr3 - addr2);
	}
}


void IPlugins::LoadEngine(void)
{
	g_pMetaHookAPI->WriteDWORD((void *)0x1DBAE6C, 0x8000000);
	g_pMetaHookAPI->WriteDWORD((void *)0x1DBAE73, 0x8000000);
	
	BaseUI_InstallHook();

	//g_hEngineModule = g_pMetaHookAPI->GetEngineModule();
	g_dwEngineBase = g_pMetaHookAPI->GetEngineBase();
	g_dwEngineSize = g_pMetaHookAPI->GetEngineSize();

	g_pfnCL_GetModelByIndex = (struct model_s *(*)(int))g_pMetaHookAPI->SearchPattern((void *)g_dwEngineBase, g_dwEngineSize, CL_GETMODELBYINDEX_SIG, sizeof(CL_GETMODELBYINDEX_SIG) - 1);
	g_pfnCL_AddToResourceList = (void (*)(resource_t *, resource_t *))g_pMetaHookAPI->SearchPattern((void *)g_dwEngineBase, g_dwEngineSize, CL_ADDTORESOURCELIST_SIG, sizeof(CL_ADDTORESOURCELIST_SIG) - 1);
	
	g_phCL_AddToResourceList = g_pMetaHookAPI->InlineHook(g_pfnCL_AddToResourceList, CL_AddToResourceList, (void *&)g_pfnCL_AddToResourceList);
	g_phCL_GetModelByIndex = g_pMetaHookAPI->InlineHook(g_pfnCL_GetModelByIndex, CL_GetModelByIndex, (void *&)g_pfnCL_GetModelByIndex);

	MemPatch_WideScreenLimit();

}
void BaseUI_InstallHook(void)
{
	CreateInterfaceFn fnCreateInterface = g_pMetaHookAPI->GetEngineFactory();
	g_pBaseUI = (IBaseUI *)fnCreateInterface(BASEUI_INTERFACE_VERSION, NULL);

	CBaseUI BaseUI;
	DWORD *pVFTable = *(DWORD **)&BaseUI;

	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 1, (void *)pVFTable[1], (void *&)g_pfnCBaseUI_Initialize);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 2, (void *)pVFTable[2], (void *&)g_pfnCBaseUI_Start);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 3, (void *)pVFTable[3], (void *&)g_pfnCBaseUI_Shutdown);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 4, (void *)pVFTable[4], (void *&)g_pfnCBaseUI_Key_Event);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 5, (void *)pVFTable[5], (void *&)g_pfnCBaseUI_CallEngineSurfaceProc);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 6, (void *)pVFTable[6], (void *&)g_pfnCBaseUI_Paint);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 7, (void *)pVFTable[7], (void *&)g_pfnCBaseUI_HideGameUI);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 8, (void *)pVFTable[8], (void *&)g_pfnCBaseUI_ActivateGameUI);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 9, (void *)pVFTable[9], (void *&)g_pfnCBaseUI_IsGameUIVisible);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 10, (void *)pVFTable[10], (void *&)g_pfnCBaseUI_HideConsole);
	g_pMetaHookAPI->VFTHook(g_pBaseUI, 0, 11, (void *)pVFTable[11], (void *&)g_pfnCBaseUI_ShowConsole);

}

