#include "base.h"

cl_exportfuncs_t gExportfuncs;
metahook_api_t *g_pMetaHookAPI;
mh_interface_t *g_pInterface;
mh_enginesave_t *g_pMetaSave;


void IPlugins::Init(metahook_api_t *pAPI, mh_interface_t *pInterface, mh_enginesave_t *pSave)
{
	g_pMetaHookAPI = pAPI;
	g_pInterface = pInterface;
	g_pMetaSave = pSave;
}

void IPlugins::LoadClient(cl_exportfuncs_t *pExportFunc)
{
	FILE *fp;
	fp = fopen("metahook\\logs\\metahook.log", "rb");
	if(fp)
	{
		fclose(fp);
		char filepath[256];
		::GetCurrentDirectory(255,filepath);
		sprintf(filepath,"%s\\metahook\\logs\\metahook.log",filepath);
		DeleteFile(filepath);
		LogToFile("已删除之前的log内容!");
	}
	LogToFile("BTE插件已加载[2013/8/17]");
	LogToFile("MGUI版本[2013/8/17]");
	memcpy(&gExportfuncs, pExportFunc, sizeof(gExportfuncs));

	pExportFunc->Initialize = Initialize;
	pExportFunc->HUD_Init = HUD_Init;
	pExportFunc->HUD_Redraw = HUD_Redraw;
	pExportFunc->V_CalcRefdef = V_CalcRefdef;
	pExportFunc->HUD_VidInit = HUD_VidInit;
	pExportFunc->HUD_DrawTransparentTriangles = HUD_DrawTransparentTriangles;
	pExportFunc->HUD_GetStudioModelInterface = HUD_GetStudioModelInterface; 
	pExportFunc->HUD_AddEntity = HUD_AddEntity;
	pExportFunc->HUD_PlayerMove = HUD_PlayerMove;
	pExportFunc->HUD_UpdateClientData = HUD_UpdateClientData;
	pExportFunc->HUD_StudioEvent = HUD_StudioEvent;
	pExportFunc->HUD_TempEntUpdate = HUD_TempEntUpdate;
	pExportFunc->HUD_PostRunCmd = HUD_PostRunCmd;
	pExportFunc->HUD_Key_Event = HUD_Key_Event;
	pExportFunc->HUD_ProcessPlayerState = HUD_ProcessPlayerState;
	pExportFunc->IN_Accumulate = IN_Accumulate;
	pExportFunc->IN_ClearStates = IN_ClearStates;
	pExportFunc->IN_MouseEvent = IN_MouseEvent;
	
	
}
void IPlugins::ExitGame(int iResult)
{
	Fonts_Free();
	delete g_pOverview;
}
void IPlugins::Shutdown()
{	
}
/*void IPlugins::LoadEngine(void)
{
	
}*/
	




/*void IPlugins::LoadEngine(void)
{


	g_dwEngineBase = g_pMetaHookAPI->GetEngineBase();
	g_dwEngineSize = g_pMetaHookAPI->GetEngineSize();

	g_pfnCL_GetModelByIndex = (struct model_s *(*)(int))g_pMetaHookAPI->SearchPattern((void *)g_dwEngineBase, g_dwEngineSize, CL_GETMODELBYINDEX_SIGNAL, sizeof(CL_GETMODELBYINDEX_SIGNAL) - 1);
	g_phCL_GetModelByIndex = g_pMetaHookAPI->InlineHook(g_pfnCL_GetModelByIndex, CL_GetModelByIndex, (void *&)g_pfnCL_GetModelByIndex);
	g_pfnCL_AddToResourceList = (void (*)(resource_t *, resource_t *))g_pMetaHookAPI->SearchPattern((void *)g_dwEngineBase, g_dwEngineSize, CL_ADDTORESOURCELIST_SIGNAL, sizeof(CL_ADDTORESOURCELIST_SIGNAL) - 1);
	g_phCL_AddToResourceList = g_pMetaHookAPI->InlineHook(g_pfnCL_AddToResourceList, CL_AddToResourceList, (void *&)g_pfnCL_AddToResourceList);

	
}*/



EXPOSE_SINGLE_INTERFACE(IPlugins, IPlugins, METAHOOK_PLUGIN_API_VERSION);