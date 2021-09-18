#include <com_model.h>

extern cl_enginefunc_t gEngfuncs;
extern event_api_s gEventAPI;
extern efx_api_s gEfxAPI;
extern engine_studio_api_t IEngineStudio;
extern int g_iMod;
extern int g_iUser1;
extern int g_iUser2;
extern int g_iUser3;
extern int g_iTeamNumber;
extern int g_iFreezeTimeOver;
extern int g_iCurrentWeapon;
extern int g_iPlayerFlags;
extern float g_flPlayerSpeed;
extern int g_iWeaponFlags;
extern int g_iWeaponLimit;
extern float g_Next_Key_CanUse;
extern int g_iHookVAngle, g_iShowCustomCrosshair;
extern float g_vecVAngle[3];

extern int (*Engfunc_Call_AddVisibleEntity)(struct cl_entity_s *pEntity);

int Initialize(struct cl_enginefuncs_s *pEnginefuncs, int iVersion);
void HUD_Init(void);
int HUD_VidInit(void);
int HUD_Redraw(float time, int intermission);
void HUD_DrawTransparentTriangles(void);
void V_CalcRefdef(struct ref_params_s *pParams);
int HUD_GetStudioModelInterface(int iVersion, struct r_studio_interface_s **ppStudioInterface, struct engine_studio_api_s *pEngineStudio);
int HUD_AddEntity(int iType, struct cl_entity_s *pEntity, const char *pszModel);
void HUD_PlayerMove(struct playermove_s *pPlayerMove, int iServer);
int HUD_UpdateClientData(client_data_t *pClientData, float flTime);
void HUD_StudioEvent(const struct mstudioevent_s *pEvent, const struct cl_entity_s *pEntity);
void HUD_PostRunCmd(struct local_state_s *from, struct local_state_s *to, struct usercmd_s *cmd, int runfuncs, double time, unsigned int random_seed);
void HUD_TempEntUpdate(double dblFrameTime, double dblClientTime, double dblGravity, struct tempent_s **ppTempEntFree, struct tempent_s **ppTempEntActive, int (*pfnAddVisibleEntity)(struct cl_entity_s *pEntity), void (*pfnTempEntPlaySound)(struct tempent_s *pTemp, float flDamp));
int HUD_Key_Event(int eventcode, int keynum, const char *pszCurrentBinding);
void HUD_ProcessPlayerState(struct entity_state_s *dst, const struct entity_state_s *src);
void IN_Accumulate(void);
void IN_ClearStates(void);
void IN_MouseEvent(int);
int ModelFrameCount(model_t *mod);