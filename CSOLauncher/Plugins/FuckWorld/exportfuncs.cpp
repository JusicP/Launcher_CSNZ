#include "base.h"
#include "event.h"
#include "BaseUI.h"
#include "CrashHandle.h"
#include "msghook.h"
#include "sprite.h"
#include "playaudio.h"
#include "engfuncs.h"

using namespace vgui;

HFont g_hCurrentFont;

cl_enginefunc_t gEngfuncs;
engine_studio_api_t IEngineStudio;
event_api_s gEventAPI;
efx_api_s gEfxAPI;
bool bLoadedSky = false;
bool bLoadedTga = false;

int g_iUser1;
int g_iUser2;
int g_iUser3;
int g_iTeamNumber;
int g_iFreezeTimeOver;
int g_iCurrentWeapon;
int g_iPlayerFlags;
float g_flPlayerSpeed;
int g_iWeaponFlags;

int g_iMod;
int g_iWeaponLimit;
float g_Entity_Index[1024];
float key_last_press = 0.0;
float g_Next_Key_CanUse = 0.0;

int g_iHookVAngle;
int g_iShowCustomCrosshair;
float g_vecVAngle[3];

int g_iTextTexture;

int g_iSniperScope[4];

void IN_Accumulate(void)
{
	if(g_iMenuActive) return;
	if(g_mgui_candraw) return;
	return gExportfuncs.IN_Accumulate();
}
void IN_ClearStates(void)
{
	return gExportfuncs.IN_ClearStates();
}
void IN_MouseEvent(int x)
{
	g_iMouseOldEvent = g_iMouseEvent;
	g_iMouseEvent = x;
	g_mgui_oldmouseevent = g_mgui_mouseevent;
	g_mgui_mouseevent = x;
	if(g_iMenuActive) return;
	if(g_mgui_candraw) return;

	return gExportfuncs.IN_MouseEvent(x);
}
int Initialize(struct cl_enginefuncs_s *pEnginefuncs, int iVersion)
{
	memcpy(&gEngfuncs, pEnginefuncs, sizeof(gEngfuncs));
	memcpy(&gEventAPI,pEnginefuncs->pEventAPI,sizeof(event_api_s));
	memcpy(&gEfxAPI,pEnginefuncs->pEfxAPI,sizeof(efx_api_s));
	
	InitCrashHandle();

	Tri_Extension_InstallHook();
	pEnginefuncs->pfnHookUserMsg = &EngFunc_HookUserMsg;
	pEnginefuncs->pfnSPR_DrawAdditive = &EngFunc_SPR_DrawAdditive;
	pEnginefuncs->pfnFillRGBA = &EngFunc_FillRGBA;
	pEnginefuncs->pfnSPR_Load = &Engfunc_SPR_Load;
	pEnginefuncs->LoadMapSprite =&Engfunc_LoadMapSprite;
	pEnginefuncs->COM_LoadFile = &Engfunc_COM_LoadFile;
	pEnginefuncs->COM_ParseFile = &Engfunc_COM_ParseFile;
	pEnginefuncs->COM_FreeFile = &Engfunc_COM_FreeFile;
	pEnginefuncs->pfnAddCommand = &EngFunc_AddCommand;
	pEnginefuncs->pfnSPR_GetList = &EngFunc_SPR_GetList;
	pEnginefuncs->pEfxAPI->R_BloodSprite = &Engfunc_BloodSprite;
	pEnginefuncs->pEfxAPI->R_BloodStream = &Engfunc_BloodStream;
	//pEnginefuncs->pEventAPI->EV_PlaySound = &Engfunc_PlaySound;
	pEnginefuncs->pEventAPI->EV_WeaponAnimation = &Engfunc_WeaponAnim;
	pEnginefuncs->pfnClientCmd = &Engfunc_ClientCmd;

	
	pEnginefuncs->pfnClientCmd = EngFunc_ClCMD;

	DeathMsgInit();
	MSG_Init();

	return gExportfuncs.Initialize(pEnginefuncs, iVersion);
}

int (__fastcall *g_pfnHudSniperScope_Draw)(void *, int,float flTime) = (int (__fastcall *)(void *,int,float))0x1961AD0;
int __fastcall HudSniperScope_Draw(void *p,int i,float f);

void DrawTexture(int index,int iX,int iY,int iW,int iH, int alpha)
{
	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	Tri_BindTexture(GL_TEXTURE_2D, index);
	gEngfuncs.pTriAPI->Color4ub(255,255,255,alpha);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	gEngfuncs.pTriAPI->TexCoord2f(0.01,0.99);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);
	gEngfuncs.pTriAPI->TexCoord2f(0.99,0.99);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);		
	gEngfuncs.pTriAPI->TexCoord2f(0.99,0.01);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
	gEngfuncs.pTriAPI->TexCoord2f(0.01,0.01);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();
}

int __fastcall HudSniperScope_Draw(void *p,int i,float f)
{
	if(g_WeaponData[g_iCurWeapon].iSniperScopeType == 1 && 0.0 < fCurrentFOV && fCurrentFOV <= 40.0)
	{
		int iH = g_sScreenInfo.iHeight / 592.0f * 256.0f;
		int iY = g_sScreenInfo.iHeight / 2 - iH;
		int iX = g_sScreenInfo.iWidth / 2 - iH;
		DrawTexture(g_Texture[g_WeaponData[g_iCurWeapon].iSniperScope[0]].iTexture,iX,iY,iH,iH,255);
		DrawTexture(g_Texture[g_WeaponData[g_iCurWeapon].iSniperScope[1]].iTexture,g_sScreenInfo.iWidth/2,iY,iH,iH,255);
		DrawTexture(g_Texture[g_WeaponData[g_iCurWeapon].iSniperScope[2]].iTexture,iX,g_sScreenInfo.iHeight/2,iH,iH,255);
		DrawTexture(g_Texture[g_WeaponData[g_iCurWeapon].iSniperScope[3]].iTexture,g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,iH,iH,255);

		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth/2 - iH,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(g_sScreenInfo.iWidth/2 + iH,0,g_sScreenInfo.iWidth/2 - iH ,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-iH,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,g_sScreenInfo.iHeight/2+iH,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-iH,0,0,0,255);

		/*gEngfuncs.pfnFillRGBABlend(g_sScreenInfo.iWidth/2,0,1,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,g_sScreenInfo.iHeight/2+1,g_sScreenInfo.iWidth,1,0,0,0,255);*/
		return g_pfnHudSniperScope_Draw(p,i,f);
	}
	if(g_WeaponData[g_iCurWeapon].iSniperScopeType == 2 && 0.0 < fCurrentFOV && fCurrentFOV <= 40.0)
	{
		int iH = g_sScreenInfo.iHeight / 592.0f * 256.0f;
		int iY = g_sScreenInfo.iHeight / 2 - iH;
		int iX = g_sScreenInfo.iWidth / 2 - iH;
		DrawTexture(g_Texture[g_iSniperScope[0]].iTexture,iX,iY,iH,iH,255);
		DrawTexture(g_Texture[g_iSniperScope[1]].iTexture,g_sScreenInfo.iWidth/2,iY,iH,iH,255);
		DrawTexture(g_Texture[g_iSniperScope[2]].iTexture,iX,g_sScreenInfo.iHeight/2,iH,iH,255);
		DrawTexture(g_Texture[g_iSniperScope[3]].iTexture,g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,iH,iH,255);

		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth/2 - iH,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(g_sScreenInfo.iWidth/2 + iH,0,g_sScreenInfo.iWidth/2 - iH ,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-iH,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,g_sScreenInfo.iHeight/2+iH,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-iH,0,0,0,255);

		/*gEngfuncs.pfnFillRGBABlend(g_sScreenInfo.iWidth/2,0,1,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,g_sScreenInfo.iHeight/2+1,g_sScreenInfo.iWidth,1,0,0,0,255);*/
		return 0/*g_pfnHudSniperScope_Draw(p,i,f)*/;
	}
	if(pCvar_DrawScope->value != 0 && g_iBTEWeapon != WPN_SFSNIPER && 0.0 < fCurrentFOV && fCurrentFOV <= 40.0)
	{
		//LogToFile("BreakPoint");
		int tid;
		float scale;
		float x,y,w,h;

		if(g_iBTEWeapon == WPN_M200)
			tid = DrawTgaGetID("other\\scope_m200");
		else
			tid = DrawTgaGetID("other\\scope");

		scale = g_sScreenInfo.iHeight / 0.85 / g_MHTga[tid].height;
		
		w = g_MHTga[tid].width * scale;
		h = g_MHTga[tid].height * scale;

		x = g_sScreenInfo.iWidth / 2 - w / 2;
		y = g_sScreenInfo.iHeight / 2 - h / 2;

		Tri_Enable(GL_TEXTURE_2D);
		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[tid].texid);
		if(g_iVideoMode)
		{
			glColor4ub(255,255,255,255);
		}
		else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		Tri_Enable(GL_BLEND);
		Tri_Enable(GL_ALPHA_TEST);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		Tri_AlphaFunc(GL_GREATER, 0.0);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);		
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(x,y+h,0);	
		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(x+w,y+h,0);		
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(x+w,y,0);		
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(x,y,0);
		gEngfuncs.pTriAPI->End();

		int LENGTH_SCOPE = w / 2;
		
		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth/2-LENGTH_SCOPE,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,0,g_sScreenInfo.iWidth/2 - LENGTH_SCOPE ,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-LENGTH_SCOPE,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,g_sScreenInfo.iHeight/2+LENGTH_SCOPE,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-LENGTH_SCOPE,0,0,0,255);
		
		// Don't know why
		gEngfuncs.pfnDrawConsoleString( -10, -10, "!" );

		return 0;
	}
	
	if(g_iBTEWeapon == WPN_SFSNIPER && 0.0 < fCurrentFOV && fCurrentFOV <= 40.0)
	{
		int LENGTH_SCOPE = g_sScreenInfo.iWidth / 3.3f;		
		
		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth/2 - LENGTH_SCOPE,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(g_sScreenInfo.iWidth/2 + LENGTH_SCOPE,0,g_sScreenInfo.iWidth/2 - LENGTH_SCOPE ,g_sScreenInfo.iHeight,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,0,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-LENGTH_SCOPE,0,0,0,255);
		gEngfuncs.pfnFillRGBABlend(0,g_sScreenInfo.iHeight/2+LENGTH_SCOPE,g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2-LENGTH_SCOPE,0,0,0,255);
		
		// Don't know why
		gEngfuncs.pfnDrawConsoleString( -10, -10, "!" );

		return 0;
	}
	return g_pfnHudSniperScope_Draw(p,i,f);
}

int (__fastcall *g_pfnCHudAmmo_DrawCrosshair)(void *, int, float flTime, int weaponid) = (int (__fastcall *)(void *, int, float, int))0x1940430;

int __fastcall CHudAmmo_DrawCrosshair(void *pthis, int, float flTime, int weaponid)
{
	return 1;
}


void HUD_Init(void)
{
	g_pOverview = new COverview;
	
	MetaHookLoadLang(); 

	pCvar_TipIcon = gEngfuncs.pfnRegisterVariable("mh_showtipicon", "1", FCVAR_ARCHIVE);
	pCvar_Name = gEngfuncs.pfnRegisterVariable("mh_teammatename", "1", FCVAR_ARCHIVE);
	pCvar_Blood = gEngfuncs.pfnRegisterVariable("mh_bloodcolor", "1", FCVAR_ARCHIVE);
	pCvar_ScoreBoard = gEngfuncs.pfnRegisterVariable("mh_scoreboard", "1", FCVAR_ARCHIVE);
	pCvar_DrawBink = gEngfuncs.pfnRegisterVariable("mh_drawbink", "1", FCVAR_ARCHIVE);
	pCvar_DrawPanel = gEngfuncs.pfnRegisterVariable("mh_drawpanel", "1", FCVAR_ARCHIVE);
	pCvar_DrawScope = gEngfuncs.pfnRegisterVariable("mh_drawscope", "1", FCVAR_ARCHIVE);
	pCvar_DrawMenu = gEngfuncs.pfnRegisterVariable("mh_drawmenu", "1", FCVAR_ARCHIVE);
	pCvar_ZombieMenu = gEngfuncs.pfnRegisterVariable("mh_zombiemenu", "1", FCVAR_ARCHIVE);

	cl_crosshair_type = gEngfuncs.pfnRegisterVariable("cl_crosshair_type", "0", FCVAR_ARCHIVE);
	cl_gunsmoke = gEngfuncs.pfnRegisterVariable("cl_gunsmoke", "1", FCVAR_ARCHIVE);

	/*cl_righthand = gEngfuncs.pfnGetCvarPointer("cl_righthand");

	if (!cl_righthand)
		cl_righthand = gEngfuncs.pfnRegisterVariable("cl_righthand", "1", FCVAR_ARCHIVE);*/


	BTEPanel_Init();
	BTEBuyMenu_Init();
	Event_Init();
	UI_Init();

	g_iSniperScope[0] = FindTexture("sprites\\scope_arc_nw");
	g_iSniperScope[1] = FindTexture("sprites\\scope_arc_ne");
	g_iSniperScope[2] = FindTexture("sprites\\scope_arc_sw");
	g_iSniperScope[3] = FindTexture("sprites\\scope_arc");
	
	/*g_iTextTexture = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iTextTexture,"test",true,true);*/

	/*int g_iTextTexture = g_pSurface->CreateNewTextureID();
	g_pSurface->DrawSetTextureFile(g_iTextTexture,"models\\texture\\#256256m2_p",true,true);*/

	g_pMetaHookAPI->InlineHook(g_pfnCHudAmmo_DrawCrosshair, CHudAmmo_DrawCrosshair, (void *&)g_pfnCHudAmmo_DrawCrosshair);
	g_pMetaHookAPI->InlineHook(g_pfnHudSniperScope_Draw, HudSniperScope_Draw, (void *&)g_pfnHudSniperScope_Draw);
	//gEngfuncs.pfnAddCommand("weapondata_reload", WeaponInitialize);

	/*g_hCurrentFont = g_pSurface->CreateFont();
	g_pSurface->AddCustomFontFile("df_gb_y9.ttf");
	g_hCurrentFont = g_pSchemeManager->("a");*/

	return gExportfuncs.HUD_Init();
}




int HUD_VidInit(void)
{
	g_iMod = 0;
	g_iWeaponLimit = 0;
	g_bAlive = false;
	g_pOverview->m_bCanCheck = false;
	bLoadedSky = false;
	g_mgui_candraw = 0;
	g_pOverview->m_pSprite = NULL;
	g_fCountDown = 0;
	g_fBombEntityTime = 0.0;
	g_zb3_menu_time = 0.0;
	g_isShowingZbMenu = 0;
	g_iHookVAngle = 0;
	g_zb_nvg = 0;
	g_CHudAmmo.SetNvgOn(false);
	g_iShowCustomCrosshair = 0;

	MessageInitialize();
	DisplayInitialize();
	ZombieMod3UIInit();
	ZombieMod4UIInit();
	DrawFontTextInitialize();
	TAB_Panel_Init();
	DrawExtraAmmoInitialize();
	g_ScoreBoard.Init();
	DrawGDBoardInitialize();
	DrawImageInitialize();
	QuestInit();
	DrawIconInitialize();
	DrawTargaImageInitialize();
	DeathMsg_Init();
	DrawRetinaReset();
	BTEPanel_TeamSuit_Reset();
	BTEPanel_BuyMenu_Reset();
	ResetZe();
	g_CHudAmmo.VidInit();
	if(!bLoadedTga)
	{
		DrawTgaLoadList();
		bLoadedTga = true;
	}

	g_ZBSboard.Init();

	g_fMuzzleTime = 0;
	g_Menu_Drawing_time = 0;
	g_Menu_Drawing = 0;
	key_last_press = 0.0;
	g_Next_Key_CanUse = 0.0;

	memset(g_Entity_Index,0,sizeof(g_Entity_Index));
	memset(g_szWeaponSkin,0,sizeof(g_szWeaponSkin));
	memset(vPlayer,0,sizeof(vPlayer));
	memset(g_PlayerExtraInfo,0,sizeof(g_PlayerExtraInfo));
	/*memset(g_szModelPrecache,0,sizeof(g_szModelPrecache));
	g_iModelPrecacheNums = 0;*/

	cl_righthand = gEngfuncs.pfnGetCvarPointer("cl_righthand");

	cl_dynamiccrosshair = gEngfuncs.pfnGetCvarPointer("cl_dynamiccrosshair");
	cl_crosshair_color = gEngfuncs.pfnGetCvarPointer("cl_crosshair_color");
	cl_crosshair_size = gEngfuncs.pfnGetCvarPointer("cl_crosshair_size");
	cl_crosshair_translucent = gEngfuncs.pfnGetCvarPointer("cl_crosshair_translucent");

	WeaponInitialize();	

	return gExportfuncs.HUD_VidInit();
}
int HUD_UpdateClientData(client_data_t *pClientData, float flTime)
{
	g_iWeaponBit = pClientData->iWeaponBits;
	
	return gExportfuncs.HUD_UpdateClientData(pClientData, flTime);
}
void HUD_ProcessPlayerState(struct entity_state_s *dst, const struct entity_state_s *src)
{
	cl_entity_t *pPlayer = gEngfuncs.GetLocalPlayer();

	if (dst->number == pPlayer->index)
	{
		//g_iTeamNumber = g_PlayerExtraInfo[pPlayer->index].teamnumber;
		g_iUser1 = src->iuser1;
		g_iUser2 = src->iuser2;
		g_iUser3 = src->iuser3;
	}

	gExportfuncs.HUD_ProcessPlayerState(dst, src);
}


int HUD_Redraw(float time, int intermission)
{
	int iResult = gExportfuncs.HUD_Redraw(time, intermission);

	// VGUI2 Test
	
	/*g_pSurface->DrawSetTexture(g_iTextTexture);
	g_pSurface->DrawSetColor(255,255,255,255);
	int w,h;
	g_pSurface->DrawGetTextureSize(g_iTextTexture,w,h);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	g_pSurface->DrawTexturedRect(400,400,400+w,400+h);*/
	
#if 0
	g_pSurface->DrawSetTextFont(g_hCurrentFont);
	gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
	g_pSurface->DrawSetTextColor(255,255,255,255);
	g_pSurface->DrawSetTextPos(0, g_sScreenInfo.iHeight/2);
	g_pSurface->DrawPrintText(L"啊咧 Test", 10);
#endif

#if 0
	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	Tri_BindTexture(GL_TEXTURE_2D, 6138);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(100,100+512,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(100+256,100+512,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(100+256,100,0);
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(100,100,0);
	gEngfuncs.pTriAPI->End();
#endif


	DrawRetina();
	ZombieMod4UIRedraw();
	BinkRedraw2();


	DrawTgaRedraw();
	DrawFontTextRedraw();
	DeathRunRedraw();
	DrawImageRedraw();	
	gEngfuncs.pfnDrawConsoleString( -10, -10, "!" );
	DisplayRedraw(time, intermission);
	DrawExtraAmmoRedraw();
	


	g_ScoreBoard.Redraw();
	DrawGDBoardRedraw();

	QuestRedraw();
	DrawRespawnBar();
	DrawFollowIcon();
	ZombieEscapeRedraw();	

	g_ZBSboard.Redraw();
	//int iValue = int(pCvar_DrawScope->value);
	//gEngfuncs.Con_Printf("!!! %d !!!!\n",iValue);

	

	
	ZombieMod3UIRedraw();

	DeathMsgRedraw(time);

	if(g_pOverview->CanDraw())
	{
		g_pOverview->EntityESP();
	}

	DrawMenu();

	g_CHudAmmo.Draw(time);

	TAB_Panel_Redraw(); // LAST !
	MGUI_Redraw();
	
	/*g_pSurface->DrawSetTextureFile(g_iTextTexture,"models\\texture\\#256256m2_p",true,true);
	int w,h;
	g_pSurface->DrawGetTextureSize(g_iTextTexture,w,h);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
	g_pSurface->DrawTexturedRect(400,400,400+w,400+h);*/

	//MH_DrawTGAFunction(g_MHTga[79].texid,255,255,255,255,500,500,1.0);
	
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	return iResult;
}

void HUD_DrawTransparentTriangles(void)
{
	if (g_pOverview->CanDraw())
		g_pOverview->Draw();

	gExportfuncs.HUD_DrawTransparentTriangles();
}
float g_skycolor[3];
void V_CalcRefdef(struct ref_params_s *pParams)
{
	if(g_iHookVAngle && g_bAlive && g_iBTEWeapon == 8)
	{
		if(!g_vecVAngle[0] && !g_vecVAngle[1])
		{
			g_vecVAngle[0] = pParams->cl_viewangles[0];
			g_vecVAngle[1] = pParams->cl_viewangles[1];
			g_vecVAngle[2] = pParams->cl_viewangles[2];
		}
		
		if(pParams->cl_viewangles[0] > 40.0)
			pParams->cl_viewangles[0] = 40.0;
		if(pParams->cl_viewangles[0] < -40.0)
			pParams->cl_viewangles[0] = -40.0;

		if(g_vecVAngle[1] + 75.0 > 360 || g_vecVAngle[1] - 75.0 < 0)
		{
			if(g_vecVAngle[1] + 75.0 > 360)
			{
				if(pParams->cl_viewangles[1] > g_vecVAngle[1] + 75.0 - 360 && pParams->cl_viewangles[1] < g_vecVAngle[1] - 150.0)
					pParams->cl_viewangles[1] = g_vecVAngle[1] + 75.0 - 360;
				if(pParams->cl_viewangles[1] < g_vecVAngle[1] - 75.0 && pParams->cl_viewangles[1] > g_vecVAngle[1] - 150.0)
					pParams->cl_viewangles[1] = g_vecVAngle[1] - 75.0;
			}
			if(g_vecVAngle[1] - 75.0 < 0)
			{
				if(pParams->cl_viewangles[1] > g_vecVAngle[1] + 75.0 && pParams->cl_viewangles[1] < g_vecVAngle[1] + 150.0)
					pParams->cl_viewangles[1] = g_vecVAngle[1] + 75.0;
				if(pParams->cl_viewangles[1] < g_vecVAngle[1] - 75.0 + 360.0 && pParams->cl_viewangles[1] > g_vecVAngle[1] + 150.0)
					pParams->cl_viewangles[1] = g_vecVAngle[1] - 75.0 + 360.0;
			}
		}
		else
		{
			if(pParams->cl_viewangles[1] > g_vecVAngle[1] + 75.0)
				pParams->cl_viewangles[1] = g_vecVAngle[1] + 75.0;
			if(pParams->cl_viewangles[1] < g_vecVAngle[1] - 75.0)
				pParams->cl_viewangles[1] = g_vecVAngle[1] - 75.0;
		}
		
	}
	
	if(pParams->movevars->skycolor_b != 255.0 && pParams->movevars->skycolor_r != 255.0 && pParams->movevars->skycolor_g != 255.0)
	{
		g_skycolor[0] = pParams->movevars->skycolor_r;
		g_skycolor[1] = pParams->movevars->skycolor_g;
		g_skycolor[2] = pParams->movevars->skycolor_b;
	}
	
	if(g_zb_nvg)
	{
		pParams->movevars->skycolor_b = pParams->movevars->skycolor_r = pParams->movevars->skycolor_g = 255.0;
	}
	else
	{
		pParams->movevars->skycolor_r = g_skycolor[0];
		pParams->movevars->skycolor_g = g_skycolor[1];
		pParams->movevars->skycolor_b = g_skycolor[2];
	}

	g_pOverview->CalcRefdef(pParams);
	gExportfuncs.V_CalcRefdef(pParams);

	static cl_entity_t *viewent;
	static model_t *pModel=NULL;
	viewent = gEngfuncs.GetViewModel();
	
	if (viewent)
	{
		//RebuildTattoo(pModel);

		if(viewent->model != pModel)
		{
			pModel = viewent->model;
			RebuildTattoo(pModel);
			CheckViewEntity();
		}

		if (g_iViewEntityBody >= 0)
			viewent->curstate.body = g_iViewEntityBody;

		if (g_iViewEntityRenderMode >= 0)
		{
			viewent->curstate.rendermode = g_iViewEntityRenderMode;
			viewent->curstate.renderfx = g_iViewEntityRenderFX;
			viewent->curstate.renderamt = g_iViewEntityRenderAmout;
			viewent->curstate.rendercolor = g_byViewEntityRenderColor;
		}
		viewent->curstate.skin = g_iSetupSkin;
	}
	
	if(!bLoadedSky)
	{
		char levelname[128];
		strcpy(levelname,gEngfuncs.pfnGetLevelName()+5);
		if(levelname && strstr(levelname,"ze_"))
		{
			LoadZePoint(levelname);
		}

		char *suf[6] = { "rt", "bk", "lf", "ft", "up", "dn" };
		char sName[128];
		char skyname[64];
		sprintf(skyname,pParams->movevars->skyName);
		int index = 0;

		for(int i=0;i<6;i++)
		{
			index = 5800+ i;
			sprintf(sName,"cstrike\\gfx\\high_env\\%s%s.tga",skyname,suf[i]);
			imagedata_s tTex;
			if(!Image_LoadImage(sName,&tTex,&index))
			{
				LogToFile("无法打开该地图的高清天空纹理，请使用正常纹理");
				LogToFile("如果下列文件存在%s的，将会应用新天空纹理贴图",sName);
				continue;
			}
			LogToFile("为该地图加载了高清天空纹理贴图[天空名称：%s]",skyname);
		}
		bLoadedSky = true;
	}
	
	if (pParams->spectator || !g_pOverview->CanDraw())
		return;

	if (!pParams->nextView)
	{
		pParams->nextView = 1;
		pParams->onlyClientDraw = false;
	}
	else
	{
		pParams->viewport[0] = pParams->viewport[1] = 0;
		pParams->viewport[2] = g_pOverview->m_pRect->value;
		pParams->viewport[3] = g_pOverview->m_pRect->value;
		pParams->nextView = 0;
		pParams->onlyClientDraw = true;
		pParams->viewangles[0] = 90;

		//pParams->vieworg[2] =  (10+1.2*g_pOverview->m_pRect->value)*4.1f/g_pOverview->m_flZoom;
	}
	g_pOverview->m_iMaxClient = pParams->maxclients;
	g_pOverview->m_bCanDraw = pParams->onlyClientDraw ? true : false;	
	
	return;
}
int HUD_GetStudioModelInterface(int iVersion, struct r_studio_interface_s **ppStudioInterface, struct engine_studio_api_s *pEngineStudio)
{
	memcpy(&IEngineStudio, pEngineStudio, sizeof(engine_studio_api_t));
	LogToFile("===初始化模型接口===");
	g_iVideoMode = (IEngineStudio.IsHardware() == 1);
	g_iVideoQuality;
	if(g_iVideoMode)
	{
		LogToFile("视频模式:OpenGL");
		char *p = (char *)glGetString(GL_VERSION);
		if(*p)
		{
			char s = *p;
			LogToFile("OpenGL 版本:%s",p);
			if(s == '1')
			{
				LogToFile("自动检测:低质量");
				//MessageBoxA(NULL,"低版本OpenGL 可能会发生白色手臂或TGA变白 请更新驱动","视频信息",MB_OK);
				g_iVideoQuality = 0;
			}
			else 
			{
				LogToFile("自动检测:高质量");
				g_iVideoQuality = 1;
			}
		}
	}
	else 
	{
		LogToFile("视频模式:D3D");
		//MessageBoxA(NULL,"当前为D3D视频模式 推荐OpenGL","视频信息",MB_OK);
	}
	//DrawTgaLoadList(); !!!
	MGUI_Init();

	char szFileName[128];
	sprintf(szFileName,"metahook/font/gamefont_%s.ttf",g_szLanguage);

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	hFind = FindFirstFile(szFileName, &FindFileData);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		LogToFile("找不到字体文件:gamefont_%s.ttf",g_szLanguage);
		sprintf(szFileName,"metahook/font/gamefont_csbte.ttf");
	} 
	else 
	{		
		FindClose(hFind);
	}

	
	Fonts_Init(szFileName,16,16); 
	//
	return gExportfuncs.HUD_GetStudioModelInterface(iVersion, ppStudioInterface, pEngineStudio);
}
void HUD_PlayerMove(struct playermove_s *pPlayerMove, int iServer)
{
	gEngfuncs.pEventAPI->EV_LocalPlayerViewheight(g_vecEyePos);	
	VectorCopy(pPlayerMove->angles,g_vecVAngles);
	VectorAdd(g_vecEyePos, pPlayerMove->origin, g_vecEyePos);
	VectorAdd(pPlayerMove->origin,pPlayerMove->view_ofs,g_vecEye);
	return gExportfuncs.HUD_PlayerMove(pPlayerMove, iServer);
}
int (*Engfunc_Call_AddVisibleEntity)(struct cl_entity_s *pEntity);
#define AMPLITUDE 0.7
int Engfunc_AddVisibleEntity(struct cl_entity_s *pEntity)
{	
	if(strstr(pEntity->model->name,"zb_skill_headshot") || strstr(pEntity->model->name,"zb_meleeup"))
	{
		cl_entity_t *pPlayer = NULL;
		pPlayer = gEngfuncs.GetEntityByIndex(pEntity->curstate.aiment);		
		if(!pEntity) Engfunc_Call_AddVisibleEntity(pEntity);
		/*if(vPlayer[pEntity->curstate.aiment].team==2)
			pEntity->curstate.renderamt = 0;*/

		pEntity->origin[0] = pPlayer->origin[0];
		pEntity->origin[1] = pPlayer->origin[1];
		pEntity->origin[2] = pPlayer->origin[2];

		return Engfunc_Call_AddVisibleEntity(pEntity);
	}
	
	if(pEntity->curstate.iuser4 == MUZZLEFLASH_GUITAR)
	{
		float fStart;
		float fFrame; 
		//float ff;
		fStart = pEntity->curstate.fuser4;
		//ff = g_flTime - pEntity->curstate.fuser4;
		fFrame = (g_flTime - fStart) * 10.0f;
		pEntity->curstate.frame = fFrame;
		float fRad = g_flTime - fStart;
		float fMultiple = AMPLITUDE * sin (1.5f * M_PI * fRad );

		float vR[3];
		gEngfuncs.pfnAngleVectors(g_vecVAngles,NULL,vR,NULL);
		vR[0] *= fMultiple;
		vR[1] *= fMultiple;
		vR[2] *= fMultiple; 
		VectorAdd(pEntity->origin,vR,pEntity->origin);
		pEntity->origin[2] = pEntity->origin[2] + 0.2f;
		

	}
	else if(pEntity->curstate.iuser4 == MUZZLEFLASH_PPQQ)
	{
		float fFrame;
		fFrame = pEntity->curstate.frame;

		if(pEntity->curstate.fuser3<g_flTime)
		{
			pEntity->curstate.fuser3 = g_flTime + 0.02f; 
			fFrame += 1.0f;
		} 
		pEntity->curstate.frame = fFrame;
		static cl_entity_s *pModel;
		pModel = gEngfuncs.GetViewModel();
		if(pModel) 
		{
			pEntity->origin[0] = pModel->attachment[pEntity->curstate.iuser3][0];
			pEntity->origin[1] = pModel->attachment[pEntity->curstate.iuser3][1];
			pEntity->origin[2] = pModel->attachment[pEntity->curstate.iuser3][2]; 
		}
	}
	return Engfunc_Call_AddVisibleEntity(pEntity);
}
int ModelFrameCount(model_t *mod)
{
	if (!mod || !mod->cache.data)
		return 0;

	if (mod->type == mod_sprite)
	{
		return ((msprite_t *)mod->cache.data)->numframes;
	}
	else
		gEngfuncs.Con_DPrintf("ModelFrameCount nonsupport type:%d\n", mod->type);

	return 0;
}

void MuzzleflashCallback ( struct tempent_s *ent, float frametime, float currenttime )
{
	cl_entity_s *pModel;
	pModel = gEngfuncs.GetViewModel();
	if(pModel) 
	{		
		ent->entity.origin[0] = pModel->attachment[ent->entity.curstate.iuser1][0];
		ent->entity.origin[1] = pModel->attachment[ent->entity.curstate.iuser1][1];
		ent->entity.origin[2] = pModel->attachment[ent->entity.curstate.iuser1][2]; 
	}
	
	/*if(currenttime < ent->entity.curstate.fuser1 + ent->entity.curstate.framerate)
		return;

	if(ent->entity.curstate.frame < ent->frameMax - 1)
	{
		ent->entity.curstate.frame ++;
		ent->entity.curstate.fuser1 = currenttime + ent->entity.curstate.framerate;
	}*/


	if(ent->entity.curstate.frame < ent->frameMax - 1)
		ent->entity.curstate.frame ++;
	else
		ent->die = currenttime + 0.01;
}

void HUD_StudioEvent(const struct mstudioevent_s *pEvent, const struct cl_entity_s *pEntity)
{
	if(pEvent&&pEntity)
	{
		if(pEvent->event != 5001 && pEvent->event != 5011 && pEvent->event != 5021 && pEvent->event != 5031) return gExportfuncs.HUD_StudioEvent(pEvent, pEntity);
		int iAttachment = pEvent->event - 5000 - 1;
		iAttachment = iAttachment / 10;
		if(pEvent->options[0] == '#')
		{
			int iMuzz/*, iAttachment*/;
			float fScale, fDie, fR;
			
			char options[64];
			strcpy(options, pEvent->options);
			int len = strlen(options);
			options[len] = ' ';
			len += 1;
			for(int i=1;i<len;i++)
			{
				char result[8], *ptr;
				memset(result, 0, sizeof(result));
				switch(options[i])
				{
					case 'I':
					{
						ptr = strstr(options + i, " ");
						int position = ptr-options;
						strncpy(result, options + i + 1, position - i - 1);
						iMuzz = atoi(result);
						break;
					}
					case 'R':
					{
						ptr = strstr(options + i, " ");
						int position = ptr-options;
						strncpy(result, options + i + 1, position - i - 1);
						fR = atof(result);
						break;
					}
					case 'S':
					{
						ptr = strstr(options + i, " ");
						int position = ptr-options;
						strncpy(result, options + i + 1, position - i - 1);
						fScale = atof(result);
						break;
					}
					case 'T':
					{
						ptr = strstr(options + i, " ");
						int position = ptr-options;
						strncpy(result, options + i + 1, position - i - 1);
						fDie = atof(result);
						break;
					}
					case 'A':
					{
						ptr = strstr(options + i, " ");
						int position = ptr-options;
						strncpy(result, options + i + 1, position - i - 1);
						//iAttachment = atoi(result);
						break;
					}
				}
			}
			struct model_s *pModel;
			TEMPENTITY *pEnt;

			char muzz[32];
			sprintf(muzz,"sprites/muzzleflash%d.spr",iMuzz);
			pModel = IEngineStudio.Mod_ForName(muzz, 0);

			int frameCount = ModelFrameCount(pModel);
			
			pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh((float *)&pEntity->attachment[iAttachment], pModel);
			pEnt->entity.curstate.rendermode = kRenderTransAdd;
			pEnt->entity.curstate.renderamt = 255;
			pEnt->entity.curstate.renderfx = 0;
			pEnt->entity.curstate.scale = fScale;
			pEnt->entity.curstate.rendercolor.r = -1;
			pEnt->entity.curstate.rendercolor.g = -1;
			pEnt->entity.curstate.rendercolor.b = -1;
			pEnt->entity.curstate.frame = gEngfuncs.pfnRandomLong(0, frameCount - 1);
			pEnt->entity.angles[0] = 0;
			pEnt->entity.angles[1] = 0;
			//pEnt->entity.angles[2] = gEngfuncs.pfnRandomLong(0, 1) ? 359.9 - gEngfuncs.pfnRandomLong(0, iP/2) : gEngfuncs.pfnRandomLong(0, iP/2);
			if (fR == 2)
				pEnt->entity.angles[2] = gEngfuncs.pfnRandomLong(0, 360);
			else if (fR == 1.5)
				pEnt->entity.angles[2] = gEngfuncs.pfnRandomLong(0, 1) ? 359.9 - gEngfuncs.pfnRandomLong(0, 15) : gEngfuncs.pfnRandomLong(0, 15);
			else
				pEnt->entity.angles[2] = 0;

 			pEnt->die = gEngfuncs.GetClientTime() + fDie;
			pEnt->frameMax = frameCount;

			if (fDie > 0.01)
			{
				pEnt->entity.curstate.frame = 0;
				pEnt->entity.curstate.framerate = fDie / frameCount;
				pEnt->flags |= FTENT_CLIENTCUSTOM;
				pEnt->callback = MuzzleflashCallback;
				pEnt->entity.curstate.iuser1 = iAttachment;
			}
			
			Engfunc_Call_AddVisibleEntity( &(pEnt->entity));

			return;

		}
		else/* if(strlen(pEvent->options) > 2)*/
		{
			int type = atoi(pEvent->options);
			
			int v4 = 10 * type / 100000;
			int v5 = type % 100000;

			if (v5 >= 10000)
				v5 %= 10000;

			int extra = v5 / 1000;
			int v6 = v5 % 1000;
			int v7 = v6 % 100;
			bool v8 = (v6 / 100) == 1;

			int index = v4 + v7 % 10;

			if (index == 3)
				index = 0;
			else if (index > 3)
				index--;

			float scale = (v7 / 10) * 0.1;

			if (scale == 0)
				scale = 0.5;

			if (extra == 0)
			{
				char muzz[32];
				sprintf(muzz, "sprites/muzzleflash%d.spr", index + 1);

				struct model_s *pModel;
				pModel = IEngineStudio.Mod_ForName(muzz, 0);

				float pos[3];
				pos[0] = pEntity->attachment[iAttachment][0];
				pos[1] = pEntity->attachment[iAttachment][1];
				pos[2] = pEntity->attachment[iAttachment][2];

				int frameCount = ModelFrameCount(pModel);
				TEMPENTITY *pTemp = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(pos, pModel);

				if (!pTemp)
					return;

				pTemp->entity.curstate.rendermode = 5;
				pTemp->entity.curstate.renderamt = 255;
				pTemp->entity.curstate.scale = scale;
				pTemp->entity.curstate.renderfx = 0;
				pTemp->entity.curstate.rendercolor.r = -1;
				pTemp->entity.curstate.rendercolor.g = -1;
				pTemp->entity.curstate.rendercolor.b = -1;
				pTemp->entity.origin[0] = pos[0];
				pTemp->entity.origin[1] = pos[1];
				pTemp->entity.origin[2] = pos[2];
				pTemp->die = gEngfuncs.GetClientTime() + 0.01;
				pTemp->entity.curstate.frame = gEngfuncs.pfnRandomLong(0, frameCount - 1);
				pTemp->entity.angles[0] = 0;
				pTemp->entity.angles[1] = 0;
				pTemp->entity.angles[2] = 0;
				pTemp->frameMax = frameCount;

				if (!v8)
					pTemp->entity.angles[2] = gEngfuncs.pfnRandomLong(0, index ? 359 : 20);

				Engfunc_Call_AddVisibleEntity( &(pTemp->entity));	
			}
			return;
		}
	}
	gExportfuncs.HUD_StudioEvent(pEvent, pEntity);
}

void HUD_WeaponsPostThink(local_state_s *from, local_state_s *to, usercmd_t *cmd, double time, unsigned int random_seed)
{
	g_iCurrentWeapon = to->client.m_iId;
	g_iPlayerFlags = from->client.flags;
	//g_flPlayerSpeed = Length(from->client.velocity);
	g_iWeaponFlags = from->client.vuser4[0];
	//g_iFreezeTimeOver = from->client.iuser3 & IUSER3_FREEZETIMEOVER;
}
void HUD_PostRunCmd(struct local_state_s *from, struct local_state_s *to, struct usercmd_s *cmd, int runfuncs, double time, unsigned int random_seed)
{
	HUD_WeaponsPostThink(from, to, cmd, time, random_seed);
	
	if(cmd)
	{
		if(cmd->buttons & IN_ATTACK2)
		{
			g_iButton = 1;
		}
		else g_iButton = 0;
	}
	return gExportfuncs.HUD_PostRunCmd(from, to, cmd, runfuncs, time, random_seed);
}
void HUD_TempEntUpdate(double dblFrameTime, double dblClientTime, double dblGravity, struct tempent_s **ppTempEntFree, struct tempent_s **ppTempEntActive, int (*pfnAddVisibleEntity)(struct cl_entity_s *pEntity), void (*pfnTempEntPlaySound)(struct tempent_s *pTemp, float flDamp))
{
	Engfunc_Call_AddVisibleEntity = pfnAddVisibleEntity;
	pfnAddVisibleEntity = &Engfunc_AddVisibleEntity;
	gExportfuncs.HUD_TempEntUpdate(dblFrameTime, dblClientTime, dblGravity, ppTempEntFree, ppTempEntActive, pfnAddVisibleEntity, pfnTempEntPlaySound);
}


int HUD_AddEntity(int iType, struct cl_entity_s *pEntity, const char *pszModel)
{
	/*if(strstr(pszModel, "models/bte_wpn/p_"))
	{
		studiohdr_t	*pstudio;
		mstudiotexture_t	*ptexture;
		pstudio = (studiohdr_t*)IEngineStudio.Mod_Extradata(pEntity->model);
		ptexture = (mstudiotexture_t *)(((byte *)pstudio) + pstudio->textureindex);	
		for(int i = 0; i < pstudio->numtextures; i++ )
		{
			if(ptexture[i].name[0] == '#')
			{
				char name[64];
				sprintf(name, "models\\texture\\%s", ptexture[i].name);
				name[strlen(name)-4] = 0;
				int tid = FindTexture(name);
				if (tid ==0) continue;
				ptexture[i].index = g_Texture[tid].iTexture;
				ptexture[i].height = g_Texture[tid].iHeight;
				ptexture[i].width = g_Texture[tid].iWidth;				
			}
		}
	}*/
	if(pEntity->player)  
	{
		int index = pEntity->index;
		vPlayer[index].info = pEntity;
		if(!(g_PlayerExtraInfo[index].iFlag &SCOREATTRIB_DEAD)) vPlayer[index].killtime = gEngfuncs.GetClientTime()+1.0;
	}
	/*else if(pszModel && strstr(pszModel,"spear"))
	{
		if(pEntity->curstate.iuser1)
		{
			cl_entity_s *pEnt = gEngfuncs.GetEntityByIndex(pEntity->curstate.iuser1);
			if(pEnt)
			{
				pEntity->origin[0] = pEnt->origin[0] + pEntity->curstate.vuser2[0];
				pEntity->origin[1] = pEnt->origin[1] + pEntity->curstate.vuser2[1];
				pEntity->origin[2] = pEnt->origin[2] + pEntity->curstate.vuser2[2];
			}
		}		
	}*/
	else if(pszModel && strstr(pszModel,"backpack"))
	{
		g_iBombEntity = pEntity->index;
		g_fBombEntityTime = g_flTime + 0.5f;
	}
	else if(pszModel && strstr(pszModel,"supply"))
	{
		pEntity->curstate.fuser1 = g_flTime + 0.1f;
		pEntity->curstate.iuser1 = 1;
	}
	else if(pszModel && strstr(pszModel,"zombitrap"))
	{
		pEntity->curstate.fuser1 = g_flTime + 0.1f;
		pEntity->curstate.iuser1 = 2;
	}
	else if(pEntity)
	{
		if(pEntity->model->name)
		{
			if(strstr(pEntity->model->name,"s_grenade_spark"))
			{
				if(g_Entity_Index[pEntity->index] < g_flTime)
				{
					int iIndex;
					gEngfuncs.CL_LoadModel("sprites/smoke_ia.spr", &iIndex);
					g_Entity_Index[pEntity->index] = g_flTime+0.05f;
					gEngfuncs.pEfxAPI->R_SparkShower(pEntity->origin);
				}
			}
			if(strstr(pEntity->model->name,"rpgrocket"))
			{
				if(g_Entity_Index[pEntity->index] < g_flTime)
				{
					int iIndex;
					gEngfuncs.CL_LoadModel("sprites/smoke_ia.spr", &iIndex);
					g_Entity_Index[pEntity->index] = g_flTime+0.05f;
					gEngfuncs.pEfxAPI->R_Explosion(pEntity->origin,iIndex,0.35f,10.0f,14);
				}
			}
			else if(strstr(pEntity->model->name,"ef_dragontail")&&pEntity->curstate.owner == gEngfuncs.GetLocalPlayer()->index)
			{
				Vector vecForw;
				gEngfuncs.pfnAngleVectors(g_vecAngles,vecForw,NULL,NULL);
				pEntity->origin[0] = (g_vecEye[0] + vecForw[0]*5.0f);
				pEntity->origin[1] = (g_vecEye[1] + vecForw[1]*5.0f);
				pEntity->origin[2] = (g_vecEye[2] + vecForw[2]*5.0f);
			}
			/*else if(strstr(pEntity->model->name,"spear.mdl") && !pEntity->curstate.iuser4)
			{
				int iIndex;
				gEngfuncs.CL_LoadModel("sprites/smoke.spr", &iIndex);
				gEfxAPI.R_BeamFollow(pEntity->index, iIndex, 1.0, 0.1, 155, 255, 218, 100);
				pEntity->curstate.iuser4 = 1;
			}*/
			

			/*if(strstr(pEntity->model->name,"ef_dragonsword")&&pEntity->curstate.owner == gEngfuncs.GetLocalPlayer()->index)
			{
				vec3_t vecForw;
				gEngfuncs.pfnAngleVectors(g_vecAngles,vecForw,NULL,NULL);
				pEntity->origin = (g_vecEye + vecForw*10.0f);
			}*/
			/*if(strstr(pEntity->model->name,"ef_dragontail")&&pEntity->curstate.owner == gEngfuncs.GetLocalPlayer()->index)
			{
				vec3_t vecForw;
				gEngfuncs.pfnAngleVectors(g_vecAngles,vecForw,NULL,NULL);
				pEntity->origin = (g_vecEye + vecForw*10.0f);
			}*/
		}
		/*if(strstr(pEntity->model->name,"svdex_smoke"))
		{
			cl_entity_t *viewent;
			viewent = gEngfuncs.GetViewModel();
			if (viewent && viewent->model->name && strstr(viewent->model->name,"bte_wpn"))
			{
				if(strstr(viewent->model->name,"svdex"))
				pEntity->curstate.frame += 0.2;
				pEntity->origin = gEngfuncs.GetViewModel()->attachment[2];
			}
			else
			{
				float fVec[3];
				fVec[0] = fVec[1] = fVec[2] = 8192.0;
				pEntity->origin = fVec;
			}
		}*/
		/*if(strstr(pEntity->model->name,"_head")) 
		{
			if(pEntity->curstate.owner>0 && pEntity->curstate.owner<33)
			{
				float vFor[3];
				cl_entity_s *pEnt = gEngfuncs.GetEntityByIndex(pEntity->curstate.owner);
				gEngfuncs.pfnAngleVectors((float*)pEnt->angles,vFor,NULL,NULL);
				pEntity->origin[2] = pEnt->origin[2] + 17.0f;
				vFor[0] *= 3.0f;
				vFor[1] *= 3.0f;
				//vFor[2] *= 20.0f;

				pEntity->origin[1] = pEnt->origin[1]+vFor[1];
				pEntity->origin[0] = pEnt->origin[0]+vFor[0];
				pEntity->angles[1] = pEnt->angles[1];
				pEntity->angles[0] = pEnt->angles[0];
			}
		}*/
	}
	return gExportfuncs.HUD_AddEntity(iType, pEntity, pszModel);
}
#define KEY_DOT	96
#define KEY_ESC	27
#define KEY_R	114

int HUD_Key_Event(int eventcode, int keynum, const char *pszCurrentBinding)
{	
	if(g_Next_Key_CanUse>g_flTime)
	{
		g_mgui_keynum = -1;
		return 0;
	}
	
	if(keynum == 53)
	{
		//g_mgui_candraw = 1 - g_mgui_candraw;
	}
	if(g_mgui_candraw)
	{
		g_mgui_keynum = keynum;
		g_Next_Key_CanUse = g_flTime + 0.15;
		if(keynum != 96 &&keynum != 27)
		{
			return 0;
		}
	}
	if(keynum>=48 && keynum<=57 && ((g_Menu_Drawing && pCvar_DrawMenu->value) || g_isShowingZbMenu) && key_last_press<g_flTime)
	{
		if(g_Menu_Can_Press[keynum-48] || g_isShowingZbMenu)
		{
		char szbuf[32];

		if(!g_isShowingZbMenu)
		{
			sprintf(szbuf, "menuselect %d\n", keynum-48);
		}
		else
		{
			if(keynum == '0')
			{
				sprintf(szbuf, "\n");
				g_zb3_menu_time = 0.0f;
			}
			else
				sprintf(szbuf, "bte_zb3_select_zombie %d\n", keynum-48-1);
		}

		gEngfuncs.pfnClientCmd(szbuf);
		gEngfuncs.pfnPlaySoundByName("sound/ui/menu_select.wav", 1.0);
		g_Menu_Drawing = 2;
		//低端极了
		key_last_press = g_flTime + 0.2;
		g_Menu_Drawing_time = g_flTime;
		g_zb3_menu_time = 0.0;
		}
		return 0; 
	}

	if(!g_Menu_Drawing && g_iMod == MOD_ZB3)
	{
		if(keynum == '5')
		{
			gEngfuncs.pfnClientCmd("speedup");
			gEngfuncs.pfnClientCmd("zbskill");
		}
		else if(keynum == '6')
		{
			gEngfuncs.pfnClientCmd("accshoot");
		}
		else if(keynum == '7')
		{
			gEngfuncs.pfnClientCmd("meleeup");
		}
	}

	return gExportfuncs.HUD_Key_Event(eventcode,keynum,pszCurrentBinding);
	
	if(!g_Menu_Drawing && g_iMod != MOD_ZB4 || (!g_Menu_Drawing && !pCvar_DrawMenu->value && g_iMod != MOD_ZB4)) return gExportfuncs.HUD_Key_Event(eventcode,keynum,pszCurrentBinding);
	if(!g_Menu_Drawing)
	{
	if(keynum == 53)
	{
		gEngfuncs.pfnClientCmd("zb4_kick");
	}
	else if(keynum == 54)
	{
		gEngfuncs.pfnClientCmd("zb4_accshoot");
	}
	else if(keynum == 55)
	{
		gEngfuncs.pfnClientCmd("meleeup");
	}	
	}
	return gExportfuncs.HUD_Key_Event(eventcode,keynum,pszCurrentBinding);
}