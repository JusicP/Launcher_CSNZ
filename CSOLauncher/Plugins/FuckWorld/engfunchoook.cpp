#include "base.h"
 
void (*pCommandImpulse)(void);
void (*pCommandInScoreDown)(void);
void (*pCommandInScoreUp)(void);
/*void (*pCommandInForwardUp)(void);
void (*pCommandInForwardDown)(void);*/
void (*pCommandInJumpDown)(void);
void (*pCommandInDuckDown)(void);
void (*pCommandInDuckUp)(void);

int	Engfunc_ClientCmd( char *szCmdString )
{	
	if(strstr(szCmdString,"menuselect"))
	{
		g_Menu_Drawing = 0;
	}
	else if(strstr(szCmdString,".mgui"))
	{
		//MGUI_ReadFromResourceFile(szCmdString);
		return 0;
	}

	return gEngfuncs.pfnClientCmd(szCmdString);
}
void Engfunc_WeaponAnim( int sequence, int body )
{
	if(g_iBTEWeapon == WPN_INFINITYEX)
	{
		if(g_iButton) return ;
	}
	else if(g_iBTEWeapon == WPN_SFSNIPER)
	{
		if(sequence >0 && sequence < 4)
		{
			return gEventAPI.EV_WeaponAnimation(1,body); 
		}
	}
	else if(g_iBTEWeapon == WPN_M200)
	{
		if(sequence >0 && sequence < 4)
		{
			if(g_iWeaponData[g_iWeapon].iClip<=1)
				return gEventAPI.EV_WeaponAnimation(3,body);
			else
				return gEventAPI.EV_WeaponAnimation(1,body);
		}
	}
	else if(g_iBTEWeapon == WPN_JANUS5)
	{
		if(sequence >= 3 && sequence <= 5)
		{
			if(g_iWeaponStat == 51)
				return gEventAPI.EV_WeaponAnimation(4, body);

			if(g_iWeaponStat == 52)
				return gEventAPI.EV_WeaponAnimation(8 + gEngfuncs.pfnRandomLong(0,2), body);

			return gEventAPI.EV_WeaponAnimation(3, body);
		}
	}
	else if(g_iBTEWeapon == WPN_JANUS3)
	{
		if(sequence >= 3 && sequence <= 5)
		{
			if(g_iWeaponStat == 51)
				return gEventAPI.EV_WeaponAnimation(4, body);

			if(g_iWeaponStat == 52)
				return gEventAPI.EV_WeaponAnimation(8 + gEngfuncs.pfnRandomLong(0,2), body);

			return gEventAPI.EV_WeaponAnimation(3, body);
		}
	}
	else if(g_iBTEWeapon == WPN_JANUS11)
	{
		if(sequence >= 3 && sequence <= 5)
		{
			if(g_iWeaponStat == 51)
				return gEventAPI.EV_WeaponAnimation(4, body);

			if(g_iWeaponStat == 52)
				return gEventAPI.EV_WeaponAnimation(8 + gEngfuncs.pfnRandomLong(0,2), body);

			return gEventAPI.EV_WeaponAnimation(3, body);
		}
	}
	else if(g_iBTEWeapon == WPN_JANUS7)
	{
		if(sequence >= 1 && sequence <= 2)
		{
			if(g_iWeaponStat == 51)
				return gEventAPI.EV_WeaponAnimation(5, body);

			if(g_iWeaponStat == 52)
				return gEventAPI.EV_WeaponAnimation(gEngfuncs.pfnRandomLong(9,10), body);

			return gEventAPI.EV_WeaponAnimation(3, gEngfuncs.pfnRandomLong(3,4));
		}
	}
	return gEventAPI.EV_WeaponAnimation(sequence,body);
}

void CmdFunc_InScoreDown(void)
{
	if(pCvar_DrawPanel->value<1) return pCommandInScoreDown();
	g_iPanelCanDraw = 1;
	if(g_iMod!= MOD_NONE && g_iMod!= MOD_ZE && g_iMod!= MOD_DR && g_iMod!= MOD_TDM && g_iMod!= MOD_HD && g_iMod!= MOD_FUNMODE && g_iMod!= MOD_BC && g_iMod!= MOD_GD && g_iMod!= MOD_DM && g_iMod!= MOD_SD && g_iMod!= MOD_ZB4 && g_iMod!= MOD_ZB && g_iMod!= MOD_ZB3 && g_iMod!= MOD_ZBS) return pCommandInScoreDown();
	return;
}
void CmdFunc_InScoreUp(void)
{
	if(pCvar_DrawPanel->value<1) return pCommandInScoreUp();
	g_iPanelCanDraw = 0;
	if(g_iMod!= MOD_NONE && g_iMod!= MOD_TDM && g_iMod!= MOD_DM && g_iMod!= MOD_HD && g_iMod!= MOD_ZE && g_iMod!= MOD_FUNMODE && g_iMod!= MOD_DR && g_iMod!= MOD_BC && g_iMod!= MOD_GD && g_iMod!= MOD_SD && g_iMod!= MOD_ZB4 && g_iMod!= MOD_ZB && g_iMod!= MOD_ZB3 && g_iMod!= MOD_ZBS) return pCommandInScoreUp();
	return;
}
void CmdFunc_Impulse(void)
{
	if (gEngfuncs.Cmd_Argc() <= 3 || strncmp(gEngfuncs.Cmd_Argv(1), "[MetaHook]", 5))
	{
		pCommandImpulse();
		return;
	}

	if (!strcmp(gEngfuncs.Cmd_Argv(2), "player"))
	{
		if (!strcmp(gEngfuncs.Cmd_Argv(3), "join"))
			gEngfuncs.pfnServerCmd("#MetaHook join");

		return;
	}
}
void CmdFunc_InJumpDown()
{
	if(g_iHookVAngle && g_bAlive && g_iBTEWeapon == 8)
		return;
	else
		pCommandInJumpDown();
}
void CmdFunc_InDuckDown()
{
	if(g_iHookVAngle && g_bAlive && g_iBTEWeapon == 8)
		return;
	else
		pCommandInDuckDown();
}
void CmdFunc_InDuckUp()
{
	if(g_iHookVAngle && g_bAlive && g_iBTEWeapon == 8)
		return;
	else
		pCommandInDuckUp();
}
int EngFunc_AddCommand(char *szCmds, void (*pFunction)(void))
{

	if (!strcmp(szCmds, "impulse"))
	{
		pCommandImpulse = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, CmdFunc_Impulse);
		return 1;
	}
	else if (!strcmp(szCmds, "+score") || !strcmp(szCmds, "+showscores"))
	{
		pCommandInScoreDown = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, CmdFunc_InScoreDown);
		return 1;
	}
	else if(!strcmp(szCmds, "-score") || !strcmp(szCmds, "-showscores"))
	{
		pCommandInScoreUp = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, CmdFunc_InScoreUp);
		return 1;
	}
	else if(!strcmp(szCmds, "+jump"))
	{
		pCommandInJumpDown = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, CmdFunc_InJumpDown);
		return 1;
	}
	/*else if(!strcmp(szCmds, "+duck"))
	{
		pCommandInDuckDown = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, CmdFunc_InDuckDown);
		return 1;
	}*/
	else if(!strcmp(szCmds, "-duck"))
	{
		pCommandInDuckUp = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, CmdFunc_InDuckUp);
		return 1;
	}
	/*else if(!strcmp(szCmds, "+forward"))
	{
		pCommandInScoreUp = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, );
		return 1;
	}
	else if(!strcmp(szCmds, "-forward"))
	{
		pCommandInScoreUp = pFunction;
		gEngfuncs.pfnAddCommand(szCmds, );
		return 1;
	}*/
	return gEngfuncs.pfnAddCommand(szCmds, pFunction);
}
struct model_s *Engfunc_LoadMapSprite(const char *pszPath)
{
	return g_pOverview->m_pSprite = gEngfuncs.LoadMapSprite(pszPath);
}
byte *Engfunc_COM_LoadFile(char *pszPath, int iUseHunk, int *piLength)
{
	byte *pbResult = gEngfuncs.COM_LoadFile(pszPath, iUseHunk, piLength);

	if (!pbResult)
		return NULL;

	if (g_pOverview && !strncmp(pszPath, "overviews/", 10))
		g_pOverview->m_bCanCheck = true;

	return pbResult;
}
char *Engfunc_COM_ParseFile(char *pszData, char *pszToken)
{
	static char szToken[1024];
	char *pszFile, *pszResult = gEngfuncs.COM_ParseFile(pszData, pszToken);

	if (!g_pOverview || !g_pOverview->m_bCanCheck)
		return pszResult;

	if (!_stricmp(pszToken, "zoom"))
	{
		gEngfuncs.COM_ParseFile(pszResult, szToken);
		g_pOverview->m_flZoom = (float)atof(szToken);
	}
	else if (!_stricmp(pszToken, "origin"))
	{
		pszFile = gEngfuncs.COM_ParseFile(pszResult, szToken);
		g_pOverview->m_vecOrigin.x = (float)atof(szToken);
		pszFile = gEngfuncs.COM_ParseFile(pszFile, szToken);
		g_pOverview->m_vecOrigin.y = (float)atof(szToken);
	}
	else if (!_stricmp(pszToken, "rotated"))
	{
		gEngfuncs.COM_ParseFile(pszResult, szToken);
		g_pOverview->m_bIsRotate = atoi(szToken) != FALSE;
	}
	else if (!_stricmp(pszToken, "height"))
	{	
		pszFile = gEngfuncs.COM_ParseFile(pszResult, szToken);
		g_pOverview->m_iHeight= (float)atof(szToken);
	}

	return pszResult;
}
void Engfunc_COM_FreeFile(void *pBuffer)
{
	if (g_pOverview)
		g_pOverview->m_bCanCheck = false;

	gEngfuncs.COM_FreeFile(pBuffer);
}
client_sprite_t *EngFunc_SPR_GetList(char *psz, int *piCount)
{
	if (!strcmp(psz, "sprites/hud.txt"))
		return gEngfuncs.pfnSPR_GetList(psz, piCount);

	return LoadWeaponSprite(psz, piCount);
}
HSPRITE	Engfunc_SPR_Load(const char *pszSprite )
{
	HSPRITE hResult = gEngfuncs.pfnSPR_Load(pszSprite);

	if (!strcmp(pszSprite, "sprites/camera.spr"))
	{
		g_pOverview->m_pCamera = (model_t *)gEngfuncs.GetSpritePointer(hResult);
		g_pOverview->m_pInfection = (model_t *)gEngfuncs.GetSpritePointer(gEngfuncs.pfnSPR_Load("sprites/iinfection.spr"));
		g_pOverview->m_pRadio= (model_t *)gEngfuncs.GetSpritePointer(gEngfuncs.pfnSPR_Load("sprites/iradio.spr"));
		g_pOverview->m_pBackPack= (model_t *)gEngfuncs.GetSpritePointer(gEngfuncs.pfnSPR_Load("sprites/ibackpack.spr"));
	}
	else if (!strcmp(pszSprite, "sprites/iplayerred.spr"))
		g_pOverview->m_rgpPlayer[1] = (model_t *)gEngfuncs.GetSpritePointer(hResult);
	else if (!strcmp(pszSprite, "sprites/iplayerblue.spr"))
		g_pOverview->m_rgpPlayer[0] = (model_t *)gEngfuncs.GetSpritePointer(hResult);
	else if (!strcmp(pszSprite, "sprites/iplayerdead.spr"))
		g_pOverview->m_pDeath = (model_t *)gEngfuncs.GetSpritePointer(hResult);

	return hResult;
}
void Engfunc_BloodStream( float * org, float * dir, int pcolor, int speed )
{
	return /*gEfxAPI.R_BloodStream(org, dir, pcolor, speed)*/;
}
void Engfunc_BloodSprite( float * org, int colorindex, int modelIndex, int modelIndex2, float size )
{
	if(!pCvar_Blood->value && strcmp("schinses",g_szLanguage)) return gEfxAPI.R_BloodSprite(org,colorindex,modelIndex,modelIndex2,size);
	if(g_iMod == MOD_ZB ||g_iMod == MOD_ZBS || g_iMod == MOD_ZB3 || g_iMod == MOD_ZE)
	{		
		return gEfxAPI.R_BloodSprite(org,3,modelIndex,modelIndex2,size);
	}
	else
	{
		TEMPENTITY *pEnt;
		struct model_s *pModel;
		pModel = IEngineStudio.Mod_ForName("sprites/blood_spark.spr", 0);
		pEnt = gEngfuncs.pEfxAPI->CL_TentEntAllocCustom(org, pModel, 0, NULL);
		pEnt->entity.curstate.rendermode = kRenderTransAdd;
		pEnt->entity.curstate.renderamt = 100;
		pEnt->entity.curstate.scale = 0.5;
		pEnt->die += 0.25;
	}
	return;
}
void Engfunc_PlaySound( int ent, float *origin, int channel, const char *sample, float volume, float attenuation, int fFlags, int pitch )
{
	/*if(ent<33&&ent>0)
	{
		if(strstr(sample,"weapons")) return;
	}	
	else */return gEventAPI.EV_PlaySound(ent,origin,channel,sample,volume,attenuation,fFlags,pitch);
}