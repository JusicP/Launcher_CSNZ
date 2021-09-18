#include "base.h"
#include "r_efx.h"
#include "msghook.h"


pfnUserMsgHook pmTeamScore;
pfnUserMsgHook pmResetHUD;
pfnUserMsgHook pmHealth;
pfnUserMsgHook pmBattery;
pfnUserMsgHook pmArmorType;
pfnUserMsgHook pmScoreAttrib;
pfnUserMsgHook pmHideWeapon;
pfnUserMsgHook pmLocation;
pfnUserMsgHook pmWeaponList;
pfnUserMsgHook pmCurWeapon;
pfnUserMsgHook pmAmmoX;
pfnUserMsgHook pmDeathMsg;
pfnUserMsgHook pmTeamInfo;
pfnUserMsgHook pmScoreInfo;
pfnUserMsgHook pmSetFOV;
pfnUserMsgHook pmSendAudio;
pfnUserMsgHook pmShowMenu;
pfnUserMsgHook pmStatusValue;
pfnUserMsgHook pmMoney;
pfnUserMsgHook pmScreenFade;
pfnUserMsgHook pmNVGToggle;

char g_szFontBuf[512];
int g_iMoney=0,g_iBuyTime=0;
int g_Menu_Drawing=0;
int g_Menu_WaitingForMore=0;
int g_BinkScopeColor=1;

void MessageInitialize(void)
{
	g_Menu_Drawing = 0;
	g_iHideWeapon = 0;
	g_flHealthFade = 0;
	g_flArmorFade = 0;
	g_iArmorFlags = DHN_3DIGITS | DHN_DRAWZERO;
	memset(g_iAmmoCount, 0, sizeof(g_iAmmoCount));
	memset(g_szLocation, 0, sizeof(g_szLocation));
	memset(g_szFontBuf,0,sizeof(g_szFontBuf));
	g_iRespawnTime = 0;
}
int MsgFunc_StatusValue(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	int iCol = READ_BYTE();
	int iIsFriend = READ_SHORT();
	if(iCol == 1)
	{
		if(iIsFriend  < 2)
		{
			g_BinkScopeColor = 1;
		}
		else
		{
			if(fCurrentFOV<=40.0 && g_iBTEWeapon == WPN_SFSNIPER) gEngfuncs.pfnPlaySoundByName("weapons/sfsniper_insight1.wav", 1.0);
			g_BinkScopeColor = 0;
		}
	}

	return pmStatusValue(pszName, iSize, pbuf);
}
int MsgFunc_TeamScore(const char *pszName, int iSize, void *pbuf)
{	
	BEGIN_READ(pbuf, iSize);
	char teamtext[12];
	strcpy(teamtext, READ_STRING());
	
	if(g_iMod != MOD_GD)
		{
		if(strstr(teamtext,"CT"))
		{
			g_SBTopRight = READ_SHORT();
		}
		else if(strstr(teamtext,"TERRORIST"))
		{
			g_SBTopLeft = READ_SHORT();
		}
		
		g_SBTopCenter = g_SBTopLeft + g_SBTopRight +1;
	}
	return pmTeamScore(pszName, iSize, pbuf);
}
int MsgFunc_ResetHUD(const char *pszName, int iSize, void *pbuf)
{	
	MessageInitialize();
	return pmResetHUD(pszName, iSize, pbuf);
}
int MsgFunc_ShowMenu(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	g_Menu_Drawing = READ_SHORT();
	if(!pCvar_DrawMenu->value) return pmShowMenu(pszName, iSize, pbuf);

	if(g_Menu_Drawing) g_Menu_Drawing_time = g_flTime;
	READ_CHAR();
	int NeedMore = READ_BYTE();
	
	if (!g_Menu_WaitingForMore)
	{
		memset(g_Menu_text,0,1024);
		strncpy(g_Menu_text, READ_STRING(), 1024);		
	}
	else
	{
		strncat(g_Menu_text, READ_STRING(), 1024 - strlen(g_Menu_text));		
	}
	g_Menu_text[1023] = 0;

	if(g_Menu_text[0] == '#')
	{
		char buffer[1024];
		memset(buffer,0,1024);
		strncpy(buffer, BufferedLocaliseTextString(g_Menu_text), 1024);
		memset(g_Menu_text,0,1024);
		strncpy(g_Menu_text, buffer,1024);
		g_Menu_text[strlen(g_Menu_text)] = '\n';
	}
	//g_Menu_text[strlen(g_Menu_text)] = '\n';
	g_Menu_WaitingForMore = NeedMore;
	
	if (!NeedMore)
	{
		g_Menu_text[strlen(g_Menu_text)] = '\n';
		GetHeightWidth();
	}
	g_Menu_text[strlen(g_Menu_text)] = 0;
	return 1;//pmShowMenu(pszName, iSize, pbuf);
}

int MsgFunc_SendAudio(const char *pszName, int iSize, void *pbuf)
{	
	BEGIN_READ(pbuf, iSize);
	int iSender = READ_BYTE();
	READ_STRING();
	READ_SHORT();
	if(iSender != gEngfuncs.GetLocalPlayer()->index)
	{
		vPlayer[iSender].fAudioTime = g_flTime + 2.0;
	}
	return pmSendAudio(pszName, iSize, pbuf);
}
int MsgFunc_Location(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	int iPlayerID = READ_BYTE();
	if (iPlayerID == gEngfuncs.GetLocalPlayer()->index)
		strcpy(g_szLocation, READ_STRING());

	return pmLocation(pszName, iSize, pbuf);
}
int MsgFunc_SetFOV(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize); 
	fCurrentFOV = (float) READ_BYTE();
	if(fCurrentFOV<=40.0/* && g_bAlive*/)
	{
		g_iViewEntityRenderMode = 0;
		g_iViewEntityRenderFX = 17;
		g_iViewEntityRenderAmout = 100;
		if(g_iBTEWeapon == WPN_SFSNIPER)
		{
			BinkSetPos(g_sScreenInfo.iWidth*0.5,g_sScreenInfo.iHeight*0.5,1);
			PlayBinkInstant("metahook\\bik\\sfscope.bik",0,1);
			gEngfuncs.pfnPlaySoundByName("weapons/sfsniper_zoom.wav", 1.0);
		}
		else
		{
			PlayBinkInstant("metahook\\bik\\sfscope.bik",1,1);
		}
		if(pCvar_DrawScope->value != 0 && g_iBTEWeapon != WPN_SFSNIPER)
		{
			g_iSpoce = 1;
			/*if(g_iBTEWeapon == WPN_M200)
				strcpy(rgTempTga.szName, "other\\scope_m200");
			else
				strcpy(rgTempTga.szName, "other\\scope");
			rgTempTga.iFunction = 1;
			rgTempTga.iCenter = 1;
			rgTempTga.r = 255;
			rgTempTga.g = 255;
			rgTempTga.b = 255;
			//rgTempTga.w = 700;
			//rgTempTga.h = 700;
			rgTempTga.x = 0.5 * g_sScreenInfo.iWidth;
			rgTempTga.y = 0.5 * g_sScreenInfo.iHeight;
			rgTempTga.iMode = 0;
			rgTempTga.iChanne = 55;
			rgTempTga.flStartDisplayTime = g_flTime;
			rgTempTga.flEndDisplayTime = 9999 / 10 + g_flTime;

			if(g_iBTEWeapon == WPN_M200)
				rgTempTga.fScale = g_sScreenInfo.iHeight / 0.92 / g_MHTga[g_tga_custom_scope_m200].height;
			else
				rgTempTga.fScale = g_sScreenInfo.iHeight / 0.92 / g_MHTga[g_tga_custom_scope].height;
			
			DrawTgaAdd(rgTempTga);*/

		}
	}
	else
	{
		g_iViewEntityRenderMode = 0;
		g_iViewEntityRenderFX = 0;
		g_iViewEntityRenderAmout = 0;
		PlayBinkInstant("metahook\\bik\\sfscope.bik",1,1);

		g_iSpoce = 0;
		/*strcpy(rgTempTga.szName, "");
		rgTempTga.iFunction = 1;
		rgTempTga.iCenter = 0;
		rgTempTga.r = 255;
		rgTempTga.g = 255;
		rgTempTga.b = 255;
		rgTempTga.x = g_sScreenInfo.iWidth;
		rgTempTga.y = g_sScreenInfo.iHeight;
		rgTempTga.iMode = 0;
		rgTempTga.iChanne = 55;
		rgTempTga.flStartDisplayTime = 0.0;
		rgTempTga.flEndDisplayTime = 0.0;
		DrawTgaAdd(rgTempTga);*/
	}
	return pmSetFOV(pszName, iSize, pbuf);
}
int MsgFunc_Health(const char *pszName, int iSize, void *pbuf)
{	
	BEGIN_READ(pbuf, iSize);
	int iHealth = READ_SHORT();

	if (iHealth <= 0)
	{
		BEGIN_READ(pbuf, iSize);
		iHealth = READ_BYTE();
		if(g_iBTEWeapon == WPN_SFSNIPER)
			PlayBinkInstant("metahook\\bik\\sfscope.bik",1,1);

		if(g_iMod != MOD_TDM)	BTEPanel_BuyMenu_Close();

		g_iHookVAngle = 0;
		g_iShowCustomCrosshair = 0;

	}

	if (iHealth != g_iHealth)
	{
		g_iHealth = iHealth;
		g_flHealthFade = FADE_TIME;

		if (iHealth >= 10000)
			g_iHealthFlags = DHN_5DIGITS | DHN_DRAWZERO;
		else if (iHealth >= 1000)
			g_iHealthFlags = DHN_4DIGITS | DHN_DRAWZERO;
		else
			g_iHealthFlags = DHN_3DIGITS | DHN_DRAWZERO;
	}

	return pmHealth(pszName, iSize, pbuf);
}
int MsgFunc_Battery(const char *pszName, int iSize, void *pbuf)
{	
	BEGIN_READ(pbuf, iSize);
	int iArmor = READ_SHORT();

	if (iArmor != g_iArmor)
	{
		g_iArmor = iArmor;
		g_flArmorFade = FADE_TIME;

		if (iArmor >= 10000)
			g_iArmorFlags = DHN_5DIGITS | DHN_DRAWZERO;
		else if (iArmor >= 1000)
			g_iArmorFlags = DHN_4DIGITS | DHN_DRAWZERO;
		else
			g_iArmorFlags = DHN_3DIGITS | DHN_DRAWZERO;

		if (iArmor <= 0)
			g_iArmorType = 0;
	}

	return pmBattery(pszName, iSize, pbuf);
}
int MsgFunc_ArmorType(const char *pszName, int iSize, void *pbuf)
{	
	BEGIN_READ(pbuf, iSize);
	g_iArmorType = READ_BYTE();
	return pmArmorType(pszName, iSize, pbuf);
}
int MsgFunc_ScoreAttrib(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	int iPlayerID = READ_BYTE();
	int iFlags = READ_BYTE();
	g_PlayerExtraInfo[iPlayerID].iFlag = iFlags;
	if (iFlags & SCOREATTRIB_DEAD) vPlayer[iPlayerID].alive = 0;
	else vPlayer[iPlayerID].alive = 1;
	if (iPlayerID == gEngfuncs.GetLocalPlayer()->index)
	{
		if (iFlags & SCOREATTRIB_DEAD)
			g_bAlive = false;
		else
			g_bAlive = true;
	}
	if(g_PlayerExtraInfo[iPlayerID].iFlag & SCOREATTRIB_HERO)
	{
		vPlayer[iPlayerID].iHero = 1;
	}
	else vPlayer[iPlayerID].iHero = 0;
	return pmScoreAttrib(pszName, iSize, pbuf);
}

int MsgFunc_HideWeapon(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	g_iHideWeapon = READ_BYTE();
	return pmHideWeapon(pszName, iSize, pbuf);
}
int MsgFunc_WeaponList(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	char szName[MAX_WEAPON_NAME];
	strcpy(szName, READ_STRING());
	int iAmmoType = READ_CHAR();
	READ_BYTE();
	READ_CHAR();
	READ_BYTE();
	READ_CHAR();
	READ_CHAR();
	int iWeaponID = READ_CHAR();

	g_iWeaponData[iWeaponID].iAmmoType = iAmmoType;
	strcpy(g_iWeaponData[iWeaponID].szName, szName);
	return pmWeaponList(pszName, iSize, pbuf);
}
int MsgFunc_CurWeapon(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	int iState = READ_BYTE();
	int iId = READ_CHAR();
	int iClip = READ_SHORT();
	if (iClip <= 0)
	{
		BEGIN_READ(pbuf, iSize);
		iState = READ_BYTE();
		iId = READ_CHAR();
		iClip = READ_CHAR();
	}
	g_iWeaponData[iId].iClip = iClip;
	if (iState)
	{
		g_iWeapon = iId;
		g_flWeaponFade = 200.0f;
	}
	return pmCurWeapon(pszName, iSize, pbuf);
}
int MsgFunc_AmmoX(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	int iIndex = READ_BYTE();
	int iCount = READ_SHORT();

	if (iCount <= 0)
	{
		BEGIN_READ(pbuf, iSize);
		iIndex = READ_BYTE();
		iCount = READ_BYTE();
	}

	g_iAmmoCount[iIndex] = iCount;
	return pmAmmoX(pszName, iSize, pbuf);
}

/*int MsgFunc_ScreenFade(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	int duration = READ_SHORT();
	int holdtime = READ_SHORT();
	int fadetype = READ_SHORT();
	if(duration==(1<<12)*2 && holdtime==(1<<10)*10 && fadetype== 0x0004)
		g_zb_nvg = 1;
	else
		g_zb_nvg = 0;

	return pmScreenFade(pszName, iSize, pbuf);
}*/
int MsgFunc_ScoreInfo(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf,iSize);
	int iFrag[33];
	int idx = READ_BYTE();
	g_plrFrag[idx] = READ_SHORT();
	g_PlayerExtraInfo[idx].frags= g_plrFrag[idx];
	g_PlayerExtraInfo[idx].deaths = READ_SHORT();
	READ_SHORT();
	READ_SHORT();

	for(int jj=1;jj<33;jj++)
	{
		iFrag[jj] = g_plrFrag[jj];
	}
	int  i,j,temp,n=33;
	for(i=1;i<n-1;i++) 
	{
		for(j=i+1;j<n;j++)
		{
			if(iFrag[i]<iFrag[j])
			{
				temp=iFrag[i]; 
				iFrag[i]=iFrag[j]; 
				iFrag[j]=temp; 
			}
		}
	}
	int iRevLast=0;
	for(i=0;i<3;i++)
	{
		for(int k=1 ;k<33;k++)
		{
			if(g_plrFrag[k] == iFrag[i+1]&&iRevLast!=k)
			{
				g_plrRank[i] = k;
				iRevLast=k;
				break;
			}
		}
	}
	return pmScoreInfo(pszName, iSize, pbuf);
}
int MsgFunc_TeamInfo(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf,iSize);
	int px = READ_BYTE();
	char * teamtext = READ_STRING();
	if(!*teamtext) { vPlayer[px].team = 0; }
	else
	{
		if(strstr(teamtext,"CT"))
		{
			vPlayer[px].team = 1;
		}
		else if(strstr(teamtext,"TERRORIST"))
		{
			vPlayer[px].team = 2;
		}
		else
		{
			vPlayer[px].team = 0;
		}
	}
	if(px == gEngfuncs.GetLocalPlayer()->index) 
	{
		ZombieMod3UICheckTeam(vPlayer[px].team);
		ZombieMod4UICheckTeam(vPlayer[px].team);
	}
	return pmTeamInfo(pszName, iSize, pbuf);
}
int MsgFunc_Money(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf,iSize);
	g_iMoney = READ_LONG();
	BTEPanel_BuyMenu_SetMoney();
	return pmMoney(pszName, iSize, pbuf);
}
int MsgFunc_MetaHook(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);

	char szFunction[2048];
	strcpy(szFunction, READ_STRING());

	if (!strcmp(szFunction, "DrawImage"))
	{
		DrawImageItem rgTempDrawImage;
		rgTempDrawImage.iFunction = 0;
		rgTempDrawImage.iCheck = READ_BYTE();
		rgTempDrawImage.iCenter = READ_BYTE();

		char szSprites[2048];
		if(rgTempDrawImage.iCheck>0)
		{
			sprintf(szSprites, "%s",READ_STRING());
			rgTempDrawImage.iSprIndex = GetSpriteIndex(szSprites);
		}
		else
		{
			sprintf(szSprites, "sprites/%s.spr", READ_STRING());
			rgTempDrawImage.hl_hSprites = gEngfuncs.pfnSPR_Load(szSprites);
		}

		rgTempDrawImage.x = READ_COORD() / 100 * g_sScreenInfo.iWidth;
		rgTempDrawImage.y = READ_COORD() / 100 * g_sScreenInfo.iHeight;
		rgTempDrawImage.color.r = READ_BYTE();
		rgTempDrawImage.color.g = READ_BYTE();
		rgTempDrawImage.color.b = READ_BYTE();
		rgTempDrawImage.iMode = READ_BYTE();
		rgTempDrawImage.flStartDisplayTime = g_flTime;
		rgTempDrawImage.flEndDisplayTime = READ_COORD() / 10 + g_flTime;
		rgTempDrawImage.iChanne = READ_BYTE();
		rgTempDrawImage.iLength = READ_SHORT();
		DrawImageAdd(rgTempDrawImage);
	}
	else if (!strcmp(szFunction, "DrawAdditiveImage"))
	{
		DrawImageItem rgTempDrawImage;
		rgTempDrawImage.iFunction = 1;
		rgTempDrawImage.iCheck = READ_BYTE();
		rgTempDrawImage.iCenter = READ_BYTE();

		char szSprites[2048];
		if(rgTempDrawImage.iCheck>0)
		{
			sprintf(szSprites, "%s",READ_STRING());
			rgTempDrawImage.iSprIndex = GetSpriteIndex(szSprites);
		}
		else
		{
			sprintf(szSprites, "sprites/%s.spr", READ_STRING());
			rgTempDrawImage.hl_hSprites = gEngfuncs.pfnSPR_Load(szSprites);
		}
		rgTempDrawImage.x = READ_COORD() / 100 * g_sScreenInfo.iWidth;
		rgTempDrawImage.y = READ_COORD() / 100 * g_sScreenInfo.iHeight;
		rgTempDrawImage.color.r = READ_BYTE();
		rgTempDrawImage.color.g = READ_BYTE();
		rgTempDrawImage.color.b = READ_BYTE();
		rgTempDrawImage.iMode = READ_BYTE();
		rgTempDrawImage.flStartDisplayTime = g_flTime;
		rgTempDrawImage.flEndDisplayTime = READ_COORD() / 10 + g_flTime;
		rgTempDrawImage.iChanne = READ_BYTE();
		rgTempDrawImage.iLength = READ_SHORT();
		if(strstr("zbzbkill",szSprites)) return 1;
		if(strstr(szSprites,"boss")) return 1;

		DrawImageAdd(rgTempDrawImage);
	}
	else if (!strcmp(szFunction, "DrawHolesImage"))
	{
		DrawImageItem rgTempDrawImage;
		rgTempDrawImage.iFunction = 2;
		rgTempDrawImage.iCheck = READ_BYTE();
		rgTempDrawImage.iCenter = READ_BYTE();

		char szSprites[2048];
		if(rgTempDrawImage.iCheck>0)
		{
			sprintf(szSprites, "%s",READ_STRING());
			rgTempDrawImage.iSprIndex = GetSpriteIndex(szSprites);
		}
		else
		{
			sprintf(szSprites, "sprites/%s.spr", READ_STRING());
			rgTempDrawImage.hl_hSprites = gEngfuncs.pfnSPR_Load(szSprites);
		}

		rgTempDrawImage.x = READ_COORD() / 100 * g_sScreenInfo.iWidth;
		rgTempDrawImage.y = READ_COORD() / 100 * g_sScreenInfo.iHeight;
		rgTempDrawImage.color.r = READ_BYTE();
		rgTempDrawImage.color.g = READ_BYTE();
		rgTempDrawImage.color.b = READ_BYTE();
		rgTempDrawImage.iMode = READ_BYTE();
		rgTempDrawImage.flStartDisplayTime = g_flTime;
		rgTempDrawImage.flEndDisplayTime = READ_COORD() / 10 + g_flTime;
		rgTempDrawImage.iChanne = READ_BYTE();
		if(strstr(szSprites,"boss")) return 1;
		DrawImageAdd(rgTempDrawImage);
	}
	else if (!strcmp(szFunction, "DrawFontText"))
	{
		static int iContinueRead;
		static struct DrawFontTextItem rgTempDrawText;
		char szBuf[200];
		strcpy(szBuf, READ_STRING());
		rgTempDrawText.iCenter = READ_BYTE();
		rgTempDrawText.x = READ_COORD() / 100 * g_sScreenInfo.iWidth;
		rgTempDrawText.y = READ_COORD() / 100 * g_sScreenInfo.iHeight;
		rgTempDrawText.color.r = READ_BYTE();
		rgTempDrawText.color.g = READ_BYTE();
		rgTempDrawText.color.b = READ_BYTE();
		rgTempDrawText.iScale = READ_BYTE();
		rgTempDrawText.flDisplayTime = READ_COORD() / 10 + g_flTime;
		rgTempDrawText.flStartTime = g_flTime;
		rgTempDrawText.fFadeTime = READ_COORD() / 10 ;
		rgTempDrawText.iFillBg = READ_BYTE();
		rgTempDrawText.iChanne = READ_BYTE();
		rgTempDrawText.flDisplayTime += rgTempDrawText.fFadeTime*2;
		iContinueRead = READ_BYTE();
		if(iContinueRead)
		{
			sprintf(g_szFontBuf,"%s%s",g_szFontBuf,szBuf);
		}
		else
		{
			if(szBuf[0] == '#')
			{
				sprintf(szBuf,"%s",GetLangUtf(&szBuf[1]));
			}
			sprintf(g_szFontBuf,"%s%s",g_szFontBuf,szBuf);
			rgTempDrawText.szText[0] = '\0';
			sprintf(rgTempDrawText.szText,"%s",g_szFontBuf);
			DrawFontTextAdd(rgTempDrawText);
			g_szFontBuf[0] = '\0';
		}
	}
	else if(!strcmp(szFunction, "DrawTargaImage"))
	{
		DrawTgaItem rgTempTga;
		strcpy(rgTempTga.szName, READ_STRING());
		rgTempTga.iFunction = READ_BYTE();
		rgTempTga.iCenter = READ_BYTE();
		rgTempTga.r = READ_BYTE();
		rgTempTga.g = READ_BYTE();
		rgTempTga.b = READ_BYTE();
		rgTempTga.x = READ_COORD() / 100 * g_sScreenInfo.iWidth;
		rgTempTga.y = READ_COORD() / 100 * g_sScreenInfo.iHeight;
		rgTempTga.w = 0;
		rgTempTga.h = 0;
		rgTempTga.iMode = READ_BYTE();
		rgTempTga.iChanne = READ_SHORT();
		rgTempTga.flStartDisplayTime = g_flTime;
		rgTempTga.flEndDisplayTime = READ_COORD() / 10 + g_flTime;
		rgTempTga.fScale = 1.0;
		DrawTgaAdd(rgTempTga);
	}
	else if (!strcmp(szFunction, "ModRunning"))
	{
		g_iMod = READ_BYTE();
		BTEPanel_BuyMenu_Reset();
	}
	else if (!strcmp(szFunction, "WeaponLimit"))
	{
		g_iWeaponLimit = READ_BYTE();
	}
	else if (!strcmp(szFunction, "TeamSuit"))
	{
		int iPackage = READ_BYTE();
		char szToken[256];
		sprintf(szToken,"%s",READ_STRING());
		//LogToFile(szToken);
		char szWpn[3][16];
		int iIndex = 0;
		int iPos = 0;
		for(int i=0 ; i<strlen(szToken);i++)
		{
			if(szToken[i] == '#')
			{
				szWpn[iIndex][iPos] = '\0';
				iIndex ++;
				iPos = 0;
				continue;
			}
			szWpn[iIndex][iPos] = szToken[i];
			iPos ++;
		}
		//BTEPanel_TeamSuit_UpdateItems(iPackage,szWpn[0],szWpn[1],szWpn[2]);
		BTEPanel_TeamSuit_Show();
		g_mgui_candraw = 1;
	}
	else if (!strcmp(szFunction, "BuyMenu"))
	{
		cl_entity_t *pPlayer = gEngfuncs.GetLocalPlayer();
		int iLocalIndex = pPlayer->index;

		if((g_iMod == MOD_ZB || g_iMod == MOD_ZB3) && vPlayer[iLocalIndex].team != 1) return 1;
		
		if((g_iHealth > 0 || g_iMod == MOD_TDM || g_iMod == MOD_DM))
		{
			char szToken[256];
			int iType = READ_BYTE();
			int iPage = READ_BYTE();
			int iHaveNextPage = READ_BYTE();
			sprintf(szToken,"%s",READ_STRING());
			if(szToken[0] == '\0')
			{			
				BTEPanel_BuyMenu_UpdateItems(-1,"");
				BTEPanel_BuyMenu_SetPage(0,0);
				//BTEPanel_BuyMenu_SetHaveNextPage(0,0);
			}
			else
			{
				char szWpn[9][32];
				int iIndex = 0;
				int iPos = 0;

				BTEPanel_BuyMenu_SetPage(iPage,iType);
				BTEPanel_BuyMenu_SetHaveNextPage(iPage>0,iHaveNextPage);

				for(int i=0 ; i<strlen(szToken);i++)
				{
					if(szToken[i] == '#')
					{
						szWpn[iIndex][iPos] = '\0';
						iIndex ++;
						iPos = 0;
						continue;
					}
					szWpn[iIndex][iPos] = szToken[i];
					iPos ++;
				}
				//szWpn[iIndex][iPos] = '\0';
				for(int i=0;i<=9;i++)
					BTEPanel_BuyMenu_UpdateItems(i,szWpn[i]);
			}
			g_mgui_candraw = 1;
		}
		
	}
	else if (!strcmp(szFunction, "ZombieMenu"))
	{
		char szToken[512];
		sprintf(szToken,"%s",READ_STRING());
		
		char szWpn[9][32];
		memset(szWpn,0,sizeof(szWpn));
		memset(g_zb3_menu_zb,0,sizeof(g_zb3_menu_zb));
		int iIndex = 0;
		int iPos = 0;

		for(int i=0 ; i<strlen(szToken);i++)
		{
			if(szToken[i] == '#')
			{
				szWpn[iIndex][iPos] = '\0';
				iIndex ++;
				iPos = 0;
				continue;
			}
			szWpn[iIndex][iPos] = szToken[i];
			iPos ++;
		}
		
		for(int i=0;i<=8;i++)
		{
			if(szWpn[i][0]!=0)
			{
				char szText[128];
				sprintf(szText,"resource\\hud\\zombie\\zombietype_%s",szWpn[i]);
				g_zb3_menu_zb[i] = FindTexture(szText);
			}
		}
		g_zb3_menu_zb[9] = FindTexture("resource\\hud\\zombie\\zombietype_cancel");

		g_isShowingZbMenu = 1;
		g_zb3_menu_time = g_flTime + 5.0;
	}
	else if (!strcmp(szFunction, "SpecialEvent"))
	{
		int iEvent = READ_BYTE();
		/*if(iEvent == EVENT_BALROG)
		{
			TEMPENTITY *pEnt;
			struct model_s *pModel;
			cl_entity_s* pEntity = gEngfuncs.GetViewModel();
			pModel = IEngineStudio.Mod_ForName( "sprites/custommuzzleflash/muz_balrog.spr", 0);
			pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh((float *)&pEntity->attachment[1], pModel);
			pEnt->entity.curstate.rendermode = kRenderTransAdd;
			pEnt->entity.curstate.renderamt = 200;
			pEnt->entity.curstate.scale = 0.2;
			pEnt->entity.curstate.frame = (float)gEngfuncs.pfnRandomLong(0,1);
			pEnt->die += g_flTime + 0.01f;
			pEnt->entity.curstate.iuser4 = 1;
			Engfunc_Call_AddVisibleEntity( &(pEnt->entity));
			
		}
		else */if(iEvent == EVENT_DR_START)
		{
			DeathRunStart();
		}
		else if(iEvent == EVENT_DR_END)
		{
			DeathRunStop();
		}
		else if(iEvent == EVENT_DR_RESET)
		{
			DeathRunReset();
		}
		else if(iEvent == EVENT_SFMG || iEvent == EVENT_SFMG2)
		{
			g_iWeaponStat = iEvent;
		}
		else if(iEvent == EVENT_BL3 || iEvent == EVENT_BL32)
		{
			g_iBl3Muzz = iEvent;
		}
		else if(iEvent == EVENT_M16 || iEvent == EVENT_M162)
		{
			g_iBl3Muzz = iEvent;
		}
		else
			g_iWeaponStat = iEvent;
	}
	else if (!strcmp(szFunction, "DRRank"))
	{
		DeathRun_ParseMsg();
	}
	else if (!strcmp(szFunction, "DrawExtraAmmo"))
	{
		g_ExtraAmmo = READ_BYTE();
	}
	else if (!strcmp(szFunction, "DrawScoreBoard"))
	{
		g_SBTopLeft = READ_SHORT();
		g_SBTopCenter = READ_SHORT();
		g_SBTopRight = READ_SHORT();
		g_SBDownLeft = READ_SHORT();
		g_SBDownRight = READ_BYTE();
		g_SBMode = READ_BYTE();
	}
	else if (!strcmp(szFunction, "SetViewEntityBody"))
	{
		g_iViewEntityBody = READ_BYTE();
	}
	else if (!strcmp(szFunction, "SetViewEntityRender"))
	{
		g_iViewEntityRenderMode = READ_BYTE();
		g_iViewEntityRenderFX = READ_BYTE();
		g_iViewEntityRenderAmout = READ_BYTE();
		g_byViewEntityRenderColor.r = READ_BYTE();
		g_byViewEntityRenderColor.g = READ_BYTE();
		g_byViewEntityRenderColor.b = READ_BYTE();
	}
	else if (!strcmp(szFunction, "ChangeTattoo"))
	{
		char name[32];
		int iType;
		sprintf(name,"%s",READ_STRING());
		if(name[0] != 0)
		{
			iType = READ_BYTE();
			if(iType == 1)
			{
				sprintf(g_sTattoo,"%s",name);
			}
			else 
			{
				sprintf(g_sTattooSmall,"%s",name);
				g_iTattooSmallEnable = 1;
			}
			LoadTattoo();
		}
	}
	else if (!strcmp(szFunction, "PlayBink"))
	{
		char szBink[64];
		sprintf(szBink, "metahook\\bik\\%s",READ_STRING());
		Bink_iX = READ_COORD() / 100 * g_sScreenInfo.iWidth;
		Bink_iY = READ_COORD() / 100 * g_sScreenInfo.iHeight;
		READ_BYTE();
		READ_BYTE();
		READ_BYTE();
		READ_BYTE();
		READ_BYTE();
		Bink_iCenter = READ_BYTE();
		BinkSetColor(255,255,255);

		PlayBinkInstant(szBink,0,0);
	}
	else if(!strcmp(szFunction,"RespawnBar"))
	{
		g_iRespawnBar =  READ_BYTE();
		g_iRespawnTime = READ_COORD() / 10 + g_flTime;
		g_iRTStart = g_flTime;
		g_iRSBarIndex = GetSpriteIndex("respawnbar");

	}
	else if (!strcmp(szFunction, "Quest"))
	{
		char sNpcName[32];
		char sNpcPic[32];
		char sMission[32];
		sprintf(sNpcName,"CSBTE_QUEST_NPC_NAME%d",READ_BYTE());
		sprintf(sNpcPic, "resource\\hud\\quest\\quest_npc%d",READ_BYTE());
		sprintf(sMission, "CSBTE_QUEST_MISSION%d",READ_BYTE());
		QuestAdd(sNpcName,sNpcPic,sMission);
	}
	else if(!strcmp(szFunction,"DrawCountDown"))
	{
		sprintf(g_sCountDownText,"%s",READ_STRING());
		g_fCountDown = float(READ_BYTE())+ g_flTime;
	}
	else if(!strcmp(szFunction,"DrawCountDownReset"))
	{
		g_fCountDown = 0;
		ResetZe();
	}
	else if(!strcmp(szFunction,"WeaponSkin"))
	{
		int ID = READ_BYTE();
		sprintf(g_szWeaponSkin[ID],"%s",READ_STRING());
		int iSer = READ_BYTE();
		//int iSer2 = 1-iSer;
		//int iSer3 = 0-iSer;
		//g_iWeaponSkin[ID][iSer] = 1; // Æ¤·ô3
		//g_iWeaponSkin[ID][iSer2] = 0; // Æ¤·ô2
		//g_iWeaponSkin[ID][iSer3] = 2; // Æ¤·ô1
		g_iWeaponSkin[ID][1] = iSer;
	}
	else if (!strcmp(szFunction, "DrawFollowIcon"))
	{
		DrawIconItem rgTemp;
		char szSprites[2048];
		sprintf(szSprites, "%s",READ_STRING());
		if(strstr(szSprites,"djb_spboxicon"))
		{
			rgTemp.iBox = 1;
		}
		else if(strstr(szSprites,"bte_bombtargetA"))
		{
			rgTemp.iBox = 2;
		}
			else if(strstr(szSprites,"bte_bombtargetB"))
		{
			rgTemp.iBox = 3;
		}
		else
		{
			rgTemp.iBox = 0;
			rgTemp.iSprIndex = GetSpriteIndex(szSprites);
		}
		rgTemp.x = READ_SHORT();
		rgTemp.y = READ_SHORT();
		rgTemp.z = READ_SHORT();
		rgTemp.iToggle = READ_BYTE();
		rgTemp.iDistance = READ_BYTE();
		rgTemp.iChannel = READ_BYTE();
		rgTemp.r = READ_BYTE();
		rgTemp.g = READ_BYTE();
		rgTemp.b = READ_BYTE();
		DrawIconAdd(rgTemp);
	}
	else if (!strcmp(szFunction, "DrawFollowIconReset"))
	{
		DrawIconInitialize();
	}
	else if (!strcmp(szFunction, "ZB3Data"))
	{
		int iDataType = READ_BYTE();
		int iData = READ_BYTE();
		if(iDataType !=5)
		{
			Zombie3UIParseData(iDataType, iData);
		}
		if(iDataType !=5)
		{
			Zombie4UIParseData(iDataType, iData); 
		}
		else
		{
			g_ExtraAmmo_Svdex_Num = iData;
		}
	}
	else if (!strcmp(szFunction, "ZB3UI"))
	{
		char skull[128];
		sprintf(skull,"%s",READ_STRING());
		int iSlot = READ_BYTE();
		int iType = READ_BYTE();
		int iData = READ_BYTE();
		ZombieMod3UIParseIcon(skull,iSlot,iType,iData);
	}
	else if (!strcmp(szFunction, "ZBSTeamScore"))
	{
		int score = READ_LONG();

		g_ZBSboard.SetTeamScore(score);
	}
	else if (!strcmp(szFunction, "ZBSPlayerScore"))
	{
		int score = READ_LONG();
		int flash = READ_BYTE();

		g_ZBSboard.SetPlayerScore(score, flash);
	}
	else if (!strcmp(szFunction, "ZBSRoundNums"))
	{
		int nums = READ_LONG();

		g_ZBSboard.SetRoundNums(nums);
	}
	else if (!strcmp(szFunction, "DrawRetina"))
	{
		char szText[128];
		sprintf(szText,"%s",READ_STRING());
		//gEngfuncs.Con_Printf(szText);
		int id = DrawTgaGetID(szText);
		int draw = READ_BYTE();
		int full = READ_BYTE();
		int flash = READ_BYTE();
		int channe = READ_SHORT();
		float time = READ_COORD() / 10 + g_flTime;
		DrawRetinaParseData(id, draw, full, flash, channe, time);
	}
	else if (!strcmp(szFunction, "SendData"))
	{
		int type = READ_BYTE();
		int data = READ_LONG();
		char data2[128];
		sprintf(data2,"%s",READ_STRING());
		switch (type)
		{
			case 1: 
			{
				g_iBuyTime = data + (int)g_flTime;
				break;
			}
			case 2:
			{
				BTEPanel_BuyMenu_UpdateItems(-1,"");
				BTEPanel_BuyMenu_SetPage(0,0);
				BTEPanel_BuyMenu_SetQuickBuy(data,data2);
				break;
			}
		}
		if(type > 10)
		{
			int id = type - 10;
			int iSlot = data;

			sprintf(g_szWeapon[id][iSlot], "%s", data2);
			g_iCustomWeapon[id][iSlot] = FindWeaponData(data2);
		}


	}

	return 1;
}
int MsgFunc_NVGToggle(const char *pszName, int iSize, void *pbuf)
{
	BEGIN_READ(pbuf, iSize);
	
	if(READ_BYTE())
		g_CHudAmmo.SetNvgOn(true);
	else
		g_CHudAmmo.SetNvgOn(false);

	return pmNVGToggle(pszName, iSize, pbuf);
}

int EngFunc_HookUserMsg(char *szMsgName, pfnUserMsgHook pfn)
{	
	/*if (!strcmp(szMsgName, "ScreenFade"))
	{
		pmScreenFade = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_ScreenFade);
	}*/
	if (!strcmp(szMsgName, "NVGToggle"))
	{
		pmNVGToggle = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_NVGToggle);
	}
	if (!strcmp(szMsgName, "TeamScore"))
	{
		pmTeamScore = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_TeamScore);
	}
	if (!strcmp(szMsgName, "ResetHUD"))
	{
		pmResetHUD = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_ResetHUD);
	}

	if (!strcmp(szMsgName, "Health"))
	{
		pmHealth = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_Health);
	}

	if (!strcmp(szMsgName, "Battery"))
	{
		pmBattery = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_Battery);
	}

	if (!strcmp(szMsgName, "ArmorType"))
	{
		pmArmorType = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_ArmorType);
	}

	if (!strcmp(szMsgName, "ScoreAttrib"))
	{
		pmScoreAttrib = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_ScoreAttrib);
	}

	if (!strcmp(szMsgName, "HideWeapon"))
	{
		pmHideWeapon = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_HideWeapon);
	}

	if (!strcmp(szMsgName, "WeaponList"))
	{
		pmWeaponList = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_WeaponList);
	}

	if (!strcmp(szMsgName, "CurWeapon"))
	{
		pmCurWeapon = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_CurWeapon);
	}

	if (!strcmp(szMsgName, "AmmoX"))
	{
		pmAmmoX = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_AmmoX);
	}
	if (!strcmp(szMsgName, "Location"))
	{
		pmLocation = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_Location);
	}

	if (!strcmp(szMsgName, "HudTextArgs"))
		gEngfuncs.pfnHookUserMsg("MetaHook", MsgFunc_MetaHook);
		
	if (!strcmp(szMsgName, "DeathMsg"))
	{
		pmDeathMsg = pfn;
		gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_DeathMsg);
		return 0;
	}
	if (!strcmp(szMsgName, "SendAudio"))
	{
		pmSendAudio = pfn;
		gEngfuncs.pfnHookUserMsg(szMsgName,MsgFunc_SendAudio);
		return 0;
	}
	if (!strcmp(szMsgName, "TeamInfo"))
	{
		pmTeamInfo = pfn;
		gEngfuncs.pfnHookUserMsg(szMsgName,MsgFunc_TeamInfo);
		return 0;
	}
	if (!strcmp(szMsgName, "ScoreAttrib"))
	{
		pmScoreAttrib = pfn;
		gEngfuncs.pfnHookUserMsg(szMsgName,MsgFunc_ScoreAttrib);
		return 0;
	}
	if (!strcmp(szMsgName, "ScoreInfo"))
	{
		pmScoreInfo = pfn;
		gEngfuncs.pfnHookUserMsg(szMsgName,MsgFunc_ScoreInfo);
		return 0;
	}
	if (!strcmp(szMsgName, "SetFOV"))
	{
		pmSetFOV = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_SetFOV);
	}
	if (!strcmp(szMsgName, "ShowMenu"))
	{
		pmShowMenu = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_ShowMenu);
	}
	if (!strcmp(szMsgName, "StatusValue"))
	{
		pmStatusValue = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_StatusValue);
	}
	if (!strcmp(szMsgName, "Money"))
	{
		pmMoney = pfn;
		return gEngfuncs.pfnHookUserMsg(szMsgName, MsgFunc_Money);
	}
	return gEngfuncs.pfnHookUserMsg(szMsgName, pfn);
}


