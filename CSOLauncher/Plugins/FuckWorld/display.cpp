#include "base.h"
#include "event.h"

CHudAmmo g_CHudAmmo;

int g_iRes;
int g_iFontWidth, g_iFontHeight;
int g_HideMoney;

int g_iNumberZero;
int g_iHealthIcon, g_iArmorIcon[2], g_iArmorFullIcon[2];

client_sprite_t *g_pSpriteList;
int g_iSpriteCount, g_iSpriteCountAllRes;

HSPRITE *g_rghSprites;
wrect_t *g_rgrcRects;
char *g_rgszSpriteNames;
float g_flTime, g_fOldTime, g_flTimeDelta;
int g_iHealth, g_iHealthFlags;
float g_flHealthFade;
int g_iArmor, g_iArmorFlags, g_iArmorType;
float g_flArmorFade;
float g_flWeaponFade;
int g_MoneyPosIco = 0;
int g_MoneyPosSym = 0;

int g_janusmk5_ammo2;
int g_infinite;

float g_fCountDown = 0;
char g_sCountDownText[256];


int DrawHudNumber(int x, int y, int iFlags, int iNumber, int r, int g, int b)
{
	int k;
	int iWidth = g_iFontWidth;
	
	if (iNumber > 0)
	{
		if (iNumber >= 10000)
		{
			k = iNumber / 10000;
			gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iNumberZero + k));
			x += iWidth;
		}
		else if (iFlags & (DHN_5DIGITS))
			x += iWidth;

		if (iNumber >= 1000)
		{
			k = (iNumber % 10000) / 1000;
			gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iNumberZero + k));
			x += iWidth;
		}
		else if (iFlags & (DHN_5DIGITS | DHN_4DIGITS))
			x += iWidth;

		if (iNumber >= 100)
		{
			k = (iNumber % 1000) / 100;
			gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iNumberZero + k));
			x += iWidth;
		}
		else if (iFlags & (DHN_5DIGITS | DHN_4DIGITS | DHN_3DIGITS))
			x += iWidth;

		if (iNumber >= 10)
		{
			k = (iNumber % 100) / 10;
			gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iNumberZero + k));
			x += iWidth;
		}
		else if (iFlags & (DHN_5DIGITS | DHN_4DIGITS | DHN_3DIGITS | DHN_2DIGITS))
			x += iWidth;

		k = iNumber % 10;
		gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0,  x, y, &GetSpriteRect(g_iNumberZero + k));
		x += iWidth;
	} 
	else if (iFlags & DHN_DRAWZERO) 
	{
		gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero), r, g, b );

		if (iFlags & (DHN_5DIGITS))
			x += iWidth;

		if (iFlags & (DHN_5DIGITS | DHN_4DIGITS))
			x += iWidth;

		if (iFlags & (DHN_5DIGITS | DHN_4DIGITS | DHN_3DIGITS))
			x += iWidth;

		if (iFlags & (DHN_5DIGITS | DHN_4DIGITS | DHN_3DIGITS | DHN_2DIGITS))
			x += iWidth;
		
		gEngfuncs.pfnSPR_DrawAdditive(0,  x, y, &GetSpriteRect(g_iNumberZero));
		x += iWidth;
	}
	return x;
}

void DisplayInitialize(void)
{	
	g_sScreenInfo.iSize = sizeof(g_sScreenInfo);
	gEngfuncs.pfnGetScreenInfo(&g_sScreenInfo);
	

	if (g_sScreenInfo.iWidth < 640)
		g_iRes = 320;
	else
		g_iRes = 640;

	if (!g_pSpriteList)
	{
		g_pSpriteList = gEngfuncs.pfnSPR_GetList("sprites/hud.txt", &g_iSpriteCountAllRes);

		if (g_pSpriteList)
		{
			g_iSpriteCount = 0;
			client_sprite_t *p = g_pSpriteList;
			for (int j = 0; j < g_iSpriteCountAllRes; j++)
			{
				if (p->iRes == g_iRes)
					g_iSpriteCount++;
				p++;
			}

 			g_rghSprites = new HSPRITE[g_iSpriteCount];
			g_rgrcRects = new wrect_t[g_iSpriteCount];
			g_rgszSpriteNames = new char[g_iSpriteCount * MAX_SPRITE_NAME_LENGTH];

			p = g_pSpriteList;
			int index = 0;
			for (int j = 0; j < g_iSpriteCountAllRes; j++)
			{
				if (p->iRes == g_iRes)
				{
					char sz[256];
					sprintf(sz, "sprites/%s.spr", p->szSprite);
					g_rghSprites[index] = gEngfuncs.pfnSPR_Load(sz);
					g_rgrcRects[index] = p->rc;
					strncpy(&g_rgszSpriteNames[index * MAX_SPRITE_NAME_LENGTH], p->szName, MAX_SPRITE_NAME_LENGTH);
					index++;
				}
				p++; 
			}
		}
	}
	else
	{
		int index = 0;
		client_sprite_t *p = g_pSpriteList;
		for (int j = 0; j < g_iSpriteCountAllRes; j++)
		{
			if (p->iRes == g_iRes)
			{
				char sz[256];
				sprintf(sz, "sprites/%s.spr", p->szSprite);
				g_rghSprites[index] = gEngfuncs.pfnSPR_Load(sz);
				index++;
			}
			p++;
		}
	}

	g_iNumberZero = GetSpriteIndex("number_0");
	g_iHealthIcon = GetSpriteIndex("cross");
	g_iArmorIcon[0] = GetSpriteIndex("suit_empty");
	g_iArmorFullIcon[0] = GetSpriteIndex("suit_full");
	g_iArmorIcon[1] = GetSpriteIndex("suithelmet_empty");
	g_iArmorFullIcon[1] = GetSpriteIndex("suithelmet_full"); 

	g_iFontWidth = g_rgrcRects[g_iNumberZero].right - g_rgrcRects[g_iNumberZero].left;
	g_iFontHeight = g_rgrcRects[g_iNumberZero].bottom - g_rgrcRects[g_iNumberZero].top;
	/*g_ExtraAmmoIndex_Svdex = GetSpriteIndex("extraammo_svdex");
	g_ExtraAmmoIndex_Musket = GetSpriteIndex("extraammo_musket");
	g_ExtraAmmoIndex_SfSniper = GetSpriteIndex("extraammo_sfsniper");
	g_ExtraAmmoIndex_Cannon = GetSpriteIndex("extraammo_cannon");
	g_ExtraAmmoIndex_M200 = GetSpriteIndex("extraammo_m200");
	g_ExtraAmmoIndex_tknife = GetSpriteIndex("extraammo_tknife");
	g_ExtraAmmoIndex_bow = GetSpriteIndex("extraammo_bow");
	g_janusmk5_ammo2 = GetSpriteIndex("janusmk5_ammo2");*/
	g_infinite = GetSpriteIndex("infinite");

}

void DisplayHealth(float flTime, int iIntermission)
{
	int r, g, b;
	int a = 0, x, y;

	if ((g_iHideWeapon & HIDEWEAPON_HEALTH) || gEngfuncs.IsSpectateOnly())
		return;
	
	if (g_flHealthFade)
	{
		g_flHealthFade -= (g_flTimeDelta * 20);

		if (g_flHealthFade <= 0)
		{
			a = MIN_ALPHA;
			g_flHealthFade = 0;
		}
		a = MIN_ALPHA + (g_flHealthFade / FADE_TIME) * 128;
	}
	else
		a = MIN_ALPHA;

	if (g_iHealth <= 15)
		a = 255;
		
	if (g_iHealth <= 25)
	{
		r = 250;
		g = 0;
		b = 0;
	}
	else
		UnpackRGB(r, g, b, RGB_YELLOWISH);

	ScaleColors(r, g, b, a);

	if (g_iWeaponBit & (1<<(WEAPON_VEST)))
	{
		int iCrossWidth = GetSpriteRect(g_iHealthIcon).right - GetSpriteRect(g_iHealthIcon).left;

		x = iCrossWidth / 2;
		y = g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2;

		gEngfuncs.pfnSPR_Set(GetSprite(g_iHealthIcon), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iHealthIcon));

		x = iCrossWidth + g_iFontWidth / 2;
		DrawHudNumber(x, y, g_iHealthFlags, g_iHealth, r, g, b);
	}
}

void DisplayArmor(float flTime, int iIntermission)
{
	if ((g_iHideWeapon & (HIDEWEAPON_HEALTH | HIDEWEAPON_ALL)) || gEngfuncs.IsSpectateOnly())
		return;

	if (!(g_iWeaponBit & (1<<(WEAPON_VEST))))
		return;

	if (g_iArmorType >= sizeof g_iArmorIcon)
		return;
	
	int x, y;
	int r, g, b, a;

	if (g_flArmorFade)
	{
		g_flArmorFade -= (g_flTimeDelta * 20);

		if (g_flArmorFade <= 0)
		{
			a = MIN_ALPHA;
			g_flArmorFade = 0;
		}
		a = MIN_ALPHA + (g_flArmorFade / FADE_TIME) * 128;
	}
	else
		a = MIN_ALPHA;
	UnpackRGB(r, g, b, RGB_YELLOWISH);
	ScaleColors(r, g, b, a);
	int iCrossWidth = GetSpriteRect(g_iHealthIcon).right - GetSpriteRect(g_iHealthIcon).left;
	x = g_sScreenInfo.iWidth / 5;
	y = g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2;
	gEngfuncs.pfnSPR_Set(GetSprite(g_iArmorIcon[g_iArmorType]), r, g, b);
	gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iArmorIcon[g_iArmorType]));
	wrect_t rcFullArmo = *&GetSpriteRect(g_iArmorFullIcon[g_iArmorType]);
	rcFullArmo.top += (rcFullArmo.bottom - rcFullArmo.top) * ((float)(100 - (min(100, g_iArmor))) * 0.01);
	if (rcFullArmo.bottom > rcFullArmo.top)
	{
		gEngfuncs.pfnSPR_Set(GetSprite(g_iArmorFullIcon[g_iArmorType]), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y + rcFullArmo.top - GetSpriteRect(g_iArmorFullIcon[g_iArmorType]).top, &rcFullArmo);
	}
	x += iCrossWidth;
	DrawHudNumber(x, y, g_iArmorFlags, g_iArmor, r, g, b);
}

void DisplayWeapon(float flTime, int iIntermission)
{	
	if ((g_iHideWeapon & (HIDEWEAPON_WEAPON | HIDEWEAPON_ALL)) || gEngfuncs.IsSpectateOnly())
		return;
	if (!(g_iWeaponBit & (1<<(WEAPON_VEST))))
		return;
	if (g_iWeapon <= 0)
		return;
	if (g_iWeaponData[g_iWeapon].iAmmoType <= 0)
		return;
	if(g_ExtraAmmo_Draw >= 2) return;

	int x, y;
	int r, g, b, a;
	int iFlags;

	a = (int) max(MIN_ALPHA, g_flWeaponFade);

	if (g_flWeaponFade > 0)
		g_flWeaponFade -= (g_flTimeDelta * 20);

	UnpackRGB(r, g, b, RGB_YELLOWISH);
	ScaleColors(r, g, b, a);

	int iIconWidth = g_iWeaponData[g_iWeapon].rcAmmoIcon.right - g_iWeaponData[g_iWeapon].rcAmmoIcon.left;
	y = g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2;

	if (g_iWeaponData[g_iWeapon].iClip < 0)
	{
		x = g_sScreenInfo.iWidth - 4 * g_iFontWidth - iIconWidth;

		if (g_iAmmoCount[g_iWeaponData[g_iWeapon].iAmmoType] >= 10000)
			iFlags = DHN_DRAWZERO | DHN_5DIGITS;
		else if (g_iAmmoCount[g_iWeaponData[g_iWeapon].iAmmoType] >= 1000)
			iFlags = DHN_DRAWZERO | DHN_4DIGITS;
		else
			iFlags = DHN_DRAWZERO | DHN_3DIGITS;

		x = DrawHudNumber(x, y, iFlags, g_iAmmoCount[g_iWeaponData[g_iWeapon].iAmmoType], r, g, b);
		return;
	}
	x = g_sScreenInfo.iWidth - 8 * g_iFontWidth - iIconWidth;

	if (g_iWeaponData[g_iWeapon].iClip >= 10000)
		iFlags = DHN_DRAWZERO | DHN_5DIGITS;
	else if (g_iWeaponData[g_iWeapon].iClip >= 1000)
		iFlags = DHN_DRAWZERO | DHN_4DIGITS;
	else
		iFlags = DHN_DRAWZERO | DHN_3DIGITS;

	x = DrawHudNumber(x, y, iFlags, g_iWeaponData[g_iWeapon].iClip, r, g, b);

	int iBarWidth =  g_iFontWidth / 10;
	x += g_iFontWidth / 2;
	gEngfuncs.pfnFillRGBA(x, y, iBarWidth, g_iFontHeight, r, g, b, a);
	x += iBarWidth + g_iFontWidth / 2;

	if (g_iAmmoCount[g_iWeaponData[g_iWeapon].iAmmoType] >= 10000)
		iFlags = DHN_DRAWZERO | DHN_5DIGITS;
	else if (g_iAmmoCount[g_iWeaponData[g_iWeapon].iAmmoType] >= 1000)
		iFlags = DHN_DRAWZERO | DHN_4DIGITS;
	else
		iFlags = DHN_DRAWZERO | DHN_3DIGITS;

	DrawHudNumber(x, y, iFlags, g_iAmmoCount[g_iWeaponData[g_iWeapon].iAmmoType], r, g, b);
}

void DisplayRedraw(float flTime, int iIntermission)
{
	g_fOldTime = g_flTime;
	g_flTime = flTime;

	g_flTimeDelta = (double)g_flTime - g_fOldTime;

	Tri_Disable( GL_BLEND );
	Tri_Disable( GL_ALPHA_TEST );
	Tri_TexEnvf( GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE );
	if(g_iMod != MOD_ZE && g_iMod != MOD_DR)
	{
		DisplayHealth(g_flTime, 1);
		DisplayArmor(g_flTime, 1);
	}
	DisplayWeapon(g_flTime, 1);
	
	if((g_iBTEWeapon == WPN_JANUS5 || g_iBTEWeapon == WPN_JANUS3 || g_iBTEWeapon == WPN_JANUS7 || g_iBTEWeapon == WPN_JANUS) && g_iWeaponStat == 52 && g_bAlive)
	{
		gEngfuncs.pfnSPR_Set(GetSprite(g_infinite), 157, 247, 255);
		gEngfuncs.pfnSPR_DrawAdditive(0, g_sScreenInfo.iWidth - 80, g_sScreenInfo.iHeight - 68, &GetSpriteRect(g_infinite));

		gEngfuncs.pfnSPR_Set(g_iWeaponData[g_iCurrentWeapon].hAmmoIcon2, 157, 247, 255);
		gEngfuncs.pfnSPR_DrawAdditive(0, g_sScreenInfo.iWidth - 40, g_sScreenInfo.iHeight - 70, &g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon2);
	}

	if(g_fCountDown > g_flTime)
	{
		MH_DrawTGAFunction(g_Texture[g_iCountBg].iTexture,255,255,255,255,20,0.4*g_sScreenInfo.iHeight,1.4);
		Fonts_SetSize(24,24);
		Fonts_SetColor(251,201,96,255);

		// Get Center -- 120?
		int iStartX = 110-Fonts_GetLen(UTF8ToUnicode(g_sCountDownText))/2;

		Fonts_Draw(UTF8ToUnicode(g_sCountDownText),iStartX,0.4*g_sScreenInfo.iHeight+55,1000,1000);
		Fonts_SetSize(64,64);
		int iRemain = int(g_fCountDown - g_flTime);
		if(iRemain < 10)
		{
			Fonts_SetColor(255,50,50,255);
		}
		char txt[6];
		sprintf(txt,"%d",iRemain);
		Fonts_Draw(UTF8ToUnicode(txt),iRemain<10?95:80,0.4*g_sScreenInfo.iHeight+135,1000,1000);
	}
	/*if(g_szCurWeapon2 && g_bAlive && g_iMod == MOD_GD)
	{
		Fonts_SetColor(251,201,96,255);
		Fonts_SetSize(24,24);
		Fonts_Draw(g_szCurWeapon2, g_sScreenInfo.iWidth - Fonts_GetLen(g_szCurWeapon2) - 18 ,g_sScreenInfo.iHeight - 50, 1000,100);
	}*/
}

void EngFunc_SPR_DrawAdditive(int frame, int x, int y, const wrect_t *prc)
{	
	if (frame)
		return;

	if (x < g_sScreenInfo.iWidth * 0.4 && y == g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2)
		return;

	if (x > g_sScreenInfo.iWidth * 0.75 && y == g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2)
		return;
	if(x > g_sScreenInfo.iWidth * 0.6 && y >= g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight && g_ExtraAmmo_Draw >= 2)
		return;

	//if(g_HideMoney == HIDEMONEY_NONE) return gEngfuncs.pfnSPR_DrawAdditive(frame, x, y, prc);

	//if(g_ExtraAmmo_Draw != 1) return gEngfuncs.pfnSPR_DrawAdditive(frame, x, y, prc);

	if(prc)
	{
		if(g_iMod == MOD_NONE || g_iMod == MOD_ZBS || !g_iMod)
		{
			if((prc->right - prc->left) == 18) //MONEY
			{
				g_MoneyPosIco = y;
				if(g_ExtraAmmo_Draw == 1) y -= 40;
				if((g_iBTEWeapon == WPN_JANUS5 || g_iBTEWeapon == WPN_JANUS3 || g_iBTEWeapon == WPN_JANUS11 || g_iBTEWeapon == WPN_JANUS7 || g_iBTEWeapon == WPN_JANUS) && g_iWeaponStat == 52) y -= 30;
			}
			else if((prc->bottom - prc->top) == 23) ///PLUS MINUS
			{
				g_MoneyPosSym = y;
				if(g_ExtraAmmo_Draw == 1) y -= 40;
				if((g_iBTEWeapon == WPN_JANUS5 || g_iBTEWeapon == WPN_JANUS3 || g_iBTEWeapon == WPN_JANUS11 || g_iBTEWeapon == WPN_JANUS7 || g_iBTEWeapon == WPN_JANUS) && g_iWeaponStat == 52) y -= 30;
			}
			else if(y == g_MoneyPosIco || y == g_MoneyPosSym)
			{
				if(g_ExtraAmmo_Draw == 1) y -= 40;
				if((g_iBTEWeapon == WPN_JANUS5 || g_iBTEWeapon == WPN_JANUS3 || g_iBTEWeapon == WPN_JANUS11 || g_iBTEWeapon == WPN_JANUS7 || g_iBTEWeapon == WPN_JANUS) && g_iWeaponStat == 52) y -= 30;
			}
		}
		else
		{
			if((prc->right - prc->left) == 18) //MONEY
			{
				g_MoneyPosIco = y;
				y += 180;
			}
			else if((prc->bottom - prc->top) == 23) ///PLUS MINUS
			{
				g_MoneyPosSym = y;
				y += 180;
			}
			else if(y == g_MoneyPosIco || y == g_MoneyPosSym)
			{
				y += 180;
			}
		}
	}
	return gEngfuncs.pfnSPR_DrawAdditive(frame, x, y, prc);
}

void EngFunc_FillRGBA(int x, int y, int width, int height, int r, int g, int b, int a)
{
	if (y == g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2)
		return;
	gEngfuncs.pfnFillRGBA(x, y, width, height, r, g, b, a);
	
}
void CHudAmmo::Draw(float flTime)
{
	if ((IS_FIRSTPERSON_SPEC || g_bAlive) && g_iCurrentWeapon != WEAPON_AWP && g_iCurrentWeapon != WEAPON_SCOUT && g_iCurrentWeapon != WEAPON_SG550 && g_iCurrentWeapon != WEAPON_G3SG1  && !(g_iHideWeapon & HIDEWEAPON_CROSSHAIR) && fCurrentFOV > 40.0 && !g_WeaponData[g_iCurWeapon].iHideCrosshair)
		DrawCrosshair(flTime, g_iCurrentWeapon);

	if (g_fExtraAmmmoNextCanDraw > g_flTime)
		return;

	if (g_WeaponData[g_iCurWeapon].iCrosshair == 1 && (g_bAlive/* || IS_FIRSTPERSON_SPEC*/))
	{
		int x, y;
		x = g_sScreenInfo.iWidth / 2 - (g_iWeaponData[g_iCurrentWeapon].rcAutoaim.right - g_iWeaponData[g_iCurrentWeapon].rcAutoaim.left) / 2;
		y = g_sScreenInfo.iHeight / 2 - (g_iWeaponData[g_iCurrentWeapon].rcAutoaim.bottom - g_iWeaponData[g_iCurrentWeapon].rcAutoaim.top) / 2;

		gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
		gEngfuncs.pfnSPR_Set(g_iWeaponData[g_iCurrentWeapon].hAutoaim, 255, 255, 255);

		if(g_iBTEWeapon == WPN_JANUS && (g_iWeaponStat == 51 || g_iWeaponStat == 52))
			gEngfuncs.pfnSPR_Set(g_iWeaponData[g_iCurrentWeapon].hAutoaim, 170, 83, 196);

		if(g_iWeaponData[g_iCurrentWeapon].rcAutoaim.right > 0 && g_iWeaponData[g_iCurrentWeapon].rcAutoaim.bottom > 0)
			gEngfuncs.pfnSPR_DrawHoles(0, x, y, &g_iWeaponData[g_iCurrentWeapon].rcAutoaim);
	}

	if (g_WeaponData[g_iCurWeapon].iCrosshair == 2 && (g_bAlive/* || IS_FIRSTPERSON_SPEC*/) && g_iShowCustomCrosshair)
	{
		int x, y;
		x = g_sScreenInfo.iWidth / 2 - (g_iWeaponData[g_iCurrentWeapon].rcAutoaim.right - g_iWeaponData[g_iCurrentWeapon].rcAutoaim.left) / 2;
		y = g_sScreenInfo.iHeight / 2 - (g_iWeaponData[g_iCurrentWeapon].rcAutoaim.bottom - g_iWeaponData[g_iCurrentWeapon].rcAutoaim.top) / 2;

		gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
		gEngfuncs.pfnSPR_Set(g_iWeaponData[g_iCurrentWeapon].hAutoaim, 255, 255, 255);
		if(g_iWeaponData[g_iCurrentWeapon].rcAutoaim.right > 0 && g_iWeaponData[g_iCurrentWeapon].rcAutoaim.bottom > 0)
			gEngfuncs.pfnSPR_DrawHoles(0, x, y, &g_iWeaponData[g_iCurrentWeapon].rcAutoaim);
	}
}
void CHudAmmo::VidInit(void)
{
	m_iAlpha = 255;
}

int CHudAmmo::DrawCrosshair(float flTime, int weaponid)
{
	int iDistance;
	int iDeltaDistance;
	int iWeaponAccuracyFlags;
	int iBarSize;
	float flCrosshairDistance;

	int ScreenWidth = g_sScreenInfo.iWidth;
	int ScreenHeight = g_sScreenInfo.iHeight;


	switch (weaponid)
	{
		case WEAPON_P228:
		case WEAPON_HEGRENADE:
		case WEAPON_SMOKEGRENADE:
		case WEAPON_FIVESEVEN:
		case WEAPON_USP:
		case WEAPON_GLOCK18:
		case WEAPON_AWP:
		case WEAPON_FLASHBANG:
		case WEAPON_DEAGLE:
		{
			iDistance = 8;
			iDeltaDistance = 3;
			break;
		}

		case WEAPON_MP5NAVY:
		{
			iDistance = 6;
			iDeltaDistance = 2;
			break;
		}

		case WEAPON_M3:
		{
			iDistance = 8;
			iDeltaDistance = 6;
			break;
		}

		case WEAPON_G3SG1:
		{
			iDistance = 6;
			iDeltaDistance = 4;
			break;
		}

		case WEAPON_AK47:
		{
			iDistance = 4;
			iDeltaDistance = 4;
			break;
		}

		case WEAPON_TMP:
		case WEAPON_KNIFE:
		case WEAPON_P90:
		{
			iDistance = 7;
			iDeltaDistance = 3;
			break;
		}

		case WEAPON_XM1014:
		{
			iDistance = 9;
			iDeltaDistance = 4;
			break;
		}

		case WEAPON_MAC10:
		{
			iDistance = 9;
			iDeltaDistance = 3;
			break;
		}

		case WEAPON_AUG:
		{
			iDistance = 3;
			iDeltaDistance = 3;
			break;
		}

		case WEAPON_C4:
		case WEAPON_UMP45:
		case WEAPON_M249:
		{
			iDistance = 6;
			iDeltaDistance = 3;
			break;
		}

		case WEAPON_SCOUT:
		case WEAPON_SG550:
		case WEAPON_SG552:
		{
			iDistance = 5;
			iDeltaDistance = 3;
			break;
		}

		default:
		{
			iDistance = 4;
			iDeltaDistance = 3;
			break;
		}
	}

	iWeaponAccuracyFlags = GetWeaponAccuracyFlags(weaponid);

	if (iWeaponAccuracyFlags != 0 && cl_dynamiccrosshair && cl_dynamiccrosshair->value != 0.0)
	{
		if ((g_iPlayerFlags & FL_ONGROUND) || !(iWeaponAccuracyFlags & 1))
		{
			if ((g_iPlayerFlags & FL_DUCKING) && (iWeaponAccuracyFlags & 4))
			{
				iDistance *= 0.5;
			}
			else
			{
				float flLimitSpeed;

				switch (weaponid)
				{
					case WEAPON_MAC10:
					case WEAPON_SG550:
					case WEAPON_GALIL:
					case WEAPON_MP5NAVY:
					case WEAPON_M3:
					case WEAPON_DEAGLE:
					case WEAPON_SG552:
					{
						flLimitSpeed = 140;
						break;
					}

					case WEAPON_KNIFE:
					{
						flLimitSpeed = 170;
						break;
					}

					default:
					{
						flLimitSpeed = 0;
						break;
					}
				}

				if (g_flPlayerSpeed > flLimitSpeed && (iWeaponAccuracyFlags & 2))
					iDistance *= 1.5;
			}
		}
		else
			iDistance *= 2;

		if (iWeaponAccuracyFlags & 8)
			iDistance *= 1.4;

		if (iWeaponAccuracyFlags & 0x10)
			iDistance *= 1.4;
	}

	if (g_iShotsFired > m_iAmmoLastCheck)
	{
		m_flCrosshairDistance += iDeltaDistance;
		m_iAlpha -= 40;

		if (m_flCrosshairDistance > 15)
			m_flCrosshairDistance = 15;

		if (m_iAlpha < 120)
			m_iAlpha = 120;
	}
	else
	{
		m_flCrosshairDistance -= (0.013 * m_flCrosshairDistance) + 0.1;
		m_iAlpha += 2;
	}

	if (g_iShotsFired > 600)
		g_iShotsFired = 1;

	m_iAmmoLastCheck = g_iShotsFired;

	if (iDistance > m_flCrosshairDistance)
		m_flCrosshairDistance = iDistance;

	if (m_iAlpha > 255)
		m_iAlpha = 255;

	iBarSize = (int)((m_flCrosshairDistance - (float)iDistance) * 0.5) + 5;

	if (g_flTime > m_flLastCalcTime + 1)
	{
		CalculateCrosshairColor();
		CalculateCrosshairDrawMode();
		CalculateCrosshairSize();

		m_flLastCalcTime = g_flTime;
	}
	
	flCrosshairDistance = m_flCrosshairDistance;

	if (m_iCrosshairScaleBase != ScreenWidth)
	{
		flCrosshairDistance *= (float)(ScreenWidth) / m_iCrosshairScaleBase;
		iBarSize = (float)(ScreenWidth * iBarSize) / m_iCrosshairScaleBase;
	}

	if (m_bNvgOn || g_zb_nvg)
		DrawCrosshairEx(flTime, weaponid, iBarSize, flCrosshairDistance, false, 250, 50, 50, m_iAlpha);
	else
		DrawCrosshairEx(flTime, weaponid, iBarSize, flCrosshairDistance, m_bAdditive, m_R, m_G, m_B, m_iAlpha);
	
	return 1;
}
void CHudAmmo::SetNvgOn(bool bNvg)
{
	m_bNvgOn = bNvg;
}

int CHudAmmo::GetWeaponAccuracyFlags(int iWeaponID)
{
	int flags;

	switch (iWeaponID)
	{
		case WEAPON_USP:
		{
			flags = (g_iWeaponFlags & 1) < 1 ? 7 : 15;
			break;
		}

		case WEAPON_GLOCK18:
		{
			flags = (g_iWeaponFlags & 2) < 1 ? 7 : 23;
			break;
		}

		case WEAPON_M4A1:
		{
			flags = (g_iWeaponFlags & 4) < 1 ? 3 : 11;
			break;
		}

		case WEAPON_MAC10:
		case WEAPON_UMP45:
		case WEAPON_MP5NAVY:
		case WEAPON_TMP:
		{
			flags = 1;
			break;
		}

		case WEAPON_AUG:
		case WEAPON_GALIL:
		case WEAPON_M249:
		case WEAPON_SG552:
		case WEAPON_AK47:
		case WEAPON_P90:
		{
			flags = 3;
			break;
		}

		case WEAPON_P228:
		case WEAPON_FIVESEVEN:
		case WEAPON_DEAGLE:
		{
			flags = 7;
			break;
		}

		case WEAPON_FAMAS:
		{
			flags = (g_iWeaponFlags & 0x10) < 1 ? 3 : 19;
			break;
		}

		default:
		{
			flags = 0;
			break;
		}
	}

	return flags;
}




int CHudAmmo::DrawCrosshairEx(float flTime, int weaponid, int iBarSize, float flCrosshairDistance, bool bAdditive, int r, int g, int b, int a)
{
	bool bDrawPoint = false;
	bool bDrawCircle = false;
	bool bDrawCross = false;

	int ScreenWidth = g_sScreenInfo.iWidth;
	int ScreenHeight = g_sScreenInfo.iHeight;

	void (*pfnFillRGBA)(int x, int y, int w, int h, int r, int g, int b, int a) = (bAdditive == false) ? gEngfuncs.pfnFillRGBABlend : gEngfuncs.pfnFillRGBA;

	switch ((int)cl_crosshair_type->value)
	{
		case 1:
		{
			bDrawPoint = true;
			bDrawCross = true;
			break;
		}

		case 2:
		{
			bDrawPoint = true;
			bDrawCircle = true;
			break;
		}

		case 3:
		{
			bDrawPoint = true;
			bDrawCircle = true;
			bDrawCross = true;
			break;
		}

		case 4:
		{
			bDrawPoint = true;
			break;
		}

		default:
		{
			bDrawCross = true;
			break;
		}
	}

	if (bDrawCircle)
	{
#if 1
		float radius = (iBarSize / 2) + flCrosshairDistance;
#if 0
		switch (m_iCrosshairScaleBase)
		{
			case 640: radius += 0.1; break;
			case 800: radius += 0.8; break;
			case 1024: radius += 0.5; break;
		}
#endif
		int count = (int)((cos(0.7853981852531433) * radius) + 0.5);

		for (int i = 0; i < count; i++)
		{
			int size = sqrt((radius * radius) - (float)(i * i));

			pfnFillRGBA((ScreenWidth / 2) + i, (ScreenHeight / 2) + size, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) + i, (ScreenHeight / 2) - size, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) - i, (ScreenHeight / 2) + size, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) - i, (ScreenHeight / 2) - size, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) + size, (ScreenHeight / 2) + i, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) + size, (ScreenHeight / 2) - i, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) - size, (ScreenHeight / 2) + i, 1, 1, r, g, b, a);
			pfnFillRGBA((ScreenWidth / 2) - size, (ScreenHeight / 2) - i, 1, 1, r, g, b, a);
		}
#else
		float radius = flCrosshairDistance * 1.1 + (iBarSize / 2);
		int count = radius * 3;

		qglDisable(GL_TEXTURE_2D);
		qglEnable(GL_BLEND);
		qglTexEnvf(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);

		if (m_bAdditive == false)
			qglBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
		else
			qglBlendFunc(GL_SRC_ALPHA, GL_ONE);

		qglColor4f(r / 255.0, g / 255.0, b / 255.0, a / 255.0);
		qglBegin(GL_LINE_LOOP);

		for (int i = 0; i < count; i++)
		{
			float angles = 2 * M_PI / count * i;
			qglVertex2f((ScreenWidth / 2) + radius * cos(angles), (ScreenHeight / 2) + radius * sin(angles));
		}

		qglEnd();
		qglColor3f(1, 1, 1);
		qglEnable(GL_TEXTURE_2D);
		qglDisable(GL_BLEND);
#endif
	}

	if (bDrawPoint)
		pfnFillRGBA((ScreenWidth / 2) - 1, (ScreenHeight / 2) - 1, 3, 3, r, g, b, a);

	if (bDrawCross)
	{
		pfnFillRGBA((ScreenWidth / 2) - (int)flCrosshairDistance - iBarSize + 1, ScreenHeight / 2, iBarSize, 1, r, g, b, a);
		pfnFillRGBA((ScreenWidth / 2) + (int)flCrosshairDistance, ScreenHeight / 2, iBarSize, 1, r, g, b, a);
		pfnFillRGBA(ScreenWidth / 2, (ScreenHeight / 2) - (int)flCrosshairDistance - iBarSize + 1, 1, iBarSize, r, g, b, a);
		pfnFillRGBA(ScreenWidth / 2, (ScreenHeight / 2) + (int)flCrosshairDistance, 1, iBarSize, r, g, b, a);
	}

	return 1;
}

void CHudAmmo::CalculateCrosshairDrawMode(void)
{
	float value = cl_crosshair_translucent->value;

	if (value == 0)
		m_bAdditive = false;
	else if (value == 1)
		m_bAdditive = true;
	else
		gEngfuncs.Con_Printf("usage: cl_crosshair_translucent <1|0>\n");
}

void CHudAmmo::CalculateCrosshairSize(void)
{
	char *value = cl_crosshair_size->string;

	int ScreenWidth = g_sScreenInfo.iWidth;
	int ScreenHeight = g_sScreenInfo.iHeight;


	if (!value)
		return;

	int size = atoi(value);

	if (size)
	{
		if (size > 3)
			size = -1;
	}
	else
	{
		if (strcmp(value, "0"))
			size = -1;
	}

	if (!stricmp(value, "auto"))
		size = 0;
	else if (!stricmp(value, "small"))
		size = 1;
	else if (!stricmp(value, "medium"))
		size = 2;
	else if (!stricmp(value, "large"))
		size = 3;

	if (size == -1)
	{
		gEngfuncs.Con_Printf("usage: cl_crosshair_size <auto|small|medium|large>\n");
		return;
	}

	switch (size)
	{
		case 0:
		{
			if (ScreenWidth >= 1024)
				m_iCrosshairScaleBase = 640;
			else if (ScreenWidth >= 800)
				m_iCrosshairScaleBase = 800;
			else
				m_iCrosshairScaleBase = 1024;

			break;
		}

		case 1:
		{
			m_iCrosshairScaleBase = 1024;
			break;
		}

		case 2:
		{
			m_iCrosshairScaleBase = 800;
			break;
		}

		case 3:
		{
			m_iCrosshairScaleBase = 640;
			break;
		}
	}
}


static char s_shared_token[1500];

char *SharedParse(char *data)
{
	int len = 0, c;
	s_shared_token[0] = '\0';

	if (!data)
		return NULL;

skipwhite:
	while ((c = *data) <= ' ')
	{
		if (c == 0)
			return NULL;

		data++;
	}

	if (c == '/' && data[1] == '/')
	{
		while (*data && *data != '\n')
			data++;

		goto skipwhite;
	}

	if (c == '\"')
	{
		data++;

		while (1)
		{
			c = *data++;

			if (c == '\"' || !c)
			{
				s_shared_token[len] = '\0';
				return data;
			}

			s_shared_token[len++] = c;
		}
	}

	if (c == '{' || c == '}'|| c == ')'|| c == '(' || c == '\'' || c == ',')
	{
		s_shared_token[len++] = c;
		s_shared_token[len] = '\0';
		return data + 1;
	}

	do
	{
		s_shared_token[len] = c;
		data++;
		len++;
		c = *data;

		if (c == '{' || c == '}'|| c == ')'|| c == '(' || c == '\'' || c == ',')
			break;
	}
	while (c > 32);

	s_shared_token[len] = '\0';
	return data;
}

const char *SharedParse(const char *data)
{
	int len = 0, c;
	s_shared_token[0] = '\0';

	if (!data)
		return NULL;

skipwhite:
	while ((c = *data) <= ' ')
	{
		if (c == 0)
			return NULL;

		data++;
	}

	if (c == '/' && data[1] == '/')
	{
		while (*data && *data != '\n')
			data++;

		goto skipwhite;
	}

	if (c == '\"')
	{
		data++;

		while (1)
		{
			c = *data++;

			if (c == '\"' || !c)
			{
				s_shared_token[len] = '\0';
				return data;
			}

			s_shared_token[len++] = c;
		}
	}

	if (c == '{' || c == '}'|| c == ')'|| c == '(' || c == '\'' || c == ',')
	{
		s_shared_token[len++] = c;
		s_shared_token[len] = '\0';
		return data + 1;
	}

	do
	{
		s_shared_token[len] = c;
		data++;
		len++;
		c = *data;

		if (c == '{' || c == '}'|| c == ')'|| c == '(' || c == '\'' || c == ',')
			break;
	}
	while (c > 32);

	s_shared_token[len] = '\0';
	return data;
}

char *SharedVarArgs(char *format, ...)
{
	va_list argptr;
	const int BufLen = 1024;
	const int NumBuffers = 4;
	static char string[NumBuffers][BufLen];
	static int curstring = 0;

	curstring = (curstring + 1) % NumBuffers;

	va_start (argptr, format);
	_vsnprintf( string[curstring], BufLen, format, argptr);
	va_end (argptr);

	return string[curstring];
}

char *SharedGetToken(void)
{
	return s_shared_token;
}


void CHudAmmo::CalculateCrosshairColor(void)
{
#ifdef TIMETEST_CALCCROSSHAIRCOLOR
	float startTime = gPerformanceCounter.GetCurTime();
#endif
	char *value = cl_crosshair_color->string;

	if (value && strcmp(value, m_szLastCrosshairColor))
	{
		int cvarR, cvarG, cvarB;
		char *token;
		char *data = value;

		data = SharedParse(data);
		token = SharedGetToken();

		if (token)
		{
			cvarR = atoi(token);

			data = SharedParse(data);
			token = SharedGetToken();

			if (token)
			{
				cvarG = atoi(token);

				data = SharedParse(data);
				token = SharedGetToken();

				if (token)
				{
					cvarB = atoi(token);

					if (m_cvarR != cvarR || m_cvarG != cvarG || m_cvarB != cvarB)
					{
						int r, g, b;

						r = min(max(0, cvarR), 255);
						g = min(max(0, cvarG), 255);
						b = min(max(0, cvarB), 255);

						m_R = r;
						m_G = g;
						m_B = b;
						m_cvarR = cvarR;
						m_cvarG = cvarG;
						m_cvarB = cvarB;
					}

					strcpy(m_szLastCrosshairColor, value);
				}
			}
		}
	}

#ifdef TIMETEST_CALCCROSSHAIRCOLOR
	gEngfuncs.Con_Printf("TimeTest CHudAmmo::CalculateCrosshairColor take %.1f sec\n", gPerformanceCounter.GetCurTime() - startTime);
#endif
}
