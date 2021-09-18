#include "base.h"

int g_ExtraAmmo_Draw;
int g_ExtraAmmo;
int g_ExtraAmmoIndex;
int g_ExtraAmmoIndex_Svdex,g_ExtraAmmoIndex_Musket,g_ExtraAmmoIndex_SfSniper,g_ExtraAmmoIndex_Cannon,g_ExtraAmmoIndex_M200,g_ExtraAmmoIndex_tknife,g_ExtraAmmoIndex_bow;
int g_iWpn_X,g_iWpn_Y;
int g_ExtraAmmo_Svdex_Num = 0;
int DrawType = 0;
float g_fExtraAmmmoNextCanDraw;

int WEAPON_AMMOID[31] = { -1, 9, -1, 2, 12, 5, 14, 6, 4, 13, 10, 7, 6, 4, 4, 4, 6, 10, 1, 10, 3, 5, 4, 10, 2, 11, 8, 4, 2, -1, 7};

void DrawExtraAmmoInitialize()
{
	g_ExtraAmmo = -1; //NONE
	g_ExtraAmmo_Draw = 0;
}

void DrawExtraAmmoRedraw()
{
	if(!g_ExtraAmmo_Draw || !g_bAlive || g_fExtraAmmmoNextCanDraw > g_flTime) return;
	int r, g, b;
	int x,y;
	int iIconWidth = g_iWeaponData[g_iWeapon].rcAmmoIcon.right - g_iWeaponData[g_iWeapon].rcAmmoIcon.left;
	y = g_sScreenInfo.iHeight - g_iFontHeight - g_iFontHeight / 2;

	if(g_ExtraAmmo_Draw == 1)
	{
		y = g_MoneyPosIco;
	}
	x = g_sScreenInfo.iWidth - 3 * g_iFontWidth - iIconWidth;


	UnpackRGB(r, g, b, RGB_LIGHTBLUE);

	if(g_iBTEWeapon == WPN_M200)
		UnpackRGB(r, g, b, RGB_YELLOWISH);
		
	if(g_ExtraAmmo_Draw == 1)
	{
		x = DrawExtraAmmoNumber(x, y, g_ExtraAmmo_Svdex_Num, r, g, b);
	}
	else 
	{
		/*if(g_iBTEWeapon == WPN_SFSNIPER || g_iBTEWeapon == WPN_M200 || g_ExtraAmmoIndex == g_ExtraAmmoIndex_tknife || g_ExtraAmmoIndex == g_ExtraAmmoIndex_bow)
		{
			DrawType = 1;
			x = DrawExtraAmmoNumber(x,y,g_iWeaponData[g_iWeapon].iClip, r, g, b);
		}
		else
		{
			DrawType = 0;
			x = DrawExtraAmmoNumber(x,y,g_ExtraAmmo, r, g, b);
		}*/
		if(g_ExtraAmmo_Draw == 2)
			x = DrawExtraAmmoNumber(x, y, g_iAmmoCount[WEAPON_AMMOID[g_iCurrentWeapon]], r, g, b);
		else if(g_ExtraAmmo_Draw == 3)
			x = DrawExtraAmmoNumber(x, y, g_iWeaponData[g_iCurrentWeapon].iClip, r, g, b);
		else
			x = DrawExtraAmmoNumber(x, y, g_iWeaponData[g_iCurrentWeapon].iClip + g_iAmmoCount[WEAPON_AMMOID[g_iCurrentWeapon]], r, g, b);
	}
	

	if(g_ExtraAmmo_Draw == 1)
	{
		gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
		gEngfuncs.pfnSPR_Set(g_iWeaponData[g_iCurrentWeapon].hAmmoIcon2, r, g, b);
		if(g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon2.right > 0 && g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon2.bottom > 0)
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon2);
	}
	else
	{
		gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
		gEngfuncs.pfnSPR_Set(g_iWeaponData[g_iCurrentWeapon].hAmmoIcon, r, g, b);
		if(g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon.right > 0 && g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon.bottom > 0)
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &g_iWeaponData[g_iCurrentWeapon].rcAmmoIcon);
	}

}

int DrawExtraAmmoNumber(int x, int y,int iNumber, int r, int g, int b)
{
	int k;
	int iWidth = g_iFontWidth;

	if (iNumber > -1)
	{
		if (iNumber >= 10)
		{
			k = (iNumber % 100) / 10;
			gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
			gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_iNumberZero + k));
			x += iWidth;
		}
		else x += iWidth;
		k = iNumber % 10;
		gEngfuncs.pfnSPR_Set(GetSprite(g_iNumberZero + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0,  x, y, &GetSpriteRect(g_iNumberZero + k));
		x += iWidth;
	} 
	return x;
}