#include "base.h"

int g_SBTopLeft,g_SBTopCenter,g_SBTopRight,g_SBDownLeft,g_SBDownRight,g_SBMode;

ScoreBoard g_ScoreBoard;

int ScoreBoard::DrawHudsNumber(int x, int y, int iNumber, int r, int g, int b,int length)
{
	int k;
	if (length>3)
	{
		k = 0;
		if(iNumber >= 1000) k = (iNumber % 10000)/1000;
		gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_snumber_0 + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_SBHUD_snumber_0 + k));
		x += m_iSBsFontWidth;
	}

	if (length>2)
	{
		k = 0;
		if(iNumber >= 100) k = (iNumber % 1000)/100;
		gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_snumber_0 + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_SBHUD_snumber_0 + k));
		x += m_iSBsFontWidth;
		
	}

	if (length>1)
	{
		k = 0;
		if(iNumber >= 10) k = (iNumber % 100)/10;
		gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_snumber_0 + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_SBHUD_snumber_0 + k));
		x += m_iSBsFontWidth;
	}

	k = iNumber % 10;
	gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_snumber_0 + k), r, g, b);
	gEngfuncs.pfnSPR_DrawAdditive(0,  x, y, &GetSpriteRect(m_SBHUD_snumber_0 + k));
	x += m_iSBsFontWidth;

	return x;
}
int ScoreBoard::DrawHudNumber(int x, int y, int iNumber, int r, int g, int b,int length)
{
	int k;
	if (length>3)
	{
		k = 0; 
		if(iNumber>=1000) k = (iNumber % 10000)/1000;
		gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_number_0 + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_SBHUD_number_0 + k));
		x += m_iSBFontWidth;
	}

	if (length>2)
	{
		k = 0; 
		if(iNumber>=100) k = (iNumber % 1000)/100;
		gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_number_0 + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_SBHUD_number_0 + k));
		x += m_iSBFontWidth;
	}

	if (length>1)
	{
		k = 0; 
		if(iNumber>=10) k = (iNumber % 100)/10;
		gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_number_0 + k), r, g, b);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_SBHUD_number_0 + k));
		x += m_iSBFontWidth;
	}

	k = iNumber % 10;
	gEngfuncs.pfnSPR_Set(GetSprite(m_SBHUD_number_0 + k), r, g, b);
	gEngfuncs.pfnSPR_DrawAdditive(0,  x, y, &GetSpriteRect(m_SBHUD_number_0 + k));
	x += m_iSBFontWidth;

	return x;
}
void ScoreBoard::Init()
{
	g_SBTopLeft = 0;
	g_SBTopCenter = 0;
	g_SBTopRight = 0;
	g_SBDownLeft = 0;
	g_SBDownRight = 0;
	g_SBMode = -1;

	m_SBHUD_number_0 = GetSpriteIndex("SBNum_0");
	m_iBgNone = GetSpriteIndex("SBOriginalBG");
	m_iBgTd = GetSpriteIndex("SBTeamDeathBG");
	m_iTextCT = GetSpriteIndex("SBText_CT");
	m_iTextTR = GetSpriteIndex("SBText_T");
	m_iTextRound = GetSpriteIndex("SBText_Round");
	m_iTextKill = GetSpriteIndex("SBText_Kill");
	m_iTextHM = GetSpriteIndex("SBText_HM");
	m_iTextZB = GetSpriteIndex("SBText_ZB");
	m_iText1st = GetSpriteIndex("SBText_1st");

	m_iSBFontWidth = g_rgrcRects[m_SBHUD_number_0].right - g_rgrcRects[m_SBHUD_number_0].left;
	m_iSBFontHeight = g_rgrcRects[m_SBHUD_number_0].bottom - g_rgrcRects[m_SBHUD_number_0].top;

	m_SBHUD_snumber_0 = GetSpriteIndex("SBSNum_0");
	m_iSBsFontWidth = g_rgrcRects[m_SBHUD_snumber_0].bottom - g_rgrcRects[m_SBHUD_snumber_0].top;
	m_iSBsFontHeight = g_rgrcRects[m_SBHUD_snumber_0].bottom - g_rgrcRects[m_SBHUD_snumber_0].top;
}
void ScoreBoard::Redraw()
{
	if (!g_pSpriteList || pCvar_ScoreBoard->value == 0)
		return;

	g_SBDownLeft = 0;
	g_SBDownRight = 0;

	for(int i=1;i<33;i++)
	{
		if(vPlayer[i].team == 2 && vPlayer[i].alive) g_SBDownLeft += 1;
		if(vPlayer[i].team == 1 && vPlayer[i].alive) g_SBDownRight += 1;
		/*char a[33];
		sprintf(a,"%d %d\n",vPlayer[i].team,vPlayer[i].alive);
		gEngfuncs.pfnConsolePrint(a);*/
		
	}
	if(g_iMod == MOD_NONE)
	{
		//========None Mod========
		//=====Bg
		int x,y;
		int iWidth = GetSpriteRect(m_iBgNone).right -GetSpriteRect(m_iBgNone).left ;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iBgNone), 225, 225, 225);
		x = (g_sScreenInfo.iWidth - iWidth) / 2;
		gEngfuncs.pfnSPR_DrawHoles(0, x, 0, &GetSpriteRect(m_iBgNone));

		//=====T,CT icon
		x += 65;
		y = 11;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextTR), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextTR));
		x += 70;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextCT), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextCT));
		//=====Draw Num Up 
		y -= 1;
		//Up Left
		x -= 115;
		DrawHudNumber(x, y,g_SBTopLeft, 120, 120, 120, 2);
		//Up Right
		x += 145;
		DrawHudNumber(x, y, g_SBTopRight, 120, 120, 120, 2);
		//Center
		x -=70;
		DrawHudNumber(x, y, g_SBTopCenter, 120, 120, 120, 2);
		//=====Round Icon
		x -= 6;
		y += 20;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextRound), 120,120,120);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextRound));
		//=====Draw Num Down
		//Down Left
		x -= 50;
		DrawHudsNumber(x, y, g_SBDownLeft, 120, 120, 120, 2);	
		//Down Right
		x += 116;
		DrawHudsNumber(x, y,g_SBDownRight, 120, 120, 120, 2);

	}
	else if(g_iMod == MOD_TDM)
	{
		//========None Mod========
		//=====Bg
		int x,y;
		int iWidth = GetSpriteRect(m_iBgTd).right -GetSpriteRect(m_iBgTd).left ;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iBgTd), 225, 225, 225);
		x = (g_sScreenInfo.iWidth - iWidth) / 2;
		gEngfuncs.pfnSPR_DrawHoles(0, x, 0, &GetSpriteRect(m_iBgTd));
		//=====T,CT icon
		x += 65;
		y = 11;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextTR), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextTR));
		x += 70;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextCT), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextCT));
		//=====Draw Num Up
		y -= 1;
		//Up Left
		x -= 120; // 120
		DrawHudNumber(x, y,g_SBTopLeft, 120, 120, 120, 3);
		//Up Right
		x += 145;
		DrawHudNumber(x, y, g_SBTopRight, 120, 120, 120, 3);
		//Center
		x -=74; //74
		DrawHudNumber(x, y, g_SBTopCenter, 120, 120, 120, 3); // 120X3,3
		//=====Kill Icon
		x += 3; //3
		y += 20; //20
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextKill), 120,120,120);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextKill));
	}
	else if(g_iMod == MOD_DM)
	{
		//=====Bg
		int x,y;
		int iWidth = GetSpriteRect(m_iBgTd).right -GetSpriteRect(m_iBgTd).left ;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iBgTd), 225, 225, 225);
		x = (g_sScreenInfo.iWidth - iWidth) / 2;
		gEngfuncs.pfnSPR_DrawHoles(0, x, 0, &GetSpriteRect(m_iBgTd));
		//=====T,CT icon
		x += 50;
		y = 11;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iText1st), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iText1st));
		x += 85;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextKill), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextKill));
		//=====Draw Num Up
		y -= 1;
		//Up Left
		x -= 118; // 120

		int iLocal =gEngfuncs.GetLocalPlayer()->index;
		g_SBTopRight = g_PlayerExtraInfo[iLocal].frags;

		g_SBTopLeft = 0;

		for(int i=1;i<33;i++)
		{
			if(g_PlayerExtraInfo[i].frags > g_SBTopLeft)
				g_SBTopLeft = g_PlayerExtraInfo[i].frags;
		}
		DrawHudNumber(x, y, g_SBTopLeft, 120, 120, 120, 2);
		//Up Right
		x += 155;
		DrawHudNumber(x, y, g_SBTopRight, 120, 120, 120, 2);
		//Center
		x -=77;
		DrawHudNumber(x, y, g_SBTopCenter, 120, 120, 120, 2);
		//=====Kill Icon
		x -= 5;
		y += 20; //20
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextKill), 120,120,120);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextKill));
	}
	else if(g_iMod == MOD_HD || g_iMod == MOD_SD)
	{
		//========None Mod========
		//=====Bg
		int x,y;
		int iWidth = GetSpriteRect(m_iBgTd).right -GetSpriteRect(m_iBgTd).left ;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iBgTd), 225, 225, 225);
		x = (g_sScreenInfo.iWidth - iWidth) / 2;
		gEngfuncs.pfnSPR_DrawHoles(0, x, 0, &GetSpriteRect(m_iBgTd));
		//=====T,CT icon
		x += 65;
		y = 11;
		/*gEngfuncs.pfnSPR_Set(GetSprite(g_SB_Text_T), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_SB_Text_T));*/
		x += 70;
		/*gEngfuncs.pfnSPR_Set(GetSprite(g_SB_Text_CT), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(g_SB_Text_CT));*/
		gEngfuncs.pfnSPR_Set(GetSprite(m_iText1st), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iText1st));
		//=====Draw Num Up
		y -= 1;
		//Up Left
		x -= 120; // 120
		DrawHudNumber(x, y,g_SBTopLeft, 120, 120, 120, 3);
		//Up Right
		x += 145;
		DrawHudNumber(x, y, g_SBTopRight, 120, 120, 120, 3);
		//Center
		x -=74; //74
		DrawHudNumber(x, y, g_SBTopCenter, 120, 120, 120, 3); // 120X3,3
		//=====Kill Icon
		x += 3; //3
		y += 20; //20
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextKill), 120,120,120);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextKill));
	}
	else if(g_iMod == MOD_ZE || g_iMod == MOD_ZB || g_iMod == MOD_ZB3)
	{
		//========None Mod========
		//=====Bg
		int x,y;
		int iWidth = GetSpriteRect(m_iBgNone).right -GetSpriteRect(m_iBgNone).left ;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iBgNone), 225, 225, 225);
		x = (g_sScreenInfo.iWidth - iWidth) / 2;
		gEngfuncs.pfnSPR_DrawHoles(0, x, 0, &GetSpriteRect(m_iBgNone));

		//=====T,CT icon
		x += 58;
		y = 11;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextZB), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextZB));
		x += 7;
		x += 70;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextHM), 140,140,140);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextHM));
		
		//=====Draw Num Up
		y -= 1;
		//Up Left
		x -= 115;
		DrawHudNumber(x, y,g_SBTopLeft, 120, 120, 120, 2);
		//Up Right
		x += 145;
		DrawHudNumber(x, y, g_SBTopRight, 120, 120, 120, 2);
		//Center
		x -=70;
		DrawHudNumber(x, y, g_SBTopCenter, 120, 120, 120, 2);
		//=====Round Icon
		x -= 6;
		y += 20;
		gEngfuncs.pfnSPR_Set(GetSprite(m_iTextRound), 120,120,120);
		gEngfuncs.pfnSPR_DrawAdditive(0, x, y, &GetSpriteRect(m_iTextRound));
		//=====Draw Num Down
		//Down Left
		x -= 50;
		DrawHudsNumber(x, y, g_SBDownLeft, 120, 120, 120, 2);	
		//Down Right
		x += 116;
		DrawHudsNumber(x, y,g_SBDownRight, 120, 120, 120, 2);

	}
}