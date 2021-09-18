#include "base.h"


int g_iGD_Left  = 5, g_iGD_Center ,g_iGD_Right,g_iGB_LV;
int iGDNumberIndex[10];
int iRank[3];
int g_plrRank[3];
int iGDBoardIndex;
int g_plrFrag[33];
float fScale = 0.16f;
float fScaleB = 1.0f;

int g_iGD_Y = 0;

int KILL_AIM[18] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 47, 49, 51, 54, 57, 60};

int GetLevel(int kills);
void DrawSelfNumbers(int n, int x, int y, float size = 1.0);

void MetaHookGDBoardInit(void)
{
	char TgaName[256];
	for(int i=0;i<10;i++)
	{
		sprintf(TgaName,"other\\number\\number%d",i);
		//sprintf(TgaName,"mode\\gd\\gdnumber\\number%d",i);
		iGDNumberIndex[i] = DrawTgaGetID(TgaName);
	}
	iGDBoardIndex = DrawTgaGetID("mode\\gd\\gdboard");
	iRank[0] = DrawTgaGetID("mode\\gd\\gd1st");
	iRank[1] = DrawTgaGetID("mode\\gd\\gd2nd");
	iRank[2] = DrawTgaGetID("mode\\gd\\gd3rd");
	memset(g_plrFrag,0,sizeof(g_plrFrag));
}
void DrawGDBoardInitialize()
{
	g_iGD_Left = 889;
	g_iGD_Center = 777;
	g_iGD_Right = 998;
	g_iGB_LV = 1;
	g_iGD_Y = 0;
	memset(g_plrRank,0,sizeof(g_plrRank));
	memset(g_plrFrag,0,sizeof(g_plrFrag));
	
}
void DrawGDBoardRedraw()
{
	//Draw Board
	if(g_iMod != MOD_GD) return;
	int iStartX = (g_sScreenInfo.iWidth - g_MHTga[iGDBoardIndex].width*fScaleB)/2;
	int iStartY = 10;
	fScale = 0.16f;	

	Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDBoardIndex].texid);
	gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iStartX,iStartY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iStartX+g_MHTga[iGDBoardIndex].width*fScaleB,iStartY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iStartX+g_MHTga[iGDBoardIndex].width*fScaleB,iStartY+g_MHTga[iGDBoardIndex].height*fScaleB,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iStartX,iStartY+g_MHTga[iGDBoardIndex].height*fScaleB,0);
	gEngfuncs.pTriAPI->End();

	// Draw Number Left

	int iNumberX = iStartX + 33;
	int iNumberY = iStartY + 13;
	int iTemp = 0;
	fScale = 0.15f;

	gEngfuncs.pTriAPI->Color4ub(255, 255, 255, 255);
	DrawSelfNumbers(g_SBTopLeft, iNumberX, iNumberY, 1.0);

	/*if(g_SBTopLeft>99)
	{
		iTemp = (g_SBTopLeft % 1000)/100;
	}
	else iTemp = 0;

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Color4ub(255, 255, 255, 255);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();

	iNumberX += g_MHTga[iGDNumberIndex[iTemp]].width*fScale+2;

	if(g_SBTopLeft>9)
	{
		iTemp = (g_SBTopLeft % 100)/10;
	}
	else iTemp = 0;

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();
	iNumberX += g_MHTga[iGDNumberIndex[iTemp]].width*fScale+2;

	iTemp = (g_SBTopLeft % 10)/1;
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();*/

	// Draw Number Right

	iNumberX = iStartX + 178;
	iNumberY = iStartY + 13;
	iTemp = 0;

	gEngfuncs.pTriAPI->Color4ub(255, 255, 255, 255);
	DrawSelfNumbers(g_SBTopRight, iNumberX, iNumberY, 1.0);

	/*if(g_SBTopRight>99)
	{
		iTemp = (g_SBTopRight % 1000)/100;
	}
	else iTemp = 0;

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();

	iNumberX += g_MHTga[iGDNumberIndex[iTemp]].width*fScale+2;

	if(g_SBTopRight>9)
	{
		iTemp = (g_SBTopRight % 100)/10;
	}
	else iTemp = 0;

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();
	iNumberX += g_MHTga[iGDNumberIndex[iTemp]].width*fScale+2;

	iTemp = (g_SBTopRight % 10)/1;
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();*/

	// Draw Number Center

	iNumberX = iStartX + 112;
	iNumberY = iStartY + 27;
	iTemp = 0;
	fScale = 0.12f;

	gEngfuncs.pTriAPI->Color4ub(239, 222, 179, 255);
	DrawSelfNumbers(g_SBTopCenter, iNumberX, iNumberY, 0.85);


	/*if(g_SBTopCenter>99)
	{
		iTemp = (g_SBTopCenter % 1000)/100;
	}
	else iTemp = 0;

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Color4ub(239, 222, 179,255);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();

	iNumberX += g_MHTga[iGDNumberIndex[iTemp]].width*fScale+2;

	if(g_SBTopCenter>9)
	{
		iTemp = (g_SBTopCenter % 100)/10;
	}
	else iTemp = 0;

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();
	iNumberX += g_MHTga[iGDNumberIndex[iTemp]].width*fScale+2;

	iTemp = (g_SBTopCenter % 10)/1;
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iGDNumberIndex[iTemp]].texid);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY,0);	
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX+g_MHTga[iGDNumberIndex[iTemp]].width*fScale,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iNumberX,iNumberY+g_MHTga[iGDNumberIndex[iTemp]].height*fScale,0);
	gEngfuncs.pTriAPI->End();*/

	// Draw Player Level
	char p1[256];
	char *pP1 = p1;

	int kills = g_plrFrag[gEngfuncs.GetLocalPlayer()->index];
	int level = GetLevel(kills) + 1;

	if(level >17)
	{
		sprintf(p1,"Lv.Max");
		wchar_t pSet[128];
		Fonts_C2W(pSet,127,pP1);
		Fonts_SetSize(18,18);
		Fonts_SetColor(255,255,255,255);
		Fonts_Draw(pSet,iStartX + 111, iStartY + 78,1000,100);
	}
	else
	{
		sprintf(p1,"Lv.%d",level);
		wchar_t pSet[128];
		Fonts_C2W(pSet,127,pP1);
		Fonts_SetSize(18,18);
		Fonts_SetColor(255,255,255,255);

		if(level >= 10)
			Fonts_Draw(pSet,iStartX + 115, iStartY + 78,1000,100);
		else
			Fonts_Draw(pSet,iStartX + 119, iStartY + 78,1000,100);
	}
	

	// Draw Rank
	int iRankX = g_sScreenInfo.iWidth - 20;
	iRankX -= g_MHTga[iRank[0]].width;
	int iRankY = iStartY + 15;

	for(int k=0;k<3;k++)
	{
		Tri_Enable(GL_TEXTURE_2D);
		gEngfuncs.pTriAPI->Color4f(1,1,1,1);
		Tri_Enable(GL_BLEND);
		Tri_Enable(GL_ALPHA_TEST);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		Tri_AlphaFunc(GL_GREATER, 0.0);
		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[iRank[k]].texid);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iRankX,iRankY,0);

		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iRankX+g_MHTga[iRank[k]].width,iRankY,0);	
		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iRankX+g_MHTga[iRank[k]].width,iRankY+g_MHTga[iRank[k]].height,0);
	
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iRankX,iRankY+g_MHTga[iRank[k]].height,0);
		gEngfuncs.pTriAPI->End();

		Fonts_SetSize(14,14);

		if(g_plrRank[k] && g_plrFrag[g_plrRank[k]])
		{
			hud_player_info_t hPlayer;
			gEngfuncs.pfnGetPlayerInfo(g_plrRank[k],&hPlayer);

			int kills = g_plrFrag[g_plrRank[k]];
			int level = GetLevel(kills) + 1;

			if(level>17)
			{
				sprintf(p1,"Lv.Max %s",hPlayer.name);
			}
			else
			{
				sprintf(p1,"Lv.%d %s",level,hPlayer.name);
			}
			if(vPlayer[g_plrRank[k]].team == 1)
			{
				Fonts_SetColor(162,213,255,255);
			}
			else
			{
				Fonts_SetColor(255,50,50,255);
			}
			
			Fonts_Draw(UTF8ToUnicode(p1),iRankX + 63, iRankY+22,1000,100);
		}
		iRankY += g_MHTga[iRank[0]].height + 3;
		g_iGD_Y = iRankY;
	}
}

int GetLevel(int kills)
{
	for(int i=17;i>=0;i--)
	{
		if(kills >= KILL_AIM[i])
			return i;
	}
	return 0;
}

void DrawSelfNumbers(int n, int x, int y, float size)
{
	int width = 18 + 4;
	width *= size;

	int k;

	k = (n % 1000) / 100;
	g_ZBSboard.DrawSelfNumber(k, x, y, size);
	x += width;

	k = (n % 100) / 10;
	g_ZBSboard.DrawSelfNumber(k, x, y, size);
	x += width;

	k = n % 10;
	g_ZBSboard.DrawSelfNumber(k, x, y, size);
	x += width;
}
