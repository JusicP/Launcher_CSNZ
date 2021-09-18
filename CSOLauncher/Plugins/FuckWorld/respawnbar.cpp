#include "base.h"
int g_iRespawnBar;
float g_iRespawnTime;
float g_iRTStart;

int g_iRSBarIndex;
int g_iRSBgIndex;

void DrawRespawnBar()
{
	if(!g_iRespawnBar) return;
	if(g_iRespawnTime<=g_flTime) return;

	//Calculate Position Wide=432,High=72
	int iStartX,iStartY;
	iStartX = (int)(g_sScreenInfo.iWidth - 432)*0.5;
	iStartY = (int)g_sScreenInfo.iHeight*0.7;

	MH_DrawTGAFunction(g_Texture[g_iRSBgIndex].iTexture,255,255,255,255,iStartX,iStartY,1);
	//Draw bg
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_iRSBgIndex].texid);
	gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iStartX,iStartY+g_MHTga[g_iRSBgIndex].height,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iStartX+g_MHTga[g_iRSBgIndex].width,iStartY+g_MHTga[g_iRSBgIndex].height,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iStartX+g_MHTga[g_iRSBgIndex].width,iStartY,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iStartX,iStartY,0);
	gEngfuncs.pTriAPI->End();*/
	//Draw Bar 419,9
	HSPRITE hBar;
	hBar =  GetSprite(g_iRSBarIndex);
	gEngfuncs.pfnSPR_Set(hBar, 255, 255, 255);
	//Calc Width
	wrect_t wrecSpr = GetSpriteRect(g_iRSBarIndex);
	wrecSpr.right = (int)419*(g_flTime-g_iRTStart)/(g_iRespawnTime-g_iRTStart);
	iStartX+=8;
	iStartY+=24;
	gEngfuncs.pfnSPR_Draw(0, iStartX,iStartY, &wrecSpr);

}
