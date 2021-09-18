#include "base.h"

int DeathRun_iTga_Rank[3];
int DeathRun_iTga_MedalRank[3];
int DeathRun_iTga_Board;
int DeathRun_iTga_Num;
int DeathRun_iTga_Col;
float DeathRun_fStartTime = 0;
int DeathRun_iNumWidth;
int DeathRun_iStop = 1;
int DeathRun_iReset = 0;
float DeathRun_Delta;
int DeathRun_iSeconds;
int DeathRun_iMinutes;
int DeathRun_MilSec;
int DeathRun_iRecord[3];
int DeathRun_iDRID[3];
int DeathRun_iDRTime[3][3];
char DeathRun_sDRName[3][32];
char DeathRun_sDRTime[3][32];

void DeathRun_InitData(void)
{
	memset(DeathRun_iDRID,0,sizeof(DeathRun_iDRID));
	DeathRun_iStop = 1;
	DeathRun_iReset = 0;
	DeathRun_iRecord[0] = DeathRun_iRecord[1] = DeathRun_iRecord[2] = 0;
}
void DeathRunReset(void)
{
	DeathRun_iReset = 1;
	DeathRun_iStop = 0;
}
void DeathRun_ParseMsg(void)
{
	int iRank = READ_BYTE();
	int ID = READ_BYTE();
	iRank --;
	sprintf(DeathRun_sDRTime[iRank],"%s",READ_STRING());
	DeathRun_iDRID[iRank] = ID;

	if(!ID)
	{
		DeathRun_iDRID[iRank] = 0;
	}
	else
	{
		
		hud_player_info_t hInfo;
		gEngfuncs.pfnGetPlayerInfo(ID,&hInfo);
		memset(DeathRun_sDRName[iRank],0,sizeof(DeathRun_sDRName[iRank]));
		sprintf(DeathRun_sDRName[iRank],"%s",hInfo.name);
	}
	return;
}
void DeathRunStop(void)
{
	DeathRun_iStop = 1;
	DeathRun_iReset = 0;
	DeathRun_iRecord[0] = DeathRun_iSeconds;
	DeathRun_iRecord[1] = DeathRun_iMinutes;
	DeathRun_iRecord[2] = DeathRun_MilSec;
}
void DeathRunStart(void)
{
	DeathRun_iStop = 0;
	DeathRun_iReset = 0;
	DeathRun_fStartTime = g_flTime;
}
void DeathRunInit(void)
{
	DeathRun_iTga_Rank[0] = FindTexture("resource\\hud\\challenge\\1st");
	DeathRun_iTga_Rank[1] = FindTexture("resource\\hud\\challenge\\2nd");
	DeathRun_iTga_Rank[2] = FindTexture("resource\\hud\\challenge\\3rd");

	DeathRun_iTga_MedalRank[0] = FindTexture("resource\\hud\\challenge\\medal_1st");
	DeathRun_iTga_MedalRank[1] = FindTexture("resource\\hud\\challenge\\medal_2nd");
	DeathRun_iTga_MedalRank[2] = FindTexture("resource\\hud\\challenge\\medal_3rd");

	DeathRun_iTga_Board = FindTexture("resource\\hud\\challenge\\timeboard");
	DeathRun_iTga_Num = DrawTgaGetID("mode\\dr\\timenumber");
	DeathRun_iTga_Col = FindTexture("resource\\hud\\challenge\\timecolon");
		
	DeathRun_iNumWidth = g_MHTga[DeathRun_iTga_Num].width / 10;
}

void DeathRunRedraw(void)
{
	if(g_iMod !=MOD_DR) return;
	// Draw Board
	int iX = (g_sScreenInfo.iWidth - g_Texture[DeathRun_iTga_Board].iWidth)/2;
	MH_DrawTGAFunction(g_Texture[DeathRun_iTga_Board].iTexture,255,255,255,255,iX,10,1);

	// Draw Time
	if(DeathRun_iReset)
	{
		DeathRun_iSeconds = DeathRun_iMinutes = DeathRun_MilSec = 0;
	}
	else if(DeathRun_iStop)
	{
		DeathRun_iSeconds = DeathRun_iRecord[0];
		DeathRun_iMinutes = DeathRun_iRecord[1];
		DeathRun_MilSec = DeathRun_iRecord[2];
	}
	else
	{
		DeathRun_Delta = g_flTime - DeathRun_fStartTime;
		if(DeathRun_Delta<0)
		{
			DeathRun_iSeconds = DeathRun_iMinutes = DeathRun_MilSec = 0;
		}
		else
		{
			DeathRun_iSeconds = unsigned(DeathRun_Delta);
			DeathRun_iMinutes = DeathRun_iSeconds / 60;
			DeathRun_iSeconds = DeathRun_iSeconds - 60*DeathRun_iMinutes;
			DeathRun_MilSec = int((g_flTime - int(g_flTime)) * 100);
		}
	}
	int iStartX,iStartY;
	iStartX = iX+6;
	iStartY = 5;
	// Draw Minues
	DeathRunDrawNumber(iStartX+10,iStartY+10,DeathRun_iMinutes);
	MH_DrawTGAFunction(g_Texture[DeathRun_iTga_Col].iTexture,255,255,255,255,iStartX+10+2*DeathRun_iNumWidth-2,iStartY+20,1);
	MH_DrawTGAFunction(g_Texture[DeathRun_iTga_Col].iTexture,255,255,255,255,iStartX+10+4*DeathRun_iNumWidth+2,iStartY+20,1);

	DeathRunDrawNumber(iStartX+10+2*DeathRun_iNumWidth+4,iStartY+10,DeathRun_iSeconds);
	DeathRunDrawNumber(iStartX+10+4*DeathRun_iNumWidth+8,iStartY+10,DeathRun_MilSec);

	// Draw Rank
	iStartX = g_sScreenInfo.iWidth - g_Texture[DeathRun_iTga_MedalRank[0]].iWidth;
	iStartY = g_sScreenInfo.iHeight*0.3f;
	MH_DrawTGAFunction(g_Texture[DeathRun_iTga_MedalRank[0]].iTexture,255,255,255,255,iStartX,iStartY,1);
	iStartY += g_Texture[DeathRun_iTga_MedalRank[0]].iHeight+20;
	MH_DrawTGAFunction(g_Texture[DeathRun_iTga_MedalRank[1]].iTexture,255,255,255,255,iStartX,iStartY,1);
	iStartY += g_Texture[DeathRun_iTga_MedalRank[0]].iHeight+20;
	MH_DrawTGAFunction(g_Texture[DeathRun_iTga_MedalRank[2]].iTexture,255,255,255,255,iStartX,iStartY,1);

	//RANK1
	Fonts_SetSize(18,18);
	Fonts_SetColor(255,255,255,255);
	iStartX = g_sScreenInfo.iWidth - g_Texture[DeathRun_iTga_MedalRank[0]].iWidth;
	iStartY = g_sScreenInfo.iHeight*0.3f;
	iStartY += 28;
	for(int i=0;i<3;i++)
	{
		if(DeathRun_iDRID[i])
		{
			Fonts_Draw(UTF8ToUnicode(DeathRun_sDRName[i]),iStartX+70,iStartY,1000,1000);
			Fonts_Draw(UTF8ToUnicode(DeathRun_sDRTime[i]),iStartX+70,iStartY+26,1000,1000);
			iStartY += (g_Texture[DeathRun_iTga_MedalRank[0]].iHeight+20);
		}
	}
	//


}
void DeathRunDrawNumber(int x,int y,int Num)
{
	int iNum_10 = Num / 10;
	float fRect = float(iNum_10) / 10.0f;
	int iX = x;
	int iY = y;
	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	

	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathRun_iTga_Num].texid);


	gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);	
	gEngfuncs.pTriAPI->TexCoord2f(fRect,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[DeathRun_iTga_Num].height,0);

	gEngfuncs.pTriAPI->TexCoord2f(fRect+0.1f,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[DeathRun_iTga_Num].width*0.1f,iY+g_MHTga[DeathRun_iTga_Num].height,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(fRect+0.1f,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[DeathRun_iTga_Num].width*0.1f,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(fRect,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();

	iX += DeathRun_iNumWidth;
	int iNum_1 = Num - 10*iNum_10;
	fRect = float(iNum_1) / 10.0f;
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
		
	gEngfuncs.pTriAPI->TexCoord2f(fRect,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[DeathRun_iTga_Num].height,0);

	gEngfuncs.pTriAPI->TexCoord2f(fRect+0.1f,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[DeathRun_iTga_Num].width*0.1f,iY+g_MHTga[DeathRun_iTga_Num].height,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(fRect+0.1f,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[DeathRun_iTga_Num].width*0.1f,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(fRect,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();
}