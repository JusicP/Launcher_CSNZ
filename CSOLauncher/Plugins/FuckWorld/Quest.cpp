#include "base.h"

int iQ_Bg,iQ_Npc,iQ_Complete;
int g_iQuestStartPos = 0;
int g_iQuestDraw = 0;
char g_szQuestNpcName[32];
char g_szQuestMission[32];
void QuestInit(void)
{
	iQ_Bg = FindTexture("resource\\hud\\quest\\quest_bg");
	iQ_Npc = FindTexture("resource\\hud\\quest\\quest_npc1");
	iQ_Complete = FindTexture("resource\\hud\\quest\\quest_complete");
}
void QuestAdd(char *pNpcName,char *pNpcPic,char *pMission)
{
	g_iQuestStartPos = 0- g_Texture[iQ_Bg].iWidth - 5;
	g_iQuestDraw = 1;
	memset(g_szQuestNpcName,0,sizeof(g_szQuestNpcName));
	memset(g_szQuestMission,0,sizeof(g_szQuestMission));
	sprintf(g_szQuestNpcName,"%s",pNpcName);
	sprintf(g_szQuestMission,"%s",pMission);
	iQ_Npc = FindTexture(pNpcPic);
}
void QuestRedraw(void)
{
	if(!g_iQuestDraw) return;
	Fonts_SetSize(16,16);
	
	static int iX,iY,iAlpha;
	iX = g_iQuestStartPos;
	iY = g_sScreenInfo.iHeight * 0.75 - g_Texture[iQ_Bg].iHeight*0.75;
	iAlpha = 255;
	if(g_iQuestStartPos > 500)
	{
		if(g_iQuestStartPos < 755)
		{
			int iDec = g_iQuestStartPos - 500;
			iY += iDec;
			iAlpha = 255 - iDec;
		}
		else 
		{
			g_iQuestDraw = 0;
			return;
		}
	}
	if(iX > 16) iX = 16;
	//iX = 15;
	Fonts_SetColor(255,255,255,iAlpha);
	MH_DrawTGAFunction(g_Texture[iQ_Bg].iTexture,255,255,255,iAlpha,iX,iY,1.0);
	iY = iY + g_Texture[iQ_Bg].iHeight - g_Texture[iQ_Npc].iHeight;
	MH_DrawTGAFunction(g_Texture[iQ_Npc].iTexture,255,255,255,iAlpha,iX,iY,1.0);
	int iY2 =  iY + g_Texture[iQ_Npc].iHeight - 5;
	Fonts_Draw(GetLangUni(g_szQuestNpcName),iX+3,iY2,1500,100);
	Fonts_Draw(GetLangUni(g_szQuestMission),iX+140,iY2-65,1000,100);
	MH_DrawTGAFunction(g_Texture[iQ_Complete].iTexture,255,255,255,iAlpha,g_Texture[iQ_Bg].iWidth + iX - 20 - g_Texture[iQ_Complete].iWidth,iY + 80,1.0);
	g_iQuestStartPos += 3;
}