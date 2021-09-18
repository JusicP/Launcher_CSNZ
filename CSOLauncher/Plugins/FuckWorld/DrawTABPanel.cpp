#include "base.h"

int g_iPanelIndex;
int g_iPanelCanDraw = 0;
team_info_t g_TeamInfo[MAX_PLAYERS];
hud_player_info_t	 g_PlayerInfoList[MAX_PLAYERS+1];
int g_PingOffset = 0;
#define BORDER_X	10
#define BORDER_Y	40

struct vRankInfo
{
	int iFrag;
	int iId;
};

vRankInfo vAfterSort[33];

int iValidPlayer[33];

float fUpdateTime = 0;

void TAB_Panel_Init(void)
{
	memset(iValidPlayer,0,sizeof(iValidPlayer));
	memset(g_TeamInfo,0,sizeof(team_info_t));
	memset(g_PlayerInfoList,0,sizeof(hud_player_info_t));
	memset(g_PlayerExtraInfo,0,sizeof(extra_player_info_t));
	//TAB_Panel_SortAllPlayer();
	g_iPanelCanDraw = 0;
	fUpdateTime = 0;
}

void TAB_Panel_SortAllPlayer(void)
{
	TAB_Panel_GetAllPlayersInfo();
	for(int i=1;i<33;i++)
	{
		vAfterSort[i].iFrag = g_PlayerExtraInfo[i].frags;
		vAfterSort[i].iId = i;
	}

	vRankInfo vTemp;
	int  i,j,n=33;
	for(i=1;i<n-1;i++) 
	{
		for(j=i+1;j<n;j++)
		{
			if(vAfterSort[i].iFrag<vAfterSort[j].iFrag || !iValidPlayer[i])
			{
				vTemp=vAfterSort[i]; 
				vAfterSort[i]=vAfterSort[j]; 
				vAfterSort[j]=vTemp; 
			}
		}
	}
}

void TAB_Panel_Redraw(void)
{
	if(fUpdateTime < g_flTime)
	{
		TAB_Panel_SortAllPlayer();
		fUpdateTime = g_flTime + 0.5f;
	}
	if(!g_iPanelCanDraw) return;
	if(g_iMod == MOD_NONE || g_iMod == MOD_GD || g_iMod == MOD_FUNMODE || g_iMod == MOD_TDM || g_iMod == MOD_SD || g_iMod == MOD_BC || g_iMod == MOD_DR || g_iMod == MOD_DM)
	{
		DrawNormalPanel();
	}
	else if(g_iMod == MOD_ZB || g_iMod == MOD_ZB3 || g_iMod == MOD_ZE)
	{
		DrawZBPanel();
	}
	else if(g_iMod == MOD_ZBS)
	{
		DrawZBSPanel();
	}
	else if(g_iMod == MOD_ZB4)
	{
		DrawZB4Panel();
	}
	else if(g_iMod == MOD_HD)
	{
		DrawHDPanel();
	}
	return;
}
void DrawZB4Panel(void)
{
	// Draw Panel
	int iX = BORDER_X;
	int iY = BORDER_Y;
	int iW = g_sScreenInfo.iWidth - 2*BORDER_X;
	int iH = g_sScreenInfo.iHeight - 2*BORDER_Y;

	MH_DrawTGA_9(g_UI_Panel_Dark, iX, iY, iW, iH, 255);
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_iPanelIndex].texid);
	gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/

	// Get Center
	int iCenterX = g_sScreenInfo.iWidth / 2;

	// Draw Server Name
	Fonts_SetColor(255,255,255,255);
	Fonts_SetSize(18,18);
	int iTextLen;
	char pTitle[512];
	char pTemp[56];
	sprintf(pTemp,"CSBTE_MOD_%d",g_iMod);
	//sprintf(pTitle,"CS:BTE(%s / %s)",GetLangUtf(pTemp),GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	sprintf(pTitle,"CS:BTE(%s",GetLangUtf(pTemp));
	//sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	//sprintf(pTitle,"%s",pTitle);

	switch (g_iWeaponLimit)
	{
		case 0:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_NoLimit"));
			break;
		}
		case 1:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_SniperOnly"));
			break;
		}
		case 2:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_PistolOnly"));
			break;
		}
		case 3:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_GrenadeOnly"));
			break;
		}
		case 4:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_KnifelOnly"));
			break;
		}
	}

	wchar_t *pText = UTF8ToUnicode(pTitle);
	iTextLen = Fonts_GetLen(pText);
	Fonts_Draw(pText,iCenterX - iTextLen/2,iY+50,1000,1000);
	iY += 18;
	// Draw ClassRoom
	Fonts_SetColor(251,201,96,150);
	Fonts_SetSize(12,12);
	wchar_t *pText2 = GetLangUni("CSBTE_TABPANEL_ROOMINFO");
	iTextLen = Fonts_GetLen(pText2);
	iY += 12;
	Fonts_Draw(pText2,iCenterX - iTextLen/2,iY+50,1000,1000);
	// Title
	Fonts_SetColor(251,201,96,255);
	wchar_t *pText3 = GetLangUni("CSBTE_TabPanel_Title_Zb4");

	// for next
	int iInfoXCT,iInfoT;
	iY += 50;
	iY+= 20;
	iTextLen = Fonts_GetLen(pText3);
	Fonts_Draw(pText3,iCenterX - iTextLen-20,iY,1000,1000);
	iInfoXCT = iCenterX - iTextLen-20;
	Fonts_Draw(pText3,iW - iTextLen-20,iY,1000,1000);
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);

	// Draw TEAM
	int iTeamT=0;
	int iTeamCT=0;
	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[i])
		{
			if(vPlayer[i].team == 1) iTeamCT++;
			else if(vPlayer[i].team == 2) iTeamT++;
		}
	}
	char *pTemp2;
	char pTemp3[256];
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_HUMAN");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamCT);
	Fonts_SetSize(14,14);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iX+10,iY+20,1000,1000);
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_ZOMBIE");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamT);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iCenterX+5,iY+20,1000,1000);
	iY += 20;
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);
	iInfoT = iW - iTextLen-20;
	// Sort Players
	// Print Player

	//194 40 47 

	int iYCT = iY+20;
	int iYT = iY + 20;
	Fonts_SetSize(14,14);
	int iLocal =gEngfuncs.GetLocalPlayer()->index; 
	int iDrawRight = 0;

	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[vAfterSort[i].iId])
		{
			if(vPlayer[vAfterSort[i].iId].team)
			{
				//Name
				wchar_t pText4[256];
				char pChar[32];
				if(vAfterSort[i].iId == iLocal) Fonts_SetColor(255,255,255,255);
				else if(vPlayer[vAfterSort[i].iId].team==1) Fonts_SetColor(173,201,235,255);
				else if(vPlayer[vAfterSort[i].iId].team==2) Fonts_SetColor(216,81,80,255);


				Fonts_Draw(UTF8ToUnicode(g_PlayerInfoList[vAfterSort[i].iId].name),iX+10,iYCT,1000,1000);
					
				// ATTRIB
				if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_DEAD)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_DEAD"),iInfoXCT - 100,iYCT,1000,1000);
				}
				else if(vPlayer[vAfterSort[i].iId].team==2)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_ZOMBIE"),iInfoXCT - 100,iYCT,1000,1000);
				}
				else if(vPlayer[vAfterSort[i].iId].iHero==1)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HERO"),iInfoXCT - 100,iYCT,1000,1000);
				}

				// Frags					
				sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].frags);
				Fonts_C2W(pText4,255,pChar);
				Fonts_Draw(pText4,iInfoXCT,iYCT,1000,1000);

				// Deaths
				sprintf(pChar,"%dK",g_PlayerExtraInfo[vAfterSort[i].iId].deaths);
				Fonts_C2W(pText4,255,pChar);
				Fonts_Draw(pText4,iInfoXCT+50,iYCT,1000,1000);

				// Ping
				if(g_PlayerInfoList[vAfterSort[i].iId].ping == 0)
				{
					const char *isBotString = gEngfuncs.PlayerInfo_ValueForKey(vAfterSort[i].iId, "*bot");
					if (isBotString && atoi(isBotString) > 0)
					{
						Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOT"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
					}
					else Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HOST"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
				}
				else
				{
					sprintf(pChar,"%d",g_PlayerInfoList[vAfterSort[i].iId].ping);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
				}
			}
			iDrawRight = 1-iDrawRight;
			if(iDrawRight)
			{
				iX = iCenterX;
				iYCT = iYCT;
				iInfoXCT = iInfoT;
			}
			else
			{
				iYCT += 22;
				iX = BORDER_X ;
				iInfoXCT =  iCenterX - iTextLen-20;
			}
		}
	}
}
void DrawZBSPanel(void)
{
	// Draw Panel
	int iX = BORDER_X;
	int iY = BORDER_Y;
	int iW = g_sScreenInfo.iWidth - 2*BORDER_X;
	int iH = g_sScreenInfo.iHeight - 2*BORDER_Y;
	MH_DrawTGA_9(g_UI_Panel_Dark, iX, iY, iW, iH, 255);
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_iPanelIndex].texid);
	//gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/

	// Get Center
	int iCenterX = g_sScreenInfo.iWidth / 2;

	// Draw Server Name
	Fonts_SetColor(255,255,255,255);
	Fonts_SetSize(18,18);
	int iTextLen;
	char pTitle[512];
	char pTemp[56];
	sprintf(pTemp,"CSBTE_MOD_%d",g_iMod);
	//sprintf(pTitle,"CS:BTE(%s / %s)",GetLangUtf(pTemp),GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	sprintf(pTitle,"CS:BTE(%s",GetLangUtf(pTemp));
	//sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	//sprintf(pTitle,"%s",pTitle);

	switch (g_iWeaponLimit)
	{
		case 0:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_NoLimit"));
			break;
		}
		case 1:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_SniperOnly"));
			break;
		}
		case 2:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_PistolOnly"));
			break;
		}
		case 3:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_GrenadeOnly"));
			break;
		}
		case 4:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_KnifelOnly"));
			break;
		}
	}

	wchar_t *pText = UTF8ToUnicode(pTitle);
	iTextLen = Fonts_GetLen(pText);
	Fonts_Draw(pText,iCenterX - iTextLen/2,iY+50,1000,1000);
	iY += 18;
	// Draw ClassRoom
	Fonts_SetColor(251,201,96,150);
	Fonts_SetSize(12,12);
	wchar_t *pText2 = GetLangUni("CSBTE_Tabpanel_Roominfo");
	iTextLen = Fonts_GetLen(pText2);
	iY += 12;
	Fonts_Draw(pText2,iCenterX - iTextLen/2,iY+50,1000,1000);

	// 画上面
	char *pTemp2;
	char *pTemp3;

	iX += 45;
	iY += 60;
	gEngfuncs.pfnFillRGBA(iX,iY,iW * 0.6,1,251,201,96,180);
	iY += 30;
	gEngfuncs.pfnFillRGBA(iX,iY,iW * 0.6,1,251,201,96,255);

	iX += 45;
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_RANK");
	Fonts_SetSize(14,14);
	Fonts_SetColor(239,179,29,255);
	Fonts_Draw(UTF8ToUnicode(pTemp2),iX,iY-2,1000,1000);

	pTemp3 = GetLangUtf("CSBTE_TABPANEL_TITLE_ZBS");
	Fonts_Draw(UTF8ToUnicode(pTemp3),iCenterX-70,iY-2,1000,1000);
	

	// 准备玩家
	if(fUpdateTime < g_flTime)
	{
		TAB_Panel_SortAllPlayer();
		fUpdateTime = g_flTime + 0.5f;
	}

	// 画下面	
	int iLocal =gEngfuncs.GetLocalPlayer()->index; 

	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[vAfterSort[i].iId])
		{
			char pChar[32];
			wchar_t pText[256];
			iY += 20;

			// 颜色
			if(vPlayer[vAfterSort[i].iId].team==1) Fonts_SetColor(173,201,235,255);
			if(vAfterSort[i].iId == iLocal) Fonts_SetColor(255,255,255,255);			
			
			// 排名
			sprintf(pChar,"%d",i);
			Fonts_C2W(pText,255,pChar);			
			Fonts_Draw(pText,iX,iY,1000,1000);
			
			// 名字
			Fonts_Draw(UTF8ToUnicode(g_PlayerInfoList[vAfterSort[i].iId].name),iX+50,iY,1000,1000);
				
			// 血量
			if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_DEAD)
			{
				Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_DEAD"),iCenterX-67,iY,1000,1000);
			}
			else
			{				
				sprintf(pChar,"%d",g_iHealth);
				Fonts_C2W(pText,255,pChar);			
				Fonts_Draw(pText,iCenterX-67,iY,1000,1000);
			}

			// 杀敌					
			sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].frags);
			Fonts_C2W(pText,255,pChar);
			Fonts_Draw(pText,iCenterX-20,iY,1000,1000);
			
			// 延迟
			if(g_PlayerInfoList[vAfterSort[i].iId].ping == 0)
			{
				const char *isBotString = gEngfuncs.PlayerInfo_ValueForKey(vAfterSort[i].iId, "*bot");
				if (isBotString && atoi(isBotString) > 0)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOT"),iCenterX-g_PingOffset+60,iY,1000,1000);
				}
				else Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HOST"),iCenterX-g_PingOffset+60,iY,1000,1000);
			}
			else
			{
				sprintf(pChar,"%d",g_PlayerInfoList[vAfterSort[i].iId].ping);
				Fonts_C2W(pText,255,pChar);
				Fonts_Draw(pText,iCenterX-g_PingOffset+60,iY,1000,1000);
			}
		}
		
	}

	//+168
	// 画右边

	// 画更下面
	gEngfuncs.pfnFillRGBA(iX-5,iH*0.67,iW * 0.83,1,251,201,96,180);
}
/*cl_entity_t *GetPlayerByIndex(int index)
{
	for (int i = 1; i < 1024; i++) // 效率很低
	{
		cl_entity_t *ent = gEngfuncs.GetEntityByIndex(i);

		if (!ent)
			continue;

		if (ent->index == index)
			return ent;
	}

	return NULL;
}*/



void DrawZBPanel(void)
{
	// Draw Panel
	int iX = BORDER_X;
	int iY = BORDER_Y;
	int iW = g_sScreenInfo.iWidth - 2*BORDER_X;
	int iH = g_sScreenInfo.iHeight - 2*BORDER_Y;

	MH_DrawTGA_9(g_UI_Panel_Dark, iX, iY, iW, iH, 255);
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_iPanelIndex].texid);
	gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/

	// Get Center
	int iCenterX = g_sScreenInfo.iWidth / 2;

	// Draw Server Name
	Fonts_SetColor(255,255,255,255);
	Fonts_SetSize(18,18);
	int iTextLen;
	char pTitle[512];
	char pTemp[56];
	sprintf(pTemp,"CSBTE_MOD_%d",g_iMod);
	//sprintf(pTitle,"CS:BTE(%s / %s)",GetLangUtf(pTemp),GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	sprintf(pTitle,"CS:BTE(%s",GetLangUtf(pTemp));
	//sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	//sprintf(pTitle,"%s",pTitle);

	switch (g_iWeaponLimit)
	{
		case 0:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_NoLimit"));
			break;
		}
		case 1:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_SniperOnly"));
			break;
		}
		case 2:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_PistolOnly"));
			break;
		}
		case 3:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_GrenadeOnly"));
			break;
		}
		case 4:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_KnifelOnly"));
			break;
		}
	}

	wchar_t *pText = UTF8ToUnicode(pTitle);
	iTextLen = Fonts_GetLen(pText);
	Fonts_Draw(pText,iCenterX - iTextLen/2,iY+50,1000,1000);
	iY += 18;
	// Draw ClassRoom
	Fonts_SetColor(251,201,96,150);
	Fonts_SetSize(12,12);
	wchar_t *pText2 = GetLangUni("CSBTE_TABPANEL_ROOMINFO");
	iTextLen = Fonts_GetLen(pText2);
	iY += 12;
	Fonts_Draw(pText2,iCenterX - iTextLen/2,iY+50,1000,1000);
	// Title
	Fonts_SetColor(251,201,96,255);
	wchar_t *pText3 = GetLangUni("CSBTE_TABPANEL_TITLE");

	// for next
	int iInfoXCT,iInfoT;
	iY += 50;
	iY+= 20;
	iTextLen = Fonts_GetLen(pText3);
	Fonts_Draw(pText3,iCenterX - iTextLen-20,iY,1000,1000);
	iInfoXCT = iCenterX - iTextLen-20;
	Fonts_Draw(pText3,iW - iTextLen-20,iY,1000,1000);
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);

	// Draw TEAM
	int iTeamT=0;
	int iTeamCT=0;
	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[i])
		{
			if(vPlayer[i].team == 1) iTeamCT++;
			else if(vPlayer[i].team == 2) iTeamT++;
		}
	}
	char *pTemp2;
	char pTemp3[256];
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_HUMAN");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamCT);
	Fonts_SetSize(14,14);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iX+10,iY+20,1000,1000);
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_ZOMBIE");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamT);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iCenterX+5,iY+20,1000,1000);
	iY += 20;
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);
	iInfoT = iW - iTextLen-20;
	// Sort Players
	if(fUpdateTime < g_flTime)
	{
		TAB_Panel_SortAllPlayer();
		fUpdateTime = g_flTime + 0.5f;
	}
	// Print Player

	//194 40 47 

	int iYCT = iY+20;
	int iYT = iY + 20;
	Fonts_SetSize(14,14);
	int iLocal =gEngfuncs.GetLocalPlayer()->index; 
	int iDrawRight = 0;

	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[vAfterSort[i].iId])
		{
			if(vPlayer[vAfterSort[i].iId].team)
			{
				//Name
				wchar_t pText4[256];
				char pChar[32];
				if(vAfterSort[i].iId == iLocal) Fonts_SetColor(255,255,255,255);
				else if(vPlayer[vAfterSort[i].iId].team==1) Fonts_SetColor(173,201,235,255);
				else if(vPlayer[vAfterSort[i].iId].team==2) Fonts_SetColor(216,81,80,255);


				Fonts_Draw(UTF8ToUnicode(g_PlayerInfoList[vAfterSort[i].iId].name),iX+10,iYCT,1000,1000);
					
				// ATTRIB
				if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_DEAD)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_DEAD"),iInfoXCT - 100,iYCT,1000,1000);
				}
				else if(vPlayer[vAfterSort[i].iId].team==2)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_ZOMBIE"),iInfoXCT - 100,iYCT,1000,1000);
				}
				else if(vPlayer[vAfterSort[i].iId].iHero==1)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HERO"),iInfoXCT - 100,iYCT,1000,1000);
				}

				// Frags					
				sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].frags);
				Fonts_C2W(pText4,255,pChar);
				Fonts_Draw(pText4,iInfoXCT,iYCT,1000,1000);

				// Deaths
				sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].deaths);
				Fonts_C2W(pText4,255,pChar);
				Fonts_Draw(pText4,iInfoXCT+50,iYCT,1000,1000);

				// Ping
				if(g_PlayerInfoList[vAfterSort[i].iId].ping == 0)
				{
					const char *isBotString = gEngfuncs.PlayerInfo_ValueForKey(vAfterSort[i].iId, "*bot");
					if (isBotString && atoi(isBotString) > 0)
					{
						Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOT"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
					}
					else Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HOST"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
				}
				else
				{
					sprintf(pChar,"%d",g_PlayerInfoList[vAfterSort[i].iId].ping);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
				}
			}
			iDrawRight = 1-iDrawRight;
			if(iDrawRight)
			{
				iX = iCenterX;
				iYCT = iYCT;
				iInfoXCT = iInfoT;
			}
			else
			{
				iYCT += 22;
				iX = BORDER_X ;
				iInfoXCT =  iCenterX - iTextLen-20;
			}
		}
	}
}
void DrawHDPanel(void)
{
	// Draw Panel
	int iX = BORDER_X;
	int iY = BORDER_Y;
	int iW = g_sScreenInfo.iWidth - 2*BORDER_X;
	int iH = g_sScreenInfo.iHeight - 2*BORDER_Y;

	MH_DrawTGA_9(g_UI_Panel_Dark, iX, iY, iW, iH, 255);
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_iPanelIndex].texid);
	gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/

	// Get Center
	int iCenterX = g_sScreenInfo.iWidth / 2;

	// Draw Server Name
	Fonts_SetColor(255,255,255,255);
	Fonts_SetSize(18,18);
	int iTextLen;
	char pTitle[512];
	char pTemp[56];
	sprintf(pTemp,"CSBTE_MOD_%d",g_iMod);
	//sprintf(pTitle,"CS:BTE(%s / %s)",GetLangUtf(pTemp),GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	sprintf(pTitle,"CS:BTE(%s",GetLangUtf(pTemp));
	//sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	//sprintf(pTitle,"%s",pTitle);

	switch (g_iWeaponLimit)
	{
		case 0:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_NoLimit"));
			break;
		}
		case 1:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_SniperOnly"));
			break;
		}
		case 2:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_PistolOnly"));
			break;
		}
		case 3:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_GrenadeOnly"));
			break;
		}
		case 4:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_KnifelOnly"));
			break;
		}
	}

	wchar_t *pText = UTF8ToUnicode(pTitle);
	iTextLen = Fonts_GetLen(pText);
	Fonts_Draw(pText,iCenterX - iTextLen/2,iY+50,1000,1000);
	iY += 18;
	// Draw ClassRoom
	Fonts_SetColor(251,201,96,150);
	Fonts_SetSize(12,12);
	wchar_t *pText2 = GetLangUni("CSBTE_TABPANEL_ROOMINFO");
	iTextLen = Fonts_GetLen(pText2);
	iY += 12;
	Fonts_Draw(pText2,iCenterX - iTextLen/2,iY+50,1000,1000);
	// Title
	Fonts_SetColor(251,201,96,255);
	wchar_t *pText3 = GetLangUni("CSBTE_TABPANEL_TITLE");

	// for next
	int iInfoXCT,iInfoT;
	iY += 50;
	iY+= 20;
	iTextLen = Fonts_GetLen(pText3);
	Fonts_Draw(pText3,iCenterX - iTextLen-20,iY,1000,1000);
	iInfoXCT = iCenterX - iTextLen-20;
	Fonts_Draw(pText3,iW - iTextLen-20,iY,1000,1000);
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);

	// Draw TEAM
	int iTeamT=0;
	int iTeamCT=0;
	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[i])
		{
			if(vPlayer[i].team == 1) iTeamCT++;
			else if(vPlayer[i].team == 2) iTeamT++;
		}
	}
	char *pTemp2;
	char pTemp3[256];
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_NOJOKER");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamCT);
	Fonts_SetSize(14,14);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iX+10,iY+20,1000,1000);
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_JOKER");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamT);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iCenterX+5,iY+20,1000,1000);
	iY += 20;
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);
	iInfoT = iW - iTextLen-20;
	// Sort Players
	if(fUpdateTime < g_flTime)
	{
		TAB_Panel_SortAllPlayer();
		fUpdateTime = g_flTime + 0.5f;
	}
	// Print Player

	//194 40 47 

	int iYCT = iY+20;
	int iYT = iY + 20;
	Fonts_SetSize(14,14);
	int iLocal =gEngfuncs.GetLocalPlayer()->index; 
	int iDrawRight = 0;

	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[vAfterSort[i].iId])
		{
			if(vPlayer[vAfterSort[i].iId].team)
			{
				//Name
				wchar_t pText4[256];
				char pChar[32];
				if(vAfterSort[i].iId == iLocal) Fonts_SetColor(255,255,255,255);
				else if(vPlayer[vAfterSort[i].iId].team==1) Fonts_SetColor(173,201,235,255);
				else if(vPlayer[vAfterSort[i].iId].team==2) Fonts_SetColor(216,81,80,255);


				Fonts_Draw(UTF8ToUnicode(g_PlayerInfoList[vAfterSort[i].iId].name),iX+10,iYCT,1000,1000);
					
				// ATTRIB
				if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_DEAD)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_DEAD"),iInfoXCT - 100,iYCT,1000,1000);
				}
				else if(vPlayer[vAfterSort[i].iId].team==2)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_JOKER"),iInfoXCT - 100,iYCT,1000,1000);
				}
				else if(vPlayer[vAfterSort[i].iId].iHero==1)
				{
					Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HERO"),iInfoXCT - 100,iYCT,1000,1000);
				}

				// Frags					
				sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].frags);
				Fonts_C2W(pText4,255,pChar);
				Fonts_Draw(pText4,iInfoXCT,iYCT,1000,1000);

				// Deaths
				sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].deaths);
				Fonts_C2W(pText4,255,pChar);
				Fonts_Draw(pText4,iInfoXCT+50,iYCT,1000,1000);

				// Ping
				if(g_PlayerInfoList[vAfterSort[i].iId].ping == 0)
				{
					const char *isBotString = gEngfuncs.PlayerInfo_ValueForKey(vAfterSort[i].iId, "*bot");
					if (isBotString && atoi(isBotString) > 0)
					{
						Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOT"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
					}
					else Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HOST"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
				}
				else
				{
					sprintf(pChar,"%d",g_PlayerInfoList[vAfterSort[i].iId].ping);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
				}
			}
			iDrawRight = 1-iDrawRight;
			if(iDrawRight)
			{
				iX = iCenterX;
				iYCT = iYCT;
				iInfoXCT = iInfoT;
			}
			else
			{
				iYCT += 22;
				iX = BORDER_X ;
				iInfoXCT =  iCenterX - iTextLen-20;
			}
		}
	}
}
void DrawNormalPanel(void)
{
	// Draw Panel
	int iX = BORDER_X;
	int iY = BORDER_Y;
	int iW = g_sScreenInfo.iWidth - 2*BORDER_X;
	int iH = g_sScreenInfo.iHeight - 2*BORDER_Y;

	MH_DrawTGA_9(g_UI_Panel_Dark, iX-3, iY, iW+4, iH, 255);

	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_iPanelIndex].texid);
	gEngfuncs.pTriAPI->Color4f(1,1,1,1);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+iH,0);
	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY+iH,0);
	
	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+iW,iY,0);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
	gEngfuncs.pTriAPI->End();*/

	// Get Center
	int iCenterX = g_sScreenInfo.iWidth / 2;

	// Draw Server Name
	Fonts_SetColor(255,255,255,255);
	Fonts_SetSize(18,18);
	int iTextLen;
	char pTitle[512];
	char pTemp[56];
	sprintf(pTemp,"CSBTE_MOD_%d",g_iMod);
	//sprintf(pTitle,"CS:BTE(%s / %s)",GetLangUtf(pTemp),GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	sprintf(pTitle,"CS:BTE(%s",GetLangUtf(pTemp));
	//sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_Tabpanel_Nolimit"));
	//sprintf(pTitle,"%s",pTitle);

	switch (g_iWeaponLimit)
	{
		case 0:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_NoLimit"));
			break;
		}
		case 1:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_SniperOnly"));
			break;
		}
		case 2:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_PistolOnly"));
			break;
		}
		case 3:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_GrenadeOnly"));
			break;
		}
		case 4:
		{
			sprintf(pTitle,"%s / %s)",pTitle,GetLangUtf("CSBTE_TabPanel_KnifelOnly"));
			break;
		}
	}


	wchar_t *pText = UTF8ToUnicode(pTitle);
	iTextLen = Fonts_GetLen(pText);
	Fonts_Draw(pText,iCenterX - iTextLen/2,iY+50,1000,1000);
	iY += 18;
	// Draw ClassRoom
	Fonts_SetColor(251,201,96,150);
	Fonts_SetSize(12,12);
	wchar_t *pText2 = GetLangUni("CSBTE_TABPANEL_ROOMINFO");
	iTextLen = Fonts_GetLen(pText2);
	iY += 12;
	Fonts_Draw(pText2,iCenterX - iTextLen/2,iY+50,1000,1000);
	// Title
	Fonts_SetColor(251,201,96,255);
	wchar_t *pText3 = GetLangUni("CSBTE_TABPANEL_TITLE");

	// for next
	int iInfoXCT,iInfoT;
	iY += 50;
	iY+= 20;
	iTextLen = Fonts_GetLen(pText3);
	Fonts_Draw(pText3,iCenterX - iTextLen-20,iY,1000,1000);
	iInfoXCT = iCenterX - iTextLen-20;
	Fonts_Draw(pText3,iW - iTextLen-20,iY,1000,1000);
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);

	// Draw TEAM
	int iTeamT=0;
	int iTeamCT=0;
	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[i])
		{
			if(vPlayer[i].team == 1) iTeamCT++;
			else if(vPlayer[i].team == 2) iTeamT++;
		}
	}
	char *pTemp2;
	char pTemp3[256];
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_CT");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamCT);
	Fonts_SetSize(14,14);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iX+10,iY+20,1000,1000);
	pTemp2 = GetLangUtf("CSBTE_TABPANEL_TEAM_T");
	sprintf(pTemp3,"%s(%d)",pTemp2,iTeamT);
	Fonts_Draw(UTF8ToUnicode(pTemp3),iCenterX+5,iY+20,1000,1000);
	iY += 20;
	gEngfuncs.pfnFillRGBA(iX+5,iY+2,iCenterX-iX-15,1,251,201,96,255);
	gEngfuncs.pfnFillRGBA(iCenterX+3,iY+2,iCenterX-iX-15,1,251,201,96,255);
	iInfoT = iW - iTextLen-20;
	// Sort Players
	if(fUpdateTime < g_flTime)
	{
		TAB_Panel_SortAllPlayer();
		fUpdateTime = g_flTime + 0.5f;
	}
	// Print Player

	//194 40 47 

	int iYCT = iY+20;
	int iYT = iY + 20;
	Fonts_SetSize(14,14);
	int iLocal =gEngfuncs.GetLocalPlayer()->index; 

	for(int i=1;i<33;i++)
	{
		if(iValidPlayer[vAfterSort[i].iId])
		{
			if(vPlayer[vAfterSort[i].iId].team)
			{
				if(vPlayer[vAfterSort[i].iId].team == 1)
				{
					//Name
					wchar_t pText4[256];
					char pChar[32];
					if(vAfterSort[i].iId == iLocal) Fonts_SetColor(255,255,255,255);
					else Fonts_SetColor(173,201,235,255);

					Fonts_Draw(UTF8ToUnicode(g_PlayerInfoList[vAfterSort[i].iId].name),iX+10,iYCT,1000,1000);
					
					// ATTRIB
					if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_DEAD)
					{
						Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_DEAD"),iInfoXCT - 100,iYCT,1000,1000);
					}

					// Frags					
					sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].frags);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoXCT,iYCT,1000,1000);

					// Deaths
					sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].deaths);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoXCT+50,iYCT,1000,1000);

					// Ping
					if(g_PlayerInfoList[vAfterSort[i].iId].ping == 0)
					{
						const char *isBotString = gEngfuncs.PlayerInfo_ValueForKey(vAfterSort[i].iId, "*bot");
						if (isBotString && atoi(isBotString) > 0)
						{
							Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOT"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
						}
						else Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HOST"),iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
						iYCT += 22;
					}
					else
					{
						sprintf(pChar,"%d",g_PlayerInfoList[vAfterSort[i].iId].ping);
						Fonts_C2W(pText4,255,pChar);
						Fonts_Draw(pText4,iInfoXCT+115-g_PingOffset,iYCT,1000,1000);
						iYCT += 22;
					}
					
				}
				else if(vPlayer[vAfterSort[i].iId].team == 2)
				{
					//Name
					wchar_t pText4[256];
					char pChar[32];
					if(vAfterSort[i].iId == iLocal) Fonts_SetColor(255,255,255,255);
					else Fonts_SetColor(216,81,80,255);
					Fonts_Draw(UTF8ToUnicode(g_PlayerInfoList[vAfterSort[i].iId].name),iCenterX+10,iYT,1000,1000);

					// ATTRIB
					if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_DEAD)
					{
						Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_DEAD"),iInfoT - 100,iYT,1000,1000);
					}
					else if(g_PlayerExtraInfo[vAfterSort[i].iId].iFlag & SCOREATTRIB_BOMB && vPlayer[iLocal].team == 2)
					{
						Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOMB"),iInfoT - 100,iYT,1000,1000);
					}
					// Frags					
					sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].frags);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoT,iYT,1000,1000);

					// Deaths
					sprintf(pChar,"%d",g_PlayerExtraInfo[vAfterSort[i].iId].deaths);
					Fonts_C2W(pText4,255,pChar);
					Fonts_Draw(pText4,iInfoT+50,iYT,1000,1000);

					// Ping
					if(g_PlayerInfoList[vAfterSort[i].iId].ping == 0)
					{
						const char *isBotString = gEngfuncs.PlayerInfo_ValueForKey(vAfterSort[i].iId, "*bot");
						if (isBotString && atoi(isBotString) > 0)
						{
							Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_BOT"),iInfoT+115-g_PingOffset,iYT,1000,1000);
						}
						else Fonts_Draw(GetLangUni("CSBTE_TABPANEL_ATTRIB_HOST"),iInfoT+115-g_PingOffset,iYT,1000,1000);
						iYT += 22;
					}
					else
					{
						sprintf(pChar,"%d",g_PlayerInfoList[vAfterSort[i].iId].ping);
						Fonts_C2W(pText4,255,pChar);
						Fonts_Draw(pText4,iInfoT+115-g_PingOffset,iYT,1000,1000);
						iYT += 22;
					}
				}
			}
		}
	}
}

void TAB_Panel_GetAllPlayersInfo( void )
{
	memset(vAfterSort,0,sizeof(vAfterSort));
	for ( int i = 1; i < MAX_PLAYERS; i++ )
	{
		gEngfuncs.pfnGetPlayerInfo( i, &g_PlayerInfoList[i] );

		cl_entity_t *ent = gEngfuncs.GetEntityByIndex(i);
		
		if(g_PlayerInfoList[i].name == NULL || !ent->index) 
		{
			iValidPlayer[i] = 0;
			g_PlayerExtraInfo[i].frags = 0;
			continue;
		}
		iValidPlayer[i] = 1;
	}
}

