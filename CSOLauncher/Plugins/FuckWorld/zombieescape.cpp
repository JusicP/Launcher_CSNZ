#include "base.h"
int g_ze_hm,g_ze_zb,g_ze_flag,g_ze_me,g_ze_bar;

float g_iZeCheck=0;
float g_ZePoint[20][3];
int g_player_lastcount[33];
int m_point[20][3];
void ResetZe(void)
{
	memset(g_player_lastcount,0,sizeof(g_player_lastcount));
	memset(m_point,0,sizeof(m_point));
	g_iZeCheck = 0;
}
int LoadZePoint(char *pName)
{
	char szFile[128];
	sprintf(szFile,"metahook\\zepoint\\%s.point",pName);
	
	FILE* pTgaList;
	static char szBuff[512];
	szBuff[0] = '\0';
	pTgaList = fopen(szFile, "rt");
	if(pTgaList == NULL)									
	{
		LogToFile( "Open Ze Point Failed[FileName:%s]",szFile);
		return 0;
	}
	int id = 0;

	while(!feof(pTgaList))
	{
		fgets(szBuff,sizeof(szBuff)-1,pTgaList);
		if(szBuff[strlen(szBuff)-1] =='\n') szBuff[strlen(szBuff)-1] = '\0';

		if(szBuff[0]==';'||!szBuff[0]) continue;

		static char szToken[1024];

		char *pText = gEngfuncs.COM_ParseFile(szBuff,szToken);
		g_ZePoint[id][0] = (float)atof(szToken);
		char *pText2 = gEngfuncs.COM_ParseFile(pText,szToken);
		g_ZePoint[id][1] = (float)atof(szToken);
		char *pText3 = gEngfuncs.COM_ParseFile(pText2,szToken);
		g_ZePoint[id][2] = (float)atof(szToken);
		id++;
	}
	fclose(pTgaList);
	return 1;
}
void ZombieEscapeRedraw()
{
	// Check Mod
	if(g_iMod != 10) return;

	// First Make Start Pos
	int iX,iY;
	iY = 100;
	iX = (g_sScreenInfo.iWidth - g_Texture[g_ze_bar].iWidth)/2;

	// Draw Bar & Flag
	MH_DrawTGAFunction(g_Texture[g_ze_bar].iTexture,255,255,255,255,iX,iY,1);
	
	/*Tri_Enable(GL_TEXTURE_2D);
	Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_ze_bar].texid);
	gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[g_ze_bar].height,0);

	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iX ,iY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_ze_bar].width,iY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_ze_bar].width,g_MHTga[g_ze_bar].height+iY,0);
		
	gEngfuncs.pTriAPI->End();*/

	int iTempX = iX;
	int iTempY = iY;
	iTempX = iX + g_Texture[g_ze_bar].iWidth - 53;
	iTempY -=26 ;
	

	MH_DrawTGAFunction(g_Texture[g_ze_flag].iTexture,255,255,255,255,iTempX,iTempY,1);
	/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_ze_flag].texid);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
	gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
	gEngfuncs.pTriAPI->TexCoord2f(0,1);
	gEngfuncs.pTriAPI->Vertex3f(iTempX,iTempY+g_MHTga[g_ze_flag].height,0);

	gEngfuncs.pTriAPI->TexCoord2f(0,0);
	gEngfuncs.pTriAPI->Vertex3f(iTempX ,iTempY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,0);
	gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_flag].width,iTempY,0);

	gEngfuncs.pTriAPI->TexCoord2f(1,1);
	gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_flag].width,g_MHTga[g_ze_flag].height+iTempY,0);*/
		
	gEngfuncs.pTriAPI->End();

	static int m_point[20][3];
	static float fNearst = 9999.0f;
	static int iLocalPos;
	int iIndex = gEngfuncs.GetLocalPlayer()->index;
	

	if(g_iZeCheck < g_flTime)
	{
		memset(m_point,0,sizeof(m_point));
		g_iZeCheck = g_flTime + 0.1f;
		//
		for ( int i = 1; i < MAX_PLAYERS; i++ )
		{
			gEngfuncs.pfnGetPlayerInfo( i, &g_PlayerInfoList[i] );
		
			if(g_PlayerInfoList[i].name == NULL) 
			{
				iValidPlayer[i] = 0;
				g_PlayerExtraInfo[i].frags = 0;
				continue;
			}
			iValidPlayer[i] = 1;
		}
		// Make Info
		for(int i =1;i<33;i++)
		{
			fNearst = 9999.0f;
			if(iValidPlayer[i] && !(g_PlayerExtraInfo[i].iFlag & SCOREATTRIB_DEAD))
			{

				static Vector vOrigin;
				int iPoint;
				vOrigin = gEngfuncs.GetEntityByIndex(i)->origin;

				for(int k = 0;k<20;k++)
				{
					static Vector iTemp2;
					iTemp2[0] = vOrigin[0] - g_ZePoint[k][0];
					iTemp2[1] = vOrigin[1] - g_ZePoint[k][1];
					iTemp2[2] = vOrigin[2] - g_ZePoint[k][2];
					float fDis = iTemp2.Length();
					if(fDis < fNearst)
					{
						fNearst = fDis;
						iPoint = k;
					}
				}
				if( (g_player_lastcount[i]-iPoint)>1 || (g_player_lastcount[i]-iPoint)<-1)
				{
					iPoint = g_player_lastcount[i];
				}
				else g_player_lastcount[i] = iPoint;
				// Check Team
				if(vPlayer[i].team == 1)
				{
					m_point[iPoint][1]++;
				}
				else if(vPlayer[i].team == 2)
				{
					m_point[iPoint][2]++;
				}
				if(iIndex == i) iLocalPos = iPoint;
			}
		}
	}

	for(int j =0 ;j<20;j++)
	{
		if(m_point[j][1])
		{
			// Human
			iTempX = iX + 53;
			iTempY = iY - 18 ;

			iTempX = iTempX + 21 * j;

			MH_DrawTGAFunction(g_Texture[g_ze_hm].iTexture,255,255,255,255,iTempX,iTempY,1);
			
			/*gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
			Tri_Enable(GL_BLEND);
			Tri_Enable(GL_ALPHA_TEST);
			Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
			Tri_AlphaFunc(GL_GREATER, 0.0);
			
			Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_ze_hm].texid);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iTempX,iTempY+g_MHTga[g_ze_hm].height,0);
	
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iTempX ,iTempY,0);

			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_hm].width,iTempY,0);

			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_hm].width,g_MHTga[g_ze_hm].height+iTempY,0);
		
			gEngfuncs.pTriAPI->End();
			gEngfuncs.pfnDrawSetTextColor(1.0f,1.0f,1.0f);*/
			char p[3];
			sprintf(p,"%d",m_point[j][1]);
			iTempX += 16;
			iTempY += 24;

			if(m_point[j][1]>9)
			{
				iTempX -= 3;
			}
			Fonts_SetColor(255,255,255,255);
			Fonts_SetSize(14,14);
			Fonts_Draw(UTF8ToUnicode(p),iTempX, iTempY,100,100);
		}
		if(m_point[j][2])
		{
			// Zombie
			iTempX = iX + 53;
			iTempY = 20 +iY ;

			iTempX = iTempX + 21 * j;

			MH_DrawTGAFunction(g_Texture[g_ze_zb].iTexture,255,255,255,255,iTempX,iTempY,1);
			/*Tri_Enable(GL_TEXTURE_2D);
			Tri_Enable(GL_BLEND);
			Tri_Enable(GL_ALPHA_TEST);
			Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
			Tri_AlphaFunc(GL_GREATER, 0.0);
			
			Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_ze_zb].texid);
			gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iTempX,iTempY+g_MHTga[g_ze_zb].height,0);
	
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iTempX ,iTempY,0);

			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_zb].width,iTempY,0);

			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_zb].width,g_MHTga[g_ze_zb].height+iTempY,0);
		
			gEngfuncs.pTriAPI->End();*/
			char p[3];
			sprintf(p,"%d",m_point[j][2]);
			iTempX += 16;
			iTempY += 24;

			if(m_point[j][2]>9)
			{
				iTempX -= 3;
			}
			Fonts_SetColor(255,255,255,255);
			Fonts_SetSize(14,14);
			Fonts_Draw(UTF8ToUnicode(p),iTempX, iTempY,100,100);
		}
	}
	// Draw Me
	
	if(iValidPlayer[iIndex] && !(g_PlayerExtraInfo[iIndex].iFlag & SCOREATTRIB_DEAD) && vPlayer[iIndex].team == 2)
	{
		iTempX = iX + 53;
		iTempY = 20 +iY ;
		iTempX = iTempX + 21 * iLocalPos;


		MH_DrawTGAFunction(g_Texture[g_ze_me].iTexture,255,255,255,255,iTempX,iTempY,1);
		/*Tri_Enable(GL_TEXTURE_2D);
		Tri_Enable(GL_BLEND);
		Tri_Enable(GL_ALPHA_TEST);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		Tri_AlphaFunc(GL_GREATER, 0.0);

		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_ze_me].texid);
		gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iTempX,iTempY+g_MHTga[g_ze_me].height,0);
	
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iTempX ,iTempY,0);

		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_me].width,iTempY,0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_me].width,g_MHTga[g_ze_me].height+iTempY,0);
		
		gEngfuncs.pTriAPI->End();*/
	}
	if(iValidPlayer[iIndex] && !(g_PlayerExtraInfo[iIndex].iFlag & SCOREATTRIB_DEAD) && vPlayer[iIndex].team == 1)
	{
		iTempX = iX + 53;
		iTempY = iY - 18 ;

		iTempX = iTempX + 21 * iLocalPos;

		MH_DrawTGAFunction(g_Texture[g_ze_me].iTexture,255,255,255,255,iTempX,iTempY,1);
		/*Tri_Enable(GL_TEXTURE_2D);
		Tri_Enable(GL_BLEND);
		Tri_Enable(GL_ALPHA_TEST);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
		Tri_AlphaFunc(GL_GREATER, 0.0);
		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_ze_me].texid);
		gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iTempX,iTempY+g_MHTga[g_ze_me].height,0);
	
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iTempX ,iTempY,0);

		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_me].width,iTempY,0);

		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iTempX+g_MHTga[g_ze_me].width,g_MHTga[g_ze_me].height+iTempY,0);
		
		gEngfuncs.pTriAPI->End();
		glDisable(GL_BLEND);
		glDisable(GL_ALPHA_TEST);*/
	}
	return;
}