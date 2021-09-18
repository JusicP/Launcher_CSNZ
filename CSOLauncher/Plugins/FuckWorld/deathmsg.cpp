#include "base.h"

DeathNoticeItem rgDeathNoticeList[ MAX_DEATHNOTICES + 1 ];
int DeathMsg_iDeathTga[2][3];
int DeathMsg_iKillCount;
float DeathMsg_fNextCountReset;
int DeathMsg_iTotalKills;


float DeathMsg_fCountResetTime[5] = {0.0, 3, 2.5, 1.7, 1.7};

int IsKnife(char *szWpnName)
{
	return (strstr(szWpnName,"axe") || strstr(szWpnName,"hdagger")||strstr(szWpnName,"combat")
		|| strstr(szWpnName,"hammer")||strstr(szWpnName,"katana")||strstr(szWpnName,"skullaxe")
		|| strstr(szWpnName,"d_knife") || strstr(szWpnName,"tomahawk") || strstr(szWpnName,"dragontail")
		|| strstr(szWpnName,"sword") || strstr(szWpnName,"d_zsh_"));
}



void DeathMsg_Init(void)
{
	// Killer
	DeathMsg_iKillCount = 0;
	DeathMsg_iTotalKills = 0;
	DeathMsg_iDeathTga[0][0] = FindTexture("resource\\hud\\deathnotice\\killbg_left");
	DeathMsg_iDeathTga[0][1] = FindTexture("resource\\hud\\deathnotice\\killbg_center");
	DeathMsg_iDeathTga[0][2] = FindTexture("resource\\hud\\deathnotice\\killbg_right");
	DeathMsg_iDeathTga[1][0] = FindTexture("resource\\hud\\deathnotice\\deathbg_left");
	DeathMsg_iDeathTga[1][1] = FindTexture("resource\\hud\\deathnotice\\deathbg_center");
	DeathMsg_iDeathTga[1][2] = FindTexture("resource\\hud\\deathnotice\\deathbg_right");
	memset(rgDeathNoticeList,0,sizeof(rgDeathNoticeList));
} 

inline int DrawConsoleString( int x, int y, const char *string )
{
	return gEngfuncs.pfnDrawConsoleString( x, y, (char*) string );
}

inline void GetConsoleStringSize( const char *string, int *width, int *height )
{
	gEngfuncs.pfnDrawConsoleStringLen( string, width, height );
}

inline int ConsoleStringLen( const char *string )
{
	int _width, _height;
	GetConsoleStringSize( string, &_width, &_height );
	return _width;
}

int GetClientColor( int clientIndex )
{
    int x = vPlayer[clientIndex].team;
	return vPlayer[clientIndex].team;
}
int MsgFunc_DeathMsg(const char *pszName, int iSize, void *pbuf)
{	
	BEGIN_READ(pbuf, iSize);
	int iKiller = READ_BYTE();
	int iVictim = READ_BYTE();
	int iHeadShot = READ_BYTE();
	char szWpnName[2048];
	sprintf(szWpnName, "d_%s",READ_STRING());

	if(iKiller && iVictim)
	{
		if(g_iMod == MOD_ZB || g_iMod == MOD_ZB3)
		{
			if(vPlayer[gEngfuncs.GetLocalPlayer()->index].team == 1 && vPlayer[iKiller].team == 2)
			{
				vPlayer[iVictim].fInfectTime = g_flTime + 3.0f;
				vPlayer[iVictim].vLastPos = gEngfuncs.GetEntityByIndex(iVictim)->origin;
			}
		}
		else if(vPlayer[gEngfuncs.GetLocalPlayer()->index].team == vPlayer[iVictim].team)
		{
			vPlayer[iVictim].fDeathTime = g_flTime + 3.0f;
			vPlayer[iVictim].killtime = g_flTime + 3.0f;
		}
	}
	int i = 0;
	for (i = 0; i < MAX_DEATHNOTICES; i++ )
	{
		if ( rgDeathNoticeList[i].iId == 0 )
			break;
	}
	if ( i == MAX_DEATHNOTICES )
	{
		memmove( rgDeathNoticeList, rgDeathNoticeList+1, sizeof(DeathNoticeItem) * MAX_DEATHNOTICES );
		i = MAX_DEATHNOTICES - 1;
	}

	hud_player_info_t hPlayer;
	gEngfuncs.pfnGetPlayerInfo(iKiller,&hPlayer);
	char *killer_name = hPlayer.name;
	if ( !killer_name )
	{
		killer_name = "";
		rgDeathNoticeList[i].szKiller[0] = 0;
	}
	else
	{
		strncpy( rgDeathNoticeList[i].szKiller, killer_name, MAX_PLAYER_NAME_LENGTH );
		rgDeathNoticeList[i].szKiller[MAX_PLAYER_NAME_LENGTH-1] = 0;
	}
	// Get the Victim's name
	char *victim_name = NULL;
	// If victim is -1, the killer killed a specific, non-player object (like a sentrygun)
	if ( ((char)iVictim) != -1 )
	{
		gEngfuncs.pfnGetPlayerInfo(iVictim,&hPlayer);
		victim_name = hPlayer.name;
	}
	if ( !victim_name )
	{
		victim_name = "";
		rgDeathNoticeList[i].szVictim[0] = 0;
	}
	else
	{
		strncpy( rgDeathNoticeList[i].szVictim, victim_name, MAX_PLAYER_NAME_LENGTH );
		rgDeathNoticeList[i].szVictim[MAX_PLAYER_NAME_LENGTH-1] = 0;
	}
	// Is it a non-player object kill?
	if ( ((char)iVictim) == -1 )
	{
		rgDeathNoticeList[i].iNonPlayerKill = TRUE;

		// Store the object's name in the Victim slot (skip the d_ bit)
		strcpy( rgDeathNoticeList[i].szVictim, szWpnName+2 );
	}
	else
	{
		if ( iKiller == iVictim || iKiller == 0 )
			rgDeathNoticeList[i].iSuicide = TRUE;
	}

	int iIndex= gEngfuncs.GetLocalPlayer()->index;

	rgDeathNoticeList[i].iId = GetSpriteIndex(szWpnName);
	rgDeathNoticeList[i].flDisplayTime = g_flTime + 6.0f;
	rgDeathNoticeList[i].iHeadShot = iHeadShot;
	rgDeathNoticeList[i].Killer = vPlayer[iKiller].team;
	rgDeathNoticeList[i].Victim = vPlayer[iVictim].team;
	
	if(g_iMod == MOD_DM)
	{
		if(iKiller != iIndex && iVictim != iIndex)
		{
			rgDeathNoticeList[i].Killer = rgDeathNoticeList[i].Victim = 2;
		}
		
		if(iKiller == iIndex && iVictim != iIndex)
		{
			rgDeathNoticeList[i].Killer = 1;
			rgDeathNoticeList[i].Victim = 2;
		}

		if(iVictim == iIndex && iKiller != iIndex)
		{
			rgDeathNoticeList[i].Killer = 2;
			rgDeathNoticeList[i].Victim = 1;
		}

	}
	
	if(iIndex == iKiller)
	{
		rgDeathNoticeList[i].iLocal = 1;
		DeathMsg_iTotalKills += 1;
	}
	else if(iIndex == iVictim)
	{
		rgDeathNoticeList[i].iLocal = 2;
		DeathMsg_iTotalKills = 0;
	}
	else rgDeathNoticeList[i].iLocal = 0;


	if(iVictim==iIndex)
	{
		if(iKiller==iIndex || (IsKnife(szWpnName) && g_iMod != MOD_ZB && g_iMod != MOD_ZB3))
		{	char szCmd[256];
			sprintf(szCmd,"speak %s","ohno");
			gEngfuncs.pfnClientCmd(szCmd);
		}
	}

	if(iKiller==iIndex)
	{

		if(iKiller!=iVictim)
		{
			
			gEngfuncs.pfnGetPlayerInfo(iKiller,&hPlayer);

			/*if(g_flTime > DeathMsg_fNextCountReset) DeathMsg_iKillCount = 0;
			DeathMsg_iKillCount += 1;
			if(DeathMsg_iKillCount > 4) DeathMsg_iKillCount = 4;
			DeathMsg_fNextCountReset = g_flTime + DeathMsg_fCountResetTime[DeathMsg_iKillCount];*/
			DeathMsg_iKillCount = 0;
			for(int i = 0;i<MAX_DEATHNOTICES;i++)
			{
				if(!strcmp(rgDeathNoticeList[i].szKiller,hPlayer.name)) DeathMsg_iKillCount ++;
			}
			DeathMsg_iKillCount = DeathMsg_iKillCount>4?4:DeathMsg_iKillCount;
			if(DeathMsg_iKillCount == 4) gEngfuncs.pfnClientCmd("bte_multikill");
			
			char szSpr1[32]; 
			sprintf(szSpr1, "KM_Number%d",DeathMsg_iKillCount);
			DrawImageItem rgTempDrawImage;
			//计算数字和文字的宽度和间距
			wrect_t *TempRect;
			TempRect = &GetSpriteRect(GetSpriteIndex(szSpr1));
			int NumWidth = (TempRect->right)-(TempRect->left);
			int NumHeight = (TempRect->bottom-TempRect->top);
			//int NumWidth = 41;
			//int NumHeight = 68;
			TempRect = &GetSpriteRect(GetSpriteIndex("KM_KillText"));
			int TextWidth = (TempRect->right)-(TempRect->left);
			int TextHeight =  (TempRect->bottom-TempRect->top);
			int iSprAllWidthHalf=(NumWidth+TextWidth+20)/2;
			//确定X中间
			int x=g_sScreenInfo.iWidth/2-iSprAllWidthHalf;
			//确定Y合适
			int iY = (int)g_sScreenInfo.iHeight*0.15;
			int y = iY;//min(iY,100);
			//Kill Number
			rgTempDrawImage.iFunction = 1;
			rgTempDrawImage.iCheck = 1;
			rgTempDrawImage.iCenter = 0;
			rgTempDrawImage.iSprIndex = GetSpriteIndex(szSpr1);
			rgTempDrawImage.hl_hSprites = GetSprite(rgTempDrawImage.iSprIndex);
			rgTempDrawImage.x = x;
			rgTempDrawImage.y = (int)y - (NumHeight - 68) / 2;
			rgTempDrawImage.color.r = 255;
			rgTempDrawImage.color.g = 255;
			rgTempDrawImage.color.b = 255;
			rgTempDrawImage.iMode = 2;
			rgTempDrawImage.flStartDisplayTime = g_flTime;
			rgTempDrawImage.flEndDisplayTime = 3.0 + g_flTime;
			rgTempDrawImage.iChanne = 51;
			rgTempDrawImage.iLength = -1;
			DrawImageAdd(rgTempDrawImage);
			//Kill Text
			y = iY;//min(iY,100);
			rgTempDrawImage.iFunction = 1;
			rgTempDrawImage.iCheck = 1;
			rgTempDrawImage.iCenter = 0;
			rgTempDrawImage.iSprIndex = GetSpriteIndex("KM_KillText");
			rgTempDrawImage.hl_hSprites = GetSprite(rgTempDrawImage.iSprIndex);
			rgTempDrawImage.x = x+  NumWidth + 5;
			//rgTempDrawImage.y = y+ (NumHeight/2)-(TextHeight/2);
			rgTempDrawImage.y = y+ (68/2)-(TextHeight/2);
			rgTempDrawImage.color.r = 255;
			rgTempDrawImage.color.g = 255;
			rgTempDrawImage.color.b = 255;
			rgTempDrawImage.iMode = 2;
			rgTempDrawImage.flStartDisplayTime = g_flTime;
			rgTempDrawImage.flEndDisplayTime = 3.0 + g_flTime;
			rgTempDrawImage.iChanne = 50;
			rgTempDrawImage.iLength = -1;
			DrawImageAdd(rgTempDrawImage);
			//特殊杀敌标志
			int iIsZombie = 0;
			if((g_iMod == MOD_ZB|| g_iMod == MOD_ZE|| g_iMod == MOD_ZB3) && vPlayer[gEngfuncs.GetLocalPlayer()->index].team == 2) iIsZombie = 1;
			int tWidth;
			int sp=0;
			char szSound[128];
			
			if(strstr(szWpnName,"grenade")||strstr(szWpnName,"mooncake")||strstr(szWpnName,"cartfrag")||strstr(szWpnName,"cake")||strstr(szWpnName,"pumpkin")||
				strstr(szWpnName,"fgrenade")||strstr(szWpnName,"heartbomb")||strstr(szWpnName,"m24grenade")||strstr(szWpnName,"fgrenade2")||strstr(szWpnName,"holybomb")&& g_iMod != MOD_GD) //HE
			{
				sp=1;
				rgTempDrawImage.iFunction = 1;
				rgTempDrawImage.iCheck = 1;
				rgTempDrawImage.iCenter = 0;
				rgTempDrawImage.iSprIndex = GetSpriteIndex("KM_Icon_Frag");
				rgTempDrawImage.hl_hSprites = GetSprite(rgTempDrawImage.iSprIndex);
				wrect_t *TempRect;
				TempRect = &GetSpriteRect(GetSpriteIndex("KM_Icon_Frag"));
				tWidth = (TempRect->right)-(TempRect->left);
				rgTempDrawImage.x = (g_sScreenInfo.iWidth-tWidth)/2;
				rgTempDrawImage.y = y+ 60;
				rgTempDrawImage.color.r = 255;
				rgTempDrawImage.color.g = 255;
				rgTempDrawImage.color.b = 255;
				rgTempDrawImage.iMode = 2;
				rgTempDrawImage.flStartDisplayTime = g_flTime;
				rgTempDrawImage.flEndDisplayTime = 1.0 + g_flTime;
				rgTempDrawImage.iChanne = 49;
				rgTempDrawImage.iLength = -1;
				DrawImageAdd(rgTempDrawImage);
				sprintf(szSound, "Gotit");
			}
			else if((IsKnife(szWpnName) && !((g_iMod == MOD_ZB || g_iMod == MOD_ZB3) && vPlayer[iIndex].team == 2) && g_iMod != MOD_GD)) //KNIFE
			{
				sp=1;
				rgTempDrawImage.iFunction = 1;
				rgTempDrawImage.iCheck = 1;
				rgTempDrawImage.iCenter = 0;
				rgTempDrawImage.iSprIndex = GetSpriteIndex("KM_Icon_knife");
				rgTempDrawImage.hl_hSprites = GetSprite(rgTempDrawImage.iSprIndex);
				wrect_t *TempRect;
				TempRect = &GetSpriteRect(GetSpriteIndex("KM_Icon_knife"));
				tWidth = (TempRect->right)-(TempRect->left);
				rgTempDrawImage.x = (g_sScreenInfo.iWidth-tWidth)/2;
				rgTempDrawImage.y = y+ 90;
				rgTempDrawImage.color.r = 255;
				rgTempDrawImage.color.g = 255;
				rgTempDrawImage.color.b = 255;
				rgTempDrawImage.iMode = 2;
				rgTempDrawImage.flStartDisplayTime = g_flTime;
				rgTempDrawImage.flEndDisplayTime = 1.0 + g_flTime;
				rgTempDrawImage.iChanne = 49;
				rgTempDrawImage.iLength = -1;
				DrawImageAdd(rgTempDrawImage);
				sprintf(szSound, "Humililation");
			}
			else if(iHeadShot&&!iIsZombie && g_iMod != MOD_GD) //HS
			{
				sp=1;
				rgTempDrawImage.iFunction = 1;
				rgTempDrawImage.iCheck = 1;
				rgTempDrawImage.iCenter = 0;
				rgTempDrawImage.iSprIndex = GetSpriteIndex("KM_Icon_Head");
				rgTempDrawImage.hl_hSprites = GetSprite(rgTempDrawImage.iSprIndex);
				wrect_t *TempRect;
				TempRect = &GetSpriteRect(GetSpriteIndex("KM_Icon_Head"));
				tWidth = (TempRect->right)-(TempRect->left);
				rgTempDrawImage.x = (g_sScreenInfo.iWidth-tWidth)/2;
				rgTempDrawImage.y = y+ 60;
				rgTempDrawImage.color.r = 255;
				rgTempDrawImage.color.g = 255;
				rgTempDrawImage.color.b = 255;
				rgTempDrawImage.iMode = 2;
				rgTempDrawImage.flStartDisplayTime = g_flTime;
				rgTempDrawImage.flEndDisplayTime = 1.0 + g_flTime;
				rgTempDrawImage.iChanne = 49;
				rgTempDrawImage.iLength = -1;
				DrawImageAdd(rgTempDrawImage);
				sprintf(szSound, "HeadShot");
			}
//			if(/*sp&&DeathMsg_iKillCount==1 && */!iIsZombie)
//			{
			bool bCanPlaySound = true;

			switch (DeathMsg_iTotalKills)
			{
				case 5:
				{
					if(!sp)
						sprintf(szSound,"Excellent");
					break;
				}
				case 10:
				{
					if(!sp)
						sprintf(szSound,"Incredible");
					break;
				}
				case 15:
				{
					if(!sp)
						sprintf(szSound,"Crazy");
					break;
				}
				case 20:
				{
					if(!sp)
						sprintf(szSound,"CantBelive");
					break;
				}
				case 25:
				{
					if(!sp)
						sprintf(szSound,"OutofWorld");
					break;
				}
				default:
				{
					if(!sp && DeathMsg_iKillCount == 1)
						bCanPlaySound = false;

					if(DeathMsg_iKillCount != 1 || iIsZombie)
					{
						switch (DeathMsg_iKillCount)
						{
							case 1:
							{
								bCanPlaySound = false;
								break;
							}
							case 2:
							{
								sprintf(szSound,"DoubleKill");
								break;
							}
							case 3:
							{
								sprintf(szSound,"TripleKill");
								break;
							}
							case 4:
							{
								sprintf(szSound,"MultiKill");
								break;
							}
						}
					}
					break;
				}

			}
			
			char szCmd[256];
			sprintf(szCmd,"speak \"%s\"\n",szSound);
				
			if(bCanPlaySound)
				gEngfuncs.pfnClientCmd(szCmd);
			/*}
			else
			{
				char szCmd[256];
				sprintf(szSound, "kill/kill_%d",DeathMsg_iKillCount);
				sprintf(szCmd,"speak \"%s\"\n",szSound);
				gEngfuncs.pfnClientCmd(szCmd);
			}*/
		}
	}
	return 0;
}
#define Y_RES	120
#define X_RES	30
#define BORDER	10
#define DRAW_FIX	-10
#define HEADX 6

void DeathMsgInit()
{
	memset(rgDeathNoticeList, 0, sizeof(rgDeathNoticeList)); //Clear Memory (Reset)
}

int DeathMsgRedraw( float flTime )
{

	static int x, y, r, g, b;
	//int m_HUD_d_skull = GetSpriteIndex("d_skull");
	static int toggle = 1;
	static float flLast = 6.0f;
	static int iFillBg = 1;

	int iMaxNotice = 4;

	switch (g_iMod)
	{
		case MOD_TDM :
		{
			iMaxNotice = 6;
			break;
		}
		case MOD_DM :
		{
			iMaxNotice = 6;
			break;
		}
		case MOD_ZBU :
		{
			iMaxNotice = 8;
			break;
		}
	}


	for ( int i = 0; i < MAX_DEATHNOTICES; i++ )
	{
		if ( rgDeathNoticeList[i].iId == 0 )
			break;  // we've gone through them all

		if ( rgDeathNoticeList[i].flDisplayTime < flTime )
		{ // display time has expired
			// remove the current item from the list
			memmove( &rgDeathNoticeList[i], &rgDeathNoticeList[i+1], sizeof(DeathNoticeItem) * (MAX_DEATHNOTICES - i) );
			i--;  // continue on the next item;  stop the counter getting incremented
			continue;
		}
	}


	int iEnd;
	for ( iEnd = 0; iEnd < MAX_DEATHNOTICES; iEnd++ )
	{
		if ( rgDeathNoticeList[iEnd].iId == 0 )
			break;
	}

	int iOffset = 0;

	if ( iEnd > iMaxNotice )
		iOffset = iEnd - iMaxNotice;

	for ( int i = iOffset; i < iMaxNotice + iOffset; i++ )
	{
		if ( rgDeathNoticeList[i].iId == 0 )
			break;  // we've gone through them all

		/*if ( rgDeathNoticeList[i].flDisplayTime < flTime )
		{ // display time has expired
			// remove the current item from the list
			memmove( &rgDeathNoticeList[i], &rgDeathNoticeList[i+1], sizeof(DeathNoticeItem) * (MAX_DEATHNOTICES - i) );
			i--;  // continue on the next item;  stop the counter getting incremented
			continue;
		}*/
		
		rgDeathNoticeList[i].flDisplayTime = min( rgDeathNoticeList[i].flDisplayTime, g_flTime +flLast );

		if(!toggle) return 0;

			y = (Y_RES + 2 + (22 * (i - iOffset)));  //!!!

			if(g_iMod == MOD_GD)
			{
				y = g_iGD_Y + 2 + (22 * (i - iOffset));
			}
			int iFillX;

			int id = (rgDeathNoticeList[i].iId == -1) ? GetSpriteIndex("d_skull"): rgDeathNoticeList[i].iId;
			x = g_sScreenInfo.iWidth - ConsoleStringLen(rgDeathNoticeList[i].szVictim) - (GetSpriteRect(id).right - GetSpriteRect(id).left)-BORDER;
			x -= 20;
			
			iFillX = x;

			//background color
			int iWidth = ConsoleStringLen(rgDeathNoticeList[i].szVictim) + (GetSpriteRect(id).right - GetSpriteRect(id).left);

			int m_Head = GetSpriteIndex("d_headshot");
			if(rgDeathNoticeList[i].iHeadShot)
			{
				x -= (GetSpriteRect(m_Head).right - GetSpriteRect(m_Head).left) ;
				iFillX = x;
				iWidth += (GetSpriteRect(m_Head).right - GetSpriteRect(m_Head).left);
			}
			if ( !rgDeathNoticeList[i].iSuicide )
			{
				iFillX  -= (5 + ConsoleStringLen( rgDeathNoticeList[i].szKiller )+BORDER);
			}

			if(rgDeathNoticeList[i].iLocal ==1 && iFillBg)
			{
				int iDrawLen = rgDeathNoticeList[i].iSuicide?(iWidth+10+BORDER+5):(5 + ConsoleStringLen( rgDeathNoticeList[i].szKiller)+iWidth+10+2*BORDER+5);
				y-=1;
				//3
				MH_DrawTGAFunction2(g_Texture[DeathMsg_iDeathTga[0][0]].iTexture,iFillX-5,y,3,20,255);
				MH_DrawTGAFunction2(g_Texture[DeathMsg_iDeathTga[0][1]].iTexture,iFillX-2,y,iDrawLen-6,20,255);
				MH_DrawTGAFunction2(g_Texture[DeathMsg_iDeathTga[0][2]].iTexture,iFillX-5+iDrawLen-3,y,3,20,255);

				
				/*Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathMsg_iDeathTga[0][0]].texid);
				gEngfuncs.pTriAPI->Color4f(1,1,1,1);
				Tri_Enable(GL_BLEND);
				Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);


		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5,y+20,0);

				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+3,y+20,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+3,y,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5,y,0);
				gEngfuncs.pTriAPI->End();

				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathMsg_iDeathTga[0][1]].texid);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2,y+20,0);

				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2+iDrawLen-6,y+20,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2+iDrawLen-6,y,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2,y,0);
				gEngfuncs.pTriAPI->End();

				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathMsg_iDeathTga[0][2]].texid);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen-3,y+20,0);

				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen,y+20,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen,y,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen-3,y,0);
				gEngfuncs.pTriAPI->End();*/
			}
			else if(rgDeathNoticeList[i].iLocal ==2 && iFillBg)
			{
				int iDrawLen = rgDeathNoticeList[i].iSuicide?(iWidth+10+BORDER+5):(5 + ConsoleStringLen( rgDeathNoticeList[i].szKiller)+iWidth+10+2*BORDER+5);
				y-=1;
				//3

				MH_DrawTGAFunction2(g_Texture[DeathMsg_iDeathTga[1][0]].iTexture,iFillX-5,y,3,20,255);
				MH_DrawTGAFunction2(g_Texture[DeathMsg_iDeathTga[1][1]].iTexture,iFillX-2,y,iDrawLen-6,20,255);
				MH_DrawTGAFunction2(g_Texture[DeathMsg_iDeathTga[1][2]].iTexture,iFillX-5+iDrawLen-3,y,3,20,255);
				/*Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathMsg_iDeathTga[1][0]].texid);
				gEngfuncs.pTriAPI->Color4f(1,1,1,1);
				Tri_Enable(GL_BLEND);
				Tri_Enable(GL_ALPHA_TEST);
				Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
				Tri_AlphaFunc(GL_GREATER, 0.0);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5,y+20,0);

				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+3,y+20,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+3,y,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5,y,0);
				gEngfuncs.pTriAPI->End();
				
				
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathMsg_iDeathTga[1][1]].texid);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2,y+20,0);

				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2+iDrawLen-6,y+20,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2+iDrawLen-6,y,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-2,y,0);
				gEngfuncs.pTriAPI->End();

				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[DeathMsg_iDeathTga[1][2]].texid);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen-3,y+20,0);

				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen,y+20,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen,y,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iFillX-5+iDrawLen-3,y,0);
				gEngfuncs.pTriAPI->End();*/
			}
			y = (Y_RES + 2 + (22 * (i - iOffset)));
			if(g_iMod == MOD_GD)
			{
				y = g_iGD_Y + 2 + (22 * (i - iOffset));
			}
			if ( !rgDeathNoticeList[i].iSuicide )
			{
				x -= (5 + ConsoleStringLen( rgDeathNoticeList[i].szKiller ) )+BORDER;
				// Draw killers name
				if(rgDeathNoticeList[i].Killer == 1)
				{
					gEngfuncs.pfnDrawSetTextColor(0.6, 0.8, 1.0);
				}
				else gEngfuncs.pfnDrawSetTextColor(1.0, 0.25, 0.25);
				
				x = 5 + DrawConsoleString( x, y, rgDeathNoticeList[i].szKiller )+BORDER;
			}

			if(rgDeathNoticeList[i].iHeadShot) x -= HEADX;
			
			r = 255;  g = 80;	b = 0;

			// Draw death weapon
			gEngfuncs.pfnSPR_Set( GetSprite(id), r, g, b );
			gEngfuncs.pfnSPR_DrawAdditive( 0, x, y, &GetSpriteRect(id) );
			
			x += (GetSpriteRect(id).right - GetSpriteRect(id).left);
			if(rgDeathNoticeList[i].iHeadShot) 
			{
				gEngfuncs.pfnSPR_Set( GetSprite(m_Head), r, g, b );
				gEngfuncs.pfnSPR_DrawAdditive( 0, x + HEADX + 3 , y, &GetSpriteRect(m_Head));
				x +=GetSpriteRect(m_Head).right - GetSpriteRect(m_Head).left;
			}
			if (rgDeathNoticeList[i].iNonPlayerKill == FALSE)
			{
				if(rgDeathNoticeList[i].Victim == 1)
				{
					gEngfuncs.pfnDrawSetTextColor(0.6, 0.8, 1.0);
				}
				else gEngfuncs.pfnDrawSetTextColor(1.0, 0.25, 0.25);
				x+=BORDER+5;
				if(rgDeathNoticeList[i].iHeadShot) x = DrawConsoleString( x + HEADX, y, rgDeathNoticeList[i].szVictim );
				else x = DrawConsoleString( x, y, rgDeathNoticeList[i].szVictim );
			}
	}
	return 1;
}