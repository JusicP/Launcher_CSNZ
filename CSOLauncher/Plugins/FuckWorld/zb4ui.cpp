#include "base.h"
#include "bink.h"
#include "BaseUI.h"

#define ZB4DATA_PWOER 100
#define ZB4DATA_SCORE 101
#define ZB4DATA_DMG 102
#define ZB4DATA_DAY_STATUS 103
#define ZB4DATA_AURA	104
#define ZB4DATA_CLASS 105
#define ZB4DATA_ROUNDSTART	106
#define ZB4DATA_RETINA	107
int g_zb4_class = ZB4_CLASS_HM;
int g_zb4_scoreboard,g_zb4_scoredmg;
int g_zb4_num0;
int g_zb4_num_width = 0;
int g_zb4_pw_left;
int g_zb4_pw_bg;
int g_zb4_pw_line1;
int g_zb4_pw_line2;
int g_zb4_pw_client = 0; 
int g_zb4_pw_server = 0;
int g_zb4_data_score=0;
int g_zb4_data_dmg = 0;
model_t *g_zb4_hudspr = NULL;
float g_zb4_checkteam=0;
int g_zb4_team_ct=0;
int g_zb4_team_t=0;
int g_zb4_day;
int g_zb4_zombie_skilltimes[]={0,11};
int g_zb4_aura;
int g_zb4_zbclass;
int g_zb4_tga_hs,g_zb4_tga_defenseup,g_zb4_tga_hpup,g_zb4_tga_midnightup,g_zb4_tga_powerup,g_zb4_tga_speedup,g_zb4_tga_cannotcontrol,g_zb4_tga_defensedown;
int g_zb4_tga_hpdown,g_zb4_tga_midnightdown,g_zb4_tga_speeddown;
int g_zb4_tga_6;
int g_zb4_tga_right;
int g_zb4_retina_class=0;
int g_zb4_retina[10];
int g_zb4_tga_icon[2];
float g_zb4_retina_start = 0;
#define DAY_DATTIME	1
#define DAY_NIGHT		2
#define DAY_EVENING	3
#define DAY_BEFOREDAYTIME	4
#define DAY_BEFORENIGHT	5

enum AuraList
{
	AURA_HM_SPEEDUP=1<<1,
	AURA_HM_HS = 1<<2,
	
	AURA_ZB_SPEEDUP = 1<<3,
	AURA_ZB_HPUP = 1<<4,
	AURA_ZB_HPDOWN = 1<<5,
	AURA_ZB_DEFUP = 1<<6,
	AURA_ZB_DEFDOWN = 1<<7
};

void ZombieMod4UICheckTeam(int team)
{
	if(team == 1) // CT
	{
		g_zb4_class = ZB4_CLASS_HM;
	}
	else if(team == 2)
	{
		g_zb4_class = ZB4_CLASS_ZB;
	}
	else g_zb4_class = 0;
}

void Zombie4UIParseData(int DataType, int iData)
{
	switch (DataType)
	{
		case ZB4DATA_PWOER:
		{
			g_zb4_pw_server = iData;
			break;
		}
		case ZB4DATA_SCORE:
		{
			g_zb4_data_score = iData;
			break;
		}
		case ZB4DATA_DMG:
		{
			g_zb4_data_dmg = iData;
			break;
		}
		case ZB4DATA_DAY_STATUS:
		{
			g_zb4_day = iData;
			break;
		}
		case ZB4DATA_AURA:
		{
			g_zb4_aura = iData;
			break;
		}
		case ZB4DATA_CLASS:
		{
			g_zb4_zbclass = iData;
			break;
		}
		case ZB4DATA_ROUNDSTART:
		{
			g_zb4_retina_class =0;
			g_zb4_pw_client = g_zb4_pw_server = 0;
			break;
		}
		case ZB4DATA_RETINA:
		{
			g_zb4_retina_start = g_flTime;
			g_zb4_retina_class = iData;
			break;
		}
	}
}

void ZombieMod4UIInit(void)
{
	g_zb4_class = ZB4_CLASS_HM;
	g_zb4_scoreboard = FindTexture("resource\\hud\\zb4\\z4_scoreboard");
	g_zb4_scoredmg = FindTexture("resource\\hud\\zb4\\z4_scorebg");
	g_zb4_pw_left = FindTexture("resource\\hud\\zb4\\adrenalinneleft");
	g_zb4_pw_bg = FindTexture("resource\\hud\\zb4\\adrenalinebg");
	g_zb4_pw_line1 = FindTexture("resource\\hud\\zb4\\adrenalinnegauge");
	g_zb4_pw_line2 = FindTexture("resource\\hud\\zb4\\adrenalinnegauge2");

	// BUFF
	g_zb4_tga_hs =FindTexture("resource\\hud\\zb4\\z4_criticalshot");
	g_zb4_tga_defenseup=FindTexture("resource\\hud\\zb4\\z4_defenseup");
	g_zb4_tga_hpup=FindTexture("resource\\hud\\zb4\\z4_hpup");
	g_zb4_tga_midnightup=FindTexture("resource\\hud\\zb4\\z4_midnightup");
	g_zb4_tga_powerup=FindTexture("resource\\hud\\zb4\\z4_powerup");
	g_zb4_tga_speedup=FindTexture("resource\\hud\\zb4\\z4_speedup");
	// DEBUFF
	g_zb4_tga_cannotcontrol=FindTexture("resource\\hud\\zb4\\z4_cannotcontrol");
	g_zb4_tga_defensedown=FindTexture("resource\\hud\\zb4\\z4_defensedown");
	g_zb4_tga_hpdown=FindTexture("resource\\hud\\zb4\\z4_hpdown");
	g_zb4_tga_midnightdown=FindTexture("resource\\hud\\zb4\\z4_midnightdown");
	g_zb4_tga_speeddown=FindTexture("resource\\hud\\zb4\\z4_speeddown");

	g_zb4_tga_6 = FindTexture("resource\\hud\\zb4\\z4_6key");
	g_zb4_tga_right = FindTexture("resource\\hud\\zb4\\right");
	g_zb4_tga_icon[0] = FindTexture("resource\\hud\\zb4\\z4_scorehuman");
	g_zb4_tga_icon[1] = FindTexture("resource\\hud\\zb4\\z4_scorezombie");

	// RETINA

	g_zb4_retina[0] = DrawTgaGetID("mode\\zb4\\retina_1");
	g_zb4_retina[1] = DrawTgaGetID("mode\\zb4\\retina_2");
	g_zb4_retina[2] = DrawTgaGetID("mode\\zb4\\zombinight");


	g_zb4_num0 = GetSpriteIndex("z4_number_0");
	g_zb4_hudspr = IEngineStudio.Mod_ForName("sprites/z4.spr",0);
	g_zb4_checkteam = 0;

}
void DrawZB4HudNumber2(int x, int y,int iNumber,int r,int g,int b,float fScale)
{
	int k;
	wrect_t Rect;

	gEngfuncs.pTriAPI->RenderMode( kRenderTransAdd );
	gEngfuncs.pTriAPI->CullFace( TRI_NONE );
	gEngfuncs.pTriAPI->Color4ub( r,g,b,255 );
	gEngfuncs.pTriAPI->SpriteTexture(g_zb4_hudspr,0);

	if(!g_zb4_num_width)
	{
		Rect = GetSpriteRect(g_zb4_num0+1);
		g_zb4_num_width = Rect.right - Rect.left;
	}
	if (iNumber >= 10000)
	{
		k = (iNumber % 100000) / 10000;
		Rect = GetSpriteRect(g_zb4_num0+k);
		TEXD_DrawTexture(x,y,256,256,&Rect,fScale);
		x += (g_zb4_num_width-4)*fScale;
	}
	if (iNumber >= 1000)
	{
		k = (iNumber % 10000) / 1000;
		Rect = GetSpriteRect(g_zb4_num0+k);
		TEXD_DrawTexture(x,y,256,256,&Rect,fScale);
		x += (g_zb4_num_width-4)*fScale;
	}
	if (iNumber >= 100)
	{
		k = (iNumber % 1000) / 100;
		Rect = GetSpriteRect(g_zb4_num0+k);
		TEXD_DrawTexture(x,y,256,256,&Rect,fScale);
		x += (g_zb4_num_width-4)*fScale;
	}

	if (iNumber >= 10)
	{
		k = (iNumber % 100) / 10;
		Rect = GetSpriteRect(g_zb4_num0+k);
		TEXD_DrawTexture(x,y,256,256,&Rect,fScale);
		x += (g_zb4_num_width-4)*fScale;
	}
	else 
	{
		x += (g_zb4_num_width-4)*fScale;
	}
	k = iNumber % 10;
	
	Rect = GetSpriteRect(g_zb4_num0+k);
	TEXD_DrawTexture(x,y,256,256,&Rect,fScale);
	x += (g_zb4_num_width-4)*fScale;
}

int test_round = 9;
int test_power = 46;
float dymic_power = 0;
int g_processing= 0;
float starttime=0;
float curtime = 0;
float endvalue=0;
void ZombieMod4UIRedraw(void)
{
	if(g_iMod != MOD_ZB4) return;
	if(!g_bAlive) return;
	int iLocal = gEngfuncs.GetLocalPlayer()->index;
	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

	ZombieMod4RetinaRedraw();

	if(g_zb4_checkteam < g_flTime)
	{
		g_zb4_checkteam = g_flTime + 0.5f;
		g_zb4_team_ct=0;
		g_zb4_team_t=0;
		for(int i=1;i<33;i++)
		{
			if(iValidPlayer[i] && !(g_PlayerExtraInfo[i].iFlag & SCOREATTRIB_DEAD))
			{
				if(vPlayer[i].team == 1) g_zb4_team_ct++;
				else if(vPlayer[i].team == 2) g_zb4_team_t++;
			}
		}
	}

	// Draw ScoreBoard
	int iX,iY;
	iX = (g_sScreenInfo.iWidth - g_Texture[g_zb4_scoreboard].iWidth)/2;
	MH_DrawTGAFunction(g_Texture[g_zb4_scoreboard].iTexture,255,255,255,255,iX,10,1.0f);
	// -- Draw Hud Number
	// -- Top 
	//    -- Left
	iX  += 13;
	DrawZB4HudNumber2(iX,16,g_SBTopLeft,239, 222, 179,0.8);
	//    -- Right
	iX += 150;
	DrawZB4HudNumber2(iX,16,g_SBTopRight,239, 222, 179,0.8);
	// -- Center
	iX = g_sScreenInfo.iWidth/2;
	if(test_round>9)
	{
		iX -=(g_zb4_num_width+2);
		DrawZB4HudNumber2(iX,34,g_SBTopRight+g_SBTopLeft+1,239, 222, 179,1.0);
	}
	else
	{
		iX -=(g_zb4_num_width/2 + 2);
		DrawZB4HudNumber2(iX-13,34,g_SBTopRight+g_SBTopLeft+1,239, 222, 179,1.0);
	}
	// -- Down
	//    -- Left
	iX = (g_sScreenInfo.iWidth - g_Texture[g_zb4_scoreboard].iWidth)/2;

	DrawZB4HudNumber2(iX+20,42,g_zb4_team_t,239, 222, 179,0.6);
	//	  --Right
	DrawZB4HudNumber2(iX+160,42,g_zb4_team_ct,239, 222, 179,0.6);

	// Draw Score & Damage
	iX = g_sScreenInfo.iWidth - g_Texture[g_zb4_scoredmg].iWidth - 15;
	iY = g_sScreenInfo.iHeight - g_Texture[g_zb4_scoredmg].iHeight - 100;

	if(g_zb4_class == ZB4_CLASS_HM)
	{
		MH_DrawTGAFunction(g_Texture[g_zb4_tga_icon[0]].iTexture,255,255,255,255,iX+10,iY+6,1.0f);
	}
	else
	{
		MH_DrawTGAFunction(g_Texture[g_zb4_tga_icon[1]].iTexture,255,255,255,255,iX+10,iY+6,1.0f);
	}
		
	MH_DrawTGAFunction(g_Texture[g_zb4_scoredmg].iTexture,255,255,255,255,iX,iY,1.0f);
	// Draw Score & Dmg Num
	
	DrawZB4HudNumber2(iX+128,iY+17,g_zb4_data_score,251,201,96,0.65); // score
	DrawZB4HudNumber2(iX+131,iY+40,g_zb4_data_dmg,251,201,96,0.5);

	// Draw POWER
	// -- Draw Bg
	iX = (g_sScreenInfo.iWidth - g_Texture[g_zb4_pw_bg].iWidth)/2;
	iY = g_sScreenInfo.iHeight- g_Texture[g_zb4_scoredmg].iHeight - 80;
	MH_DrawTGAFunction(g_Texture[g_zb4_pw_bg].iTexture,255,255,255,255,iX,iY,1.0f);
	// -- Left Icon
	// Calc Flash
	float fSubTime = g_flTime;
	int iAlpha;
	fSubTime -=(int)fSubTime;
	fSubTime-=0.5;
	fSubTime=fabsf(fSubTime);
	iAlpha =50+205.0*fSubTime*2;
	MH_DrawTGAFunction(g_Texture[g_zb4_pw_left].iTexture,255,255,255,g_zb4_pw_server==100?255:iAlpha,iX,iY,1.0f);
	// Power Number
	//DrawZB4HudNumber2(iX+44,iY+40,g_zb4_pw_client,239, 222, 179,1.0f);
	DrawZB4HudNumber2(iX+38,iY+40,g_zb4_pw_client,239, 222, 179,1.0f);
	// Line
	iX += g_Texture[g_zb4_pw_left].iWidth;
	iY += 46;
	MH_DrawTGAFunction3(g_zb4_pw_line1,iX,iY,g_zb4_pw_client/100.0,g_Texture[g_zb4_pw_line1].iHeight,255);

	
	// Once Change!!!
	// Fix
	// Bound it
	if(g_zb4_pw_client > 100) g_zb4_pw_client = 100;
	if(g_zb4_pw_client < 0) g_zb4_pw_client = 0;
	if(g_zb4_pw_client > g_zb4_pw_server)
	{
		if( (endvalue - g_zb4_pw_client) > 0) // still decrease
		{
			g_zb4_pw_client = g_zb4_pw_server;
		}
		else
		{
			endvalue = g_zb4_pw_client;
			g_zb4_pw_client = g_zb4_pw_server;
		}
	}
	if( (endvalue - g_zb4_pw_client) > 0)
	{
		float fDelta = g_flTime - curtime;
		endvalue -= fDelta*100/3;
		MH_DrawTGAFunction3(g_zb4_pw_line2,iX+g_zb4_pw_client/100.0f*g_Texture[g_zb4_pw_line1].iWidth,iY,(endvalue-g_zb4_pw_client)/100.0,g_Texture[g_zb4_pw_line1].iHeight,255);
	}
	g_zb4_pw_client = g_zb4_pw_server;
	curtime = g_flTime; 
#define DAY_DATTIME	1
#define DAY_NIGHT		2
#define DAY_EVENING	3
#define DAY_BEFOREDAYTIME	4
#define DAY_BEFORENIGHT	5
	// Draw Aura / BUFF
	iX = 14;
	iY = g_sScreenInfo.iHeight * 0.54;
	if(g_zb4_class == ZB4_CLASS_HM)
	{
		
		// POWER UP
		MH_DrawTGAFunction(g_Texture[g_zb4_tga_powerup].iTexture,255,255,255,255,iX,iY,1.0f);
		// Draw Text
		Fonts_SetSize(14,14);
		Fonts_SetColor(173,201,235,255);
		wchar_t p[10];
		swprintf(p,L"%d%%",g_zb4_pw_server);
		//Fonts_Draw(p,iX+20,iY+42,100,100);
		Fonts_Draw(p,iX+7,iY+42,100,100);

		iX += 53;
		if(g_zb4_aura & AURA_HM_SPEEDUP)
		{
			// SPEED UP
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_speedup].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += 53;
		}
		if(g_zb4_aura & AURA_HM_HS)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_hs].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += 53;
		}
		// MID DOWN
		iX = 14;
		iY += 53;
		if(g_zb4_day == DAY_NIGHT)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_midnightdown].iTexture,255,255,255,255,iX,iY,1.0f);
		}
		else if(g_zb4_day == DAY_BEFORENIGHT)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_midnightdown].iTexture,255,255,255,iAlpha,iX,iY,1.0f);
		}
		if(g_zb4_pw_server>29)
		{
			iY = g_sScreenInfo.iHeight- g_Texture[g_zb4_scoredmg].iHeight - 110;
			Fonts_SetSize(24,24);
			Fonts_SetColor(251,201,96,255);
			wchar_t p[20];
			swprintf(p,L"Concentrated Fire");
			//swprintf(p,L"可使用[精准打击]");
			int iW = Fonts_GetLen(p);
			iW += (g_Texture[g_zb4_tga_6].iWidth + 6);
			iX = (g_sScreenInfo.iWidth-iW)/2;
			iX += 30;
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_6].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += (g_Texture[g_zb4_tga_6].iWidth + 6);
			Fonts_Draw(p,iX,iY+31,800,100);
			
		}
	}
	else
	{
		// BUFF
		// HEALTH UP
		if(g_zb4_day == DAY_NIGHT)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_hpup].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += 53;
		}
		// MID UP
		if(g_zb4_day == DAY_NIGHT)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_midnightup].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += 53;
		}
		else if(g_zb4_day == DAY_BEFORENIGHT)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_midnightup].iTexture,255,255,255,iAlpha,iX,iY,1.0f);
			iX += 53;
		}
		if(g_zb4_aura & AURA_ZB_SPEEDUP)
		{
			// SPEED UP
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_speedup].iTexture,255,255,255,255,iX,iY,1.0f);
		}
		// DEBUFF
		iX = 14;
		iY += 53;
		if(g_iHealth == 1 && g_zb4_day == DAY_NIGHT)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_cannotcontrol].iTexture,255,255,255,iAlpha,iX,iY,1.0f);
			iX += 53;
		}
		if( g_zb4_day == DAY_BEFOREDAYTIME)
		{
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_speeddown].iTexture,255,255,255,iAlpha,iX,iY,1.0f);
			iX += 53;
		}
		// Text
		//iY = g_sScreenInfo.iHeight- g_Texture[g_zb4_scoredmg].iHeight - 80;
		iY = g_sScreenInfo.iHeight- g_Texture[g_zb4_scoredmg].iHeight - 110;
		if(g_zb4_zbclass == 1)
		{
			Fonts_SetSize(24,24);
			Fonts_SetColor(251,201,96,255);
			wchar_t p[20];
			swprintf(p,L"Wall Climb(%d)",g_zb4_pw_server / g_zb4_zombie_skilltimes[g_zb4_zbclass]);
			//swprintf(p,L"可使用[攀爬](%d次)",g_zb4_pw_server / g_zb4_zombie_skilltimes[g_zb4_zbclass]);
			int iW = Fonts_GetLen(p);
			iW += (g_Texture[g_zb4_tga_right].iWidth + 6);
			iX = (g_sScreenInfo.iWidth-iW)/2;
			iX += 30;
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_right].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += (g_Texture[g_zb4_tga_right].iWidth + 6);
			//Fonts_Draw(p,iX+20,iY+20,800,100);
			Fonts_Draw(p,iX,iY+31,800,100);

		}
		//iY = g_sScreenInfo.iHeight- g_Texture[g_zb4_scoredmg].iHeight - 80;
		iY = g_sScreenInfo.iHeight- g_Texture[g_zb4_scoredmg].iHeight - 110;
		if(g_zb4_zbclass == 2)
		{
			Fonts_SetSize(24,24);
			Fonts_SetColor(251,201,96,255);
			wchar_t p[20];
			swprintf(p,L"Leap(%d)",g_zb4_pw_server / g_zb4_zombie_skilltimes[g_zb4_zbclass]);
			//swprintf(p,L"可使用[攀爬](%d次)",g_zb4_pw_server / g_zb4_zombie_skilltimes[g_zb4_zbclass]);
			int iW = Fonts_GetLen(p);
			iW += (g_Texture[g_zb4_tga_right].iWidth + 6);
			iX = (g_sScreenInfo.iWidth-iW)/2;
			iX += 30;
			MH_DrawTGAFunction(g_Texture[g_zb4_tga_right].iTexture,255,255,255,255,iX,iY,1.0f);
			iX += (g_Texture[g_zb4_tga_right].iWidth + 6);
			//Fonts_Draw(p,iX+20,iY+20,800,100);
			Fonts_Draw(p,iX,iY+31,800,100);
		}
		
	}
}
void ZombieMod4RetinaRedraw(void)
{
	if(!g_zb4_retina_class) return;
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);

	if(g_zb4_class == ZB4_CLASS_ZB && g_zb4_day == DAY_NIGHT)
	{
		Tri_Enable(GL_TEXTURE_2D);
		Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb4_retina[2]].texid);
		float alpha;
				
		float fX = 0.05f;
		float fY = 0.95f;
		if(g_iVideoMode) glColor4ub(255,255,255,255);
		else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);

		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
	
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX );
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2,0);
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,0,0);
		
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(0,0,0);
		gEngfuncs.pTriAPI->End();
				//
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,0,0);
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2,0);
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
		gEngfuncs.pTriAPI->End();
				//
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2,0);
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->End();
		//
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
		gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2,0);
		gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
		gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);
		gEngfuncs.pTriAPI->End();
	}
	switch (g_zb4_retina_class)
	{
	case 1:
		{
				Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb4_retina[1]].texid);
				float alpha;
				float fSubTime = g_flTime;
				fSubTime -=(int)fSubTime;
				fSubTime-=0.5;
				fSubTime=fabsf(fSubTime);	
				alpha =fSubTime+0.5;
				alpha *= 255;
				if(g_iVideoMode) glColor4ub(255,0,0,alpha);
				else gEngfuncs.pTriAPI->Color4ub(255,255,255,alpha);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);		
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(0,0,0);
				gEngfuncs.pTriAPI->End();
				break;
		}
	case 2:
		{
				Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb4_retina[0]].texid);
				float alpha;
				
				float fX = 0.05f;
				float fY = 0.95f;
				if(g_iVideoMode) glColor4ub(255,255,255,255);
				else gEngfuncs.pTriAPI->Color4ub(255,255,255,255);

				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX );
				gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2,0);
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,0,0);
		
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(0,0,0);
				gEngfuncs.pTriAPI->End();
				//
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,0,0);
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2,0);
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,0,0);
				gEngfuncs.pTriAPI->End();
				//
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight/2,0);
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight,0);
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(0,g_sScreenInfo.iHeight,0);
				gEngfuncs.pTriAPI->End();
				//
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight,0);
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fX);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth/2,g_sScreenInfo.iHeight/2,0);		
				gEngfuncs.pTriAPI->TexCoord2f(fY,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight/2,0);
				gEngfuncs.pTriAPI->TexCoord2f(fX,1-fY);
				gEngfuncs.pTriAPI->Vertex3f(g_sScreenInfo.iWidth,g_sScreenInfo.iHeight,0);
				gEngfuncs.pTriAPI->End();
				break;
		}
	}
}