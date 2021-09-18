#include "base.h"
#include "bink.h"
#include "BaseUI.h"
#define CLASS_ZB	1
#define CLASS_HM	2
#define CLASS_HERO	3

UIElement UISlot[5];

int g_zb3_class = CLASS_HM;
int g_zb_nvg = 0;
int g_zb3_rage = -1;
float g_zb3_morale = 0;
int g_zb3_morale_int = 100;
int g_zb3_morale_up = 0;
float g_zb3_rage_percent = 0;
int g_zb3_spr_morale_icon;
int g_zb3_spr_morale_level;
int g_zb3_spr_morale_effect;
int g_zb3_spr_morale_effect2;
int g_zb3_spr_rage_level;
int g_zb3_spr_rage_bg;
int g_zb3_spr_rage_index;
float g_zb3_timer_rage = 0;
int g_zb3_frame_rage = 0;
int g_zb3_bik_select = 1;
int g_zb3_spr_supply;
HSPRITE g_zb3_hspr_rage[7];
int g_zb3_zombietga_index;
int g_zb3_tga_skullslot_bg;
int g_zb3_tga_keyslot_bg;
int g_zb3_tga_hs_hs;
int g_zb3_tga_hs_spd;
int g_zb3_tga_hs_kni;
int g_zb3_tga_hs[5];
int g_zb3_tga_zs_zombicrazy;
int g_zb3_tga_icon_hero,g_zb3_tga_icon_supply,g_zb3_tga_icon_trap;
int g_zb3_retina[10];
int g_zb3_retina_draw,g_zb3_retina_class;
float g_zb3_retina_start;
int g_zb3_top_show_type;

int g_zb3_item[3][2];

int g_zb3_item_bit;

int g_zb3_menu_zb[10];
float g_zb3_menu_time;
int g_isShowingZbMenu;
int zb3_iBinkTextureID = 0;
BYTE *pZombieSelectBinkMem = NULL;

void ZombieMod3UIParseIcon(char *pszName,int iSlot,int iType,int iData)
{
	// iType
	// 1--NORMAL 2--FLASH 3--COLDDOWN 4--NOTALAILABLE
	if(iSlot == 0)
	{
		g_zb3_zombietga_index=FindTexture(pszName);
		return;
	}
	UISlot[iSlot].iType = iType;
	UISlot[iSlot].iMH = DrawTgaGetID(pszName);
	/*if(g_zb3_class == CLASS_ZB)	
	{		
		UISlot[iSlot].r = 255;
		UISlot[iSlot].g = 210;
		UISlot[iSlot].b = 191;
		UISlot[iSlot].a = 255;
	}
	else
	{*/
	UISlot[iSlot].r =  UISlot[iSlot].g = 255;
	UISlot[iSlot].b = 191;
	UISlot[iSlot].a = 255;
	//}
	UISlot[iSlot].flStartDisplayTime = g_flTime;
	UISlot[iSlot].flEndDisplayTime = g_flTime + iData;
	if(iType ==4) UISlot[iSlot].a = 100;
}

void ZombieMod3UICheckTeam(int team)
{
	if(team == 1) // CT
	{
		g_zb3_class = CLASS_HM;
	}
	else if(team == 2)
	{
		g_zb3_class = CLASS_ZB;
	}
	else g_zb3_class = 0;
}

#define	HUMAN_SKILL	20
#define	TANK_ZB		0
#define	SPEED_ZB	1
#define	HEAVY_ZB	2
#define	HEAL_ZB		3
#define	DEIMOS_ZB	4
#define	CHINA_ZB	5
#define	BOMMER_ZB	6
#define	RESIDENT_ZB	7
#define GANYMEDE_ZB	8

void ZB3SkillIconCallback ( struct tempent_s *ent, float frametime, float currenttime )
{
	if (currenttime + 1 > ent->die && ent->entity.curstate.renderamt)
		ent->entity.curstate.renderamt -=15;
}

void Zombie3UIParseData(int DataType, int iData)
{
	switch (DataType)
	{
		case ZB3DATA_HM_MORALE:
		{
			if(g_zb3_morale_up) g_zb3_morale = float(iData) / 13.0f;
			else g_zb3_morale = float(iData) / 10.0f;
			g_zb3_morale_int = iData * 10 + 100;
			break;
		}
		case ZB3DATA_ZB_LEVEL:
		{
			break;
		}
		case ZB3DATA_HM_MORALE_MAX :
		{
			g_zb3_item_bit = iData;
			if((1<<2) & g_zb3_item_bit)
				g_zb3_morale_up = 1;	
			break;
		}
		case ZB3DATA_ZB_RAGE:
		{
			g_zb3_rage_percent = float(iData)/100.0;
			if(g_zb3_rage_percent <0.25) g_zb3_rage = -1;
			else if(g_zb3_rage_percent <0.5) g_zb3_rage = 0;
			else if(g_zb3_rage_percent <0.75) g_zb3_rage = 1;
			else g_zb3_rage = 2;
			break;
		}
		case ZB3DATA_RETINA:
		{
			g_zb3_retina_draw = 1;
			g_zb3_retina_class = iData;
			g_zb3_retina_start = g_flTime;
			break;
		}
		case ZB3DATA_RETINASTOP:
		{
			g_zb3_retina_draw = 0;
			break;
		}
		case ZB3DATA_CLEARUI:
		{
			memset(UISlot,0,sizeof(UISlot));
			break;
		}
		case ZB3DATA_TOPUI:
		{
			g_zb3_top_show_type = iData;
			break;
		}
		case ZB3DATA_BECOME_ZB:
		{
			memset(UISlot,0,sizeof(UISlot));			
			DrawRetinaReset();			
			switch (iData)
			{
				case HUMAN_SKILL:
				{
					ZombieMod3UIParseIcon("mode\\zb3\\humanskill_hm_spd",1,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\humanskill_hm_hd",2,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\humanskill_hm_2x",3,2,3);
					break;
				}
				case TANK_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_tank_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombicrazy",1,2,3);
					break;
				}
				case SPEED_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_speed_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_hide",1,2,3);
					break;
				}
				case HEAVY_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_heavy_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombitrap",1,2,3);
					break;
				}
				case HEAL_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_heal_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombiheal",1,2,3);
					break;
				}
				case DEIMOS_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_deimos_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_tentacle",1,2,3);
					break;
				}
				case CHINA_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_china_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombistiffen",1,2,3);
					break;
				}
				case BOMMER_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_boomer_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombiheal",1,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombiguard",2,2,3);
					break;
				}
				case RESIDENT_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_resident_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombijumpup",1,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombipenetration",2,2,3);
					break;
				}
				case GANYMEDE_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_ganymede_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_rush",1,2,3);
					break;
				}
				break;
			}
		}
		case 11:
		{
			DrawRetinaReset();			
			switch (iData)
			{
				case BOMMER_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_boomer_zombi",0,2,3);
					//ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombiheal",1,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombiguard",2,2,3);
					break;
				}
				case RESIDENT_ZB:
				{
					g_zb3_top_show_type = 0;
					ZombieMod3UIParseIcon("resource\\hud\\zombie\\zombietype_resident_zombi",0,2,3);
					ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombijumpup",1,2,3);
					//ZombieMod3UIParseIcon("mode\\zb3\\zombieskill_zombipenetration",2,2,3);
					break;
				}
			}
			break;
		}
		case 12:
		{
			g_zb_nvg = iData;
			break;
		}
		case 13:
		{
			struct model_s *pModel;
			cl_entity_t *pEntity = NULL;
			TEMPENTITY *pEnt;

			int id = iData;
			pEntity = gEngfuncs.GetEntityByIndex(id);
			if(!pEntity) return;			

			pModel = IEngineStudio.Mod_ForName("sprites/zb_meleeup.spr", 0);
			
			pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(pEntity->origin, pModel);
			pEnt->entity.curstate.rendermode = kRenderTransAdd;
			pEnt->entity.curstate.renderamt = 254;
			pEnt->entity.curstate.scale = 1.0;
			pEnt->entity.curstate.aiment = id;

			pEnt->die = g_flTime +8.0f;

			pEnt->flags |= FTENT_CLIENTCUSTOM;
			pEnt->callback = ZB3SkillIconCallback;

			Engfunc_Call_AddVisibleEntity( &(pEnt->entity));


			gEngfuncs.pEventAPI->EV_PlaySound(id, pEntity->origin, CHAN_ITEM, "sound/bte/item/speedup.wav", 1.0, 0.8, 0, 100);
			break;
		}
		case 14:
		{
			struct model_s *pModel;
			cl_entity_t *pEntity = NULL;
			TEMPENTITY *pEnt;

			int id = iData;
			pEntity = gEngfuncs.GetEntityByIndex(id);
			if(!pEntity) return;

			pModel = IEngineStudio.Mod_ForName("sprites/zb_skill_headshot.spr", 0);
			pEnt = gEngfuncs.pEfxAPI->CL_TempEntAllocHigh(pEntity->origin, pModel);
			pEnt->entity.curstate.rendermode = kRenderTransAdd;
			pEnt->entity.curstate.renderamt = 254;
			pEnt->entity.curstate.scale = 1.0;
			pEnt->entity.curstate.aiment = id;

			pEnt->die = g_flTime +4.0f;

			pEnt->flags |= FTENT_CLIENTCUSTOM;
			pEnt->callback = ZB3SkillIconCallback;

			Engfunc_Call_AddVisibleEntity( &(pEnt->entity));

			

			gEngfuncs.pEventAPI->EV_PlaySound(id, pEntity->origin, CHAN_ITEM, "sound/bte/item/speedup.wav", 1.0, 0.8, 0, 100);
			break;
		}
		case 15:
		{
			g_iHookVAngle = iData;
			memset(g_vecVAngle, 0, sizeof(g_vecVAngle));
			if(!iData)
				gEngfuncs.pfnClientCmd("-duck;");
			break;
		}
		case 16:
		{
			g_iShowCustomCrosshair = iData;

			if(iData)
			{
				g_iHideWeapon |= HIDEWEAPON_CROSSHAIR;
			}
			else
			{
				g_iHideWeapon &= ~HIDEWEAPON_CROSSHAIR;
			}
			break;
		}
		case 17:
		{
			cl_entity_t *pEntity = NULL;

			int id = iData;
			pEntity = gEngfuncs.GetEntityByIndex(id);
			if(!pEntity) return;

			gEngfuncs.pEventAPI->EV_PlaySound(id, pEntity->origin, CHAN_ITEM, "sound/bte/item/speedup.wav", 1.0, 0.8, 0, 100);
			break;
		}
	}
}
void ZombieMod3UIInit(void)
{
	g_zb3_item[0][0] = GetSpriteIndex("zb3_ammoup");
	g_zb3_item[0][1] = GetSpriteIndex("zb3_arup");
	g_zb3_item[1][0] = GetSpriteIndex("zb3_jumphigher");
	g_zb3_item[1][1] = GetSpriteIndex("zb3_hpup");
	g_zb3_item[2][0] = GetSpriteIndex("zb3_highmorale");
	g_zb3_item[2][1] = GetSpriteIndex("zb3_fastrespawn");
	
	g_zb3_spr_morale_icon = GetSpriteIndex("ZB3_MoraleIcon");
	g_zb3_spr_morale_level = GetSpriteIndex("ZB3_MoraleLevel");
	g_zb3_spr_morale_effect = GetSpriteIndex("ZB3_MoraleEffect");
	g_zb3_spr_morale_effect2 = GetSpriteIndex("ZB3_MoraleEffect2");
	g_zb3_spr_supply = GetSpriteIndex("radar_item");
	g_zb3_spr_rage_level = GetSpriteIndex("ZB3_RageLevel");
	g_zb3_spr_rage_bg = GetSpriteIndex("ZB3_RageBg");
	g_zb3_spr_rage_index = GetSpriteIndex("ZB3_RageEffect000");	

	memset(UISlot,0,sizeof(UISlot));
	for(int i=1;i<7;i++)
	{
		char szSpr[32];
		sprintf(szSpr,"sprites/rage%d.spr",i);
		g_zb3_hspr_rage[i-1] = gEngfuncs.pfnSPR_Load(szSpr);
	}
	g_zb3_retina_draw = 0;
	g_zb3_retina_class = 0;
	g_zb3_retina_start = 0;

	g_zb3_retina[0] = DrawTgaGetID("mode\\zb3\\retina_zombicrazy");
	g_zb3_retina[6] = DrawTgaGetID("mode\\zb3\\retina_damagedouble");
	g_zb3_retina[4] = DrawTgaGetID("mode\\zb3\\retina_zombiheal");
	g_zb3_retina[3] = DrawTgaGetID("mode\\zb3\\retina_zombispeedup");
	g_zb3_retina[2] = DrawTgaGetID("mode\\zb3\\retina_zombihide");

	g_zb3_tga_keyslot_bg = FindTexture("resource\\hud\\zombie\\skillslotkeybg");
	g_zb3_tga_skullslot_bg = FindTexture("resource\\hud\\zombie\\skillslotbg");
	g_zb3_tga_hs_hs = DrawTgaGetID("mode\\zb3\\humanskill_hm_hd");
	g_zb3_tga_hs_spd = DrawTgaGetID("mode\\zb3\\humanskill_hm_spd");
	g_zb3_tga_hs_kni = DrawTgaGetID("mode\\zb3\\humanskill_hm_2x");
	//g_zb3_tga_zs_zombicrazy = DrawTgaGetID("mode\\zb3\\zombieskill_zombicrazy");

	g_zb3_tga_icon_hero = FindTexture("resource\\hud\\icon\\hero_s");
	g_zb3_tga_icon_supply = FindTexture("resource\\hud\\icon\\supplybox");
	g_zb3_tga_icon_trap = FindTexture("resource\\hud\\icon\\trap_s");

	g_zb3_tga_hs[1] = g_zb3_tga_hs_spd;
	g_zb3_tga_hs[2] = g_zb3_tga_hs_hs;
	g_zb3_tga_hs[3] = g_zb3_tga_hs_kni;

	g_zb3_class = CLASS_HM;
	g_zb3_rage = -1;
	g_zb3_morale = 0;
	g_zb3_morale_int = 100;
	g_zb3_rage_percent = 0;

	g_zb3_timer_rage = 0;
	g_zb3_frame_rage = 0;
	g_zb3_zombietga_index=FindTexture("resource\\hud\\zombie\\zombietype_defaultzb");

	memset(g_zb3_menu_zb,0,sizeof(g_zb3_menu_zb));
	if(!zb3_iBinkTextureID) zb3_iBinkTextureID = g_pSurface->CreateNewTextureID();
}
void ZombieMod3RetinaRedraw(void)
{
	if(!g_zb3_retina_draw) return;
	if(!g_zb3_retina_class) return;
	//if(g_zb3_class != CLASS_ZB) return;
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	Tri_AlphaFunc(GL_GREATER, 0.0);
	switch (g_zb3_retina_class)
	{
	case 1:
		{
				Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_retina[g_zb3_retina_class-1]].texid);
				float alpha;
				float fSubTime = g_flTime;
				fSubTime -=(int)fSubTime;
				fSubTime-=0.5;
				fSubTime=fabsf(fSubTime);	
				alpha =fSubTime+0.5;
				alpha *= 255;
				if(g_iVideoMode) glColor4ub(255,255,255,alpha);
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
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_retina[g_zb3_retina_class-1]].texid);
				float alpha;
				if(g_flTime-g_zb3_retina_start<1.0)
				{
					alpha = g_flTime-g_zb3_retina_start;
				}
				else
				{
					g_zb3_retina_draw = 0;
					break;
				}
				alpha *= 255;
				if(g_iVideoMode) glColor4ub(255,255,255,alpha);
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
	case 3:
	case 4:		
	case 5:
		{
				Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_retina[g_zb3_retina_class-1]].texid);
				float alpha = 255;
				/*float fSubTime = g_flTime;
				fSubTime -=(int)fSubTime;
				fSubTime-=0.5;
				fSubTime=fabsf(fSubTime);	
				alpha =fSubTime+0.5;
				alpha *= 255;*/
				if(g_iVideoMode) glColor4ub(255,255,255,alpha);
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
	case 6:
	case 7:
		{
				Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_retina[g_zb3_retina_class-1]].texid);
				float alpha;
				
				if(g_zb3_retina_class==3||g_zb3_retina_class==7||g_zb3_retina_class==4)
				{
					float fSubTime = g_flTime;
					fSubTime -=(int)fSubTime;
					fSubTime-=0.5;
					fSubTime=fabsf(fSubTime);	
					alpha =fSubTime+0.5;
				}
				else
				{
					if(g_flTime-g_zb3_retina_start<1.0)
					{
						alpha = g_flTime-g_zb3_retina_start;
					}
					else
					{
						g_zb3_retina_draw = 0;
						break;
					}
				}
				alpha *= 255;
				float fX = 0.05f;
				float fY = 0.95f;
				if(g_iVideoMode) glColor4ub(255,255,255,alpha);
				else gEngfuncs.pTriAPI->Color4ub(255,255,255,alpha);

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
#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif
void ZombieMod3UIRedraw(void)
{
	if(g_iMod != MOD_ZB3) return;
	if(!g_bAlive) return;
	int iLocal = gEngfuncs.GetLocalPlayer()->index;
	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_Enable(GL_ALPHA_TEST);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 
	// 视网膜
	ZombieMod3RetinaRedraw();

	for(int i=0;i<=2;i++)
	{
		if(1<<i & g_zb3_item_bit)
		{
			gEngfuncs.pTriAPI->RenderMode(kRenderNormal);
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_item[i][g_zb3_class == CLASS_ZB]), 254, 196, 168);
			gEngfuncs.pfnSPR_DrawAdditive(0, 6, g_sScreenInfo.iHeight * 0.28 + 50 * i + 30, &GetSpriteRect(g_zb3_item[i][g_zb3_class == CLASS_ZB]));
		}
	}

	// 英雄图标
	for(int i=1 ;i<33;i++)
	{
		if(vPlayer[i].iHero && i!=iLocal)
		{
			float vecScreen[2];
			
			//gEngfuncs.pTriAPI->WorldToScreen(vPlayer[i].info->origin,vecScreen);
			cl_entity_s *p ;
			p = gEngfuncs.GetEntityByIndex(i);

			if(!p) continue;			
			if(CalcScreen(p->origin, vecScreen))
			{
				
				
				/*Tri_Enable(GL_TEXTURE_2D);
				Tri_BindTexture(GL_TEXTURE_2D,g_MHTga[g_zb3_tga_icon_hero].texid);
				glColor4f(1,1,1,1);
				Tri_Enable(GL_BLEND);
				Tri_Enable(GL_ALPHA_TEST);
				Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); 

				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1]+g_MHTga[g_zb3_tga_icon_hero].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_zb3_tga_icon_hero].width,vecScreen[1]+g_MHTga[g_zb3_tga_icon_hero].height,0);		
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0]+g_MHTga[g_zb3_tga_icon_hero].width,vecScreen[1],0);		
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(vecScreen[0],vecScreen[1],0);
				gEngfuncs.pTriAPI->End();*/

				Vector vOriDis;

				VectorSubtract(gEngfuncs.GetLocalPlayer()->origin,p->origin,vOriDis);
				float distance = sqrt(vOriDis.x*vOriDis.x+vOriDis.y*vOriDis.y+vOriDis.z*vOriDis.z)/40.0f;
				if (distance < 50.0)
				{
					MH_DrawTGAFunction(g_Texture[g_zb3_tga_icon_hero].iTexture,255,255,255,255,vecScreen[0] - g_Texture[g_zb3_tga_icon_hero].iWidth / 2,vecScreen[1] - g_Texture[g_zb3_tga_icon_hero].iHeight / 2,1.0);
					
					char p1[256];
					wchar_t p2[256];
					sprintf(p1,"[%dm]",(short int)distance);

					Fonts_C2W(p2,255,p1);
					Fonts_SetColor(186,164,255,255);
					Fonts_SetSize(16,16);
					int a = g_Texture[g_zb3_tga_icon_hero].iWidth /2;
					Fonts_Draw(p2,int(vecScreen[0] - Fonts_GetLen(p2) / 2 - 2),vecScreen[1]+60 - g_Texture[g_zb3_tga_icon_hero].iHeight / 2,100,100);
				}
			}
		}
	}

	if(g_zb3_class == CLASS_HM || g_zb3_class == CLASS_HERO)
	{
		// 士气等级
		// 符号
		int iX,iY;
		iX = g_sScreenInfo.iWidth/2;
		iX -= 100;
		if(g_zb3_morale_up) iX -= 30;
		//iY = 390/*g_sScreenInfo.iHeight * 0.86*/;

		//int yoffset = g_sScreenInfo.iHeight * 0.14;

		iY = g_sScreenInfo.iHeight - 100;//max(90,yoffset);
		if(g_zb3_morale_int == 100)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),0,177,0);
			Fonts_SetColor(0,177,0,255);
		}
		if(g_zb3_morale_int == 110)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),0,177,0);
			Fonts_SetColor(0,177,0,255);
		}
		if(g_zb3_morale_int == 120)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),0,177,0);
			Fonts_SetColor(0,177,0,255);
		}
		if(g_zb3_morale_int == 130)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),0,177,0);
			Fonts_SetColor(0,177,0,255);
		}
		if(g_zb3_morale_int == 140)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),137,191,20);
			Fonts_SetColor(137,191,20,255);
		}
		if(g_zb3_morale_int == 150)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),137,191,20);
			Fonts_SetColor(137,191,20,255);
		}
		if(g_zb3_morale_int == 160)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),250,229,0);
			Fonts_SetColor(250,229,0,255);
		}
		if(g_zb3_morale_int == 170)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),250,229,0);
			Fonts_SetColor(250,229,0,255);
		}
		if(g_zb3_morale_int == 180)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),243,127,1);
			Fonts_SetColor(243,127,1,255);
		}
		if(g_zb3_morale_int == 190)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),243,127,1);
			Fonts_SetColor(243,127,1,255);
		}
		if(g_zb3_morale_int == 200)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),255,3,0);
			Fonts_SetColor(255,3,0,255);
		}
		if(g_zb3_morale_int == 210)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),127,40,208);
			Fonts_SetColor(127,40,208,255);
		}
		if(g_zb3_morale_int == 220)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),127,40,208);
			Fonts_SetColor(127,40,208,255);
		}
		if(g_zb3_morale_int == 230)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_icon),127,40,208);
			Fonts_SetColor(127,40,208,255);
		}
		//gEngfuncs.pfnSPR_DrawAdditive(g_zb3_spr_morale_icon,iX,iY,&GetSpriteRect(g_zb3_spr_morale_icon));
		gEngfuncs.pfnSPR_DrawAdditive(0,iX,iY,&GetSpriteRect(g_zb3_spr_morale_icon));
		// 效果 200%
		/*if(g_zb3_morale_int == 200 && !g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect),255,255,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect));
		}*/
		if(g_zb3_morale_int == 200 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect),255,255,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect));
		}
		if(g_zb3_morale_int == 210 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect2),127,40,208);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect2));
		}
		if(g_zb3_morale_int == 220 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect2),127,40,208);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect2));
		}
		if(g_zb3_morale_int == 230 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect2),127,40,208);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect2));
		}
		/*if(g_zb3_morale_int == 210 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect2),255,0,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect2));
		}
		if(g_zb3_morale_int == 220 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect2),255,0,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect2));
		}
		if(g_zb3_morale_int == 230 && g_zb3_morale_up)
		{
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_effect2),255,0,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX-17,iY-16,&GetSpriteRect(g_zb3_spr_morale_effect2));
		}*/
		iX += 53;
		iY += 13;	
		static wrect_t *TempRect = &GetSpriteRect(g_zb3_spr_morale_level);
		wrect_t ModifyRect;
		ModifyRect.bottom = TempRect->bottom;
		ModifyRect.left = TempRect->left;
		ModifyRect.right = TempRect->right;
		ModifyRect.top = TempRect->top;
		int iLen = TempRect->right - ModifyRect.left;
		if(!g_zb3_morale_up) iLen =iLen / 1.3;
		ModifyRect.right = iLen + ModifyRect.left;
		// 背景条
		gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_level),50,50,50);
		//gEngfuncs.pfnSPR_DrawAdditive(g_zb3_spr_morale_level,iX,iY,&ModifyRect);
		gEngfuncs.pfnSPR_DrawAdditive(0,iX,iY,&ModifyRect);

		// 当前条
		if(g_zb3_morale!=0)
		{
			iLen = TempRect->right - ModifyRect.left;
			iLen = iLen * g_zb3_morale;
			if(!g_zb3_morale_up) iLen = iLen / 1.3;
			ModifyRect.right = iLen + ModifyRect.left;
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_morale_level),255,255,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX,iY,&ModifyRect);
		}

		// 汉字
		Fonts_SetSize(16,16);
		iX += 00;
		iY -= 18; 
		char p1[256];
		char *pTemp = GetLangUtf("CSBTE_ZB3_ATTACK");
		sprintf(p1,"%s%d%%",pTemp,g_zb3_morale_int);
		Fonts_Draw(UTF8ToUnicode(p1),iX,iY,1000,100);;
	}
	else if(g_zb3_class == CLASS_ZB)
	{
		// 背景
		int iX,iY;
		iX = g_sScreenInfo.iWidth/2 - gEngfuncs.pfnSPR_Width(GetSprite(g_zb3_spr_rage_bg), 0) / 2;
		iY = g_sScreenInfo.iHeight*0.97 - gEngfuncs.pfnSPR_Height(GetSprite(g_zb3_spr_rage_bg), 0) / 2;

		gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_rage_bg), 255, 255, 255);
		gEngfuncs.pfnSPR_DrawAdditive(0, iX, iY, &GetSpriteRect(g_zb3_spr_rage_bg));

		// 动态头像
		if(g_zb3_timer_rage < g_flTime)
		{
			g_zb3_timer_rage = g_flTime + 0.1;
			g_zb3_frame_rage ++;
			if(g_zb3_frame_rage>7) g_zb3_frame_rage = 0;
		}
		if(g_zb3_rage != -1)
		{
			int iRageIndex = 8*g_zb3_rage+g_zb3_frame_rage;
			gEngfuncs.pfnSPR_Set( g_zb3_hspr_rage[(iRageIndex/4)], 255, 255, 255);
			gEngfuncs.pfnSPR_DrawAdditive(0, iX, iY-3, &GetSpriteRect(iRageIndex+g_zb3_spr_rage_index));
		}
		// 怒气槽
		// 背景条
		iX += 76;
		iY += 50;
		gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_rage_level),50,50,50);
		//gEngfuncs.pfnSPR_DrawAdditive(g_zb3_spr_rage_level,iX,iY,&GetSpriteRect(g_zb3_spr_rage_level));
		gEngfuncs.pfnSPR_DrawAdditive(0,iX,iY,&GetSpriteRect(g_zb3_spr_rage_level));
		// 当前条
		if(g_zb3_rage_percent!=0)
		{
			static wrect_t *TempRect = &GetSpriteRect(g_zb3_spr_rage_level);
			wrect_t ModifyRect;
			ModifyRect.bottom = TempRect->bottom;
			ModifyRect.left = TempRect->left;
			ModifyRect.right = TempRect->right;
			ModifyRect.top = TempRect->top;
			int iLen = ModifyRect.right - ModifyRect.left;
			iLen = iLen * g_zb3_rage_percent + 1;
			ModifyRect.right = iLen + ModifyRect.left;
			gEngfuncs.pfnSPR_Set(GetSprite(g_zb3_spr_rage_level),255,255,255);
			gEngfuncs.pfnSPR_DrawAdditive(0,iX,iY,&ModifyRect);
		}
	}
	
	// BINK背景选择
	static HBINK zb3_hBink;
	static int zb3_iPlaying = 0;
	static float zb3_fStartTime = 0;
	static int zb3_iFrame = 0;

	if(g_zb3_menu_time > g_flTime)
	{
		g_isShowingZbMenu = 1;
		if(pCvar_ZombieMenu->value)
		{
		
		if(!zb3_iPlaying)
		{
			if(pZombieSelectBinkMem) free(pZombieSelectBinkMem);
			zb3_hBink = BinkOpen("metahook\\bik\\zbselectbg.bik",135266304);
			if(!zb3_hBink)
			{
				LogToFile("[Bink]ZB3加载BIK文件失败");
				return;
			}
			int iPixelSize = 4 * zb3_hBink->Width * zb3_hBink->Height;
			pZombieSelectBinkMem = (BYTE *)malloc(iPixelSize);
			zb3_fStartTime = 0;
			zb3_iFrame = 1;
			zb3_iPlaying = 1;
		}
		if(!zb3_iPlaying) return;
		if(g_flTime - zb3_fStartTime > ( float(zb3_hBink->FrameRateDiv)/ float(zb3_hBink->FrameRate))) 
		{ 
			zb3_iFrame ++;
			zb3_fStartTime = g_flTime;
			if(zb3_iFrame> (int)zb3_hBink->Frames)
			{
				zb3_iFrame = 1;
			}
			BinkGoto(zb3_hBink, zb3_iFrame, 0);
			BinkDoFrame(zb3_hBink);
			BinkCopyToBuffer(zb3_hBink, pZombieSelectBinkMem, zb3_hBink->Width * 4, zb3_hBink->Height, 0, 0, BINKSURFACE32RA);
			g_pSurface->DrawSetTextureRGBA(zb3_iBinkTextureID,pZombieSelectBinkMem,zb3_hBink->Width, zb3_hBink->Height,1,true);
		}
		int iX =0,iY=g_sScreenInfo.iHeight-40 - zb3_hBink->Height,iWidth,iHeight;
		iWidth = zb3_hBink->Width;
		iHeight = zb3_hBink->Height;



		Tri_Enable(GL_TEXTURE_2D);
		Tri_Enable(GL_BLEND);
		Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
		g_pSurface->DrawSetTexture(zb3_iBinkTextureID);
		g_pSurface->DrawTexturedRect(iX,iY,iX+iWidth,iY+iHeight);

		/*Tri_BindTexture(GL_TEXTURE_2D, zb3_iBinkTextureID);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY+iHeight,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iX+iWidth,iY+iHeight,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iX+iWidth,iY,0);
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
		gEngfuncs.pTriAPI->End();*/

		iX = 60;
		Fonts_SetColor(255,255,255,222);
		Fonts_SetSize(16,16);
		Fonts_Draw(GetLangUni("CSBTE_ZOMBIE_SELECT"),iX,iY+45,100,100);
		char p[128];
		//sprintf(p,"%s%d%s",GetLangUtf("CSBTE_REMAINING"),int(g_zb3_menu_time - g_flTime)+1,GetLangUtf("CSBTE_SECOUNDS"));
		sprintf(p,"%s%d",GetLangUtf("CSBTE_REMAINING"),int(g_zb3_menu_time - g_flTime)+1);
		sprintf(p,"%s%s",p,GetLangUtf("CSBTE_SECOUNDS"));

		Fonts_Draw(UTF8ToUnicode(p),iX,iY+65,100,100);

		for(int i = 1;i<11;i++)
		{
			int iLine,iCol,iX,iY;
			if(i % 2 == 0)
			{
				iLine = i / 2 - 1;
			}
			else iLine = i / 2;
			iCol = (i+1)%2;
			iY = g_sScreenInfo.iHeight-40 - zb3_hBink->Height;
			iX = 24 + 69 * iCol;
			iY += (80 + 59 * iLine);
			int iHeight = 54;
			int iWidth = 63;


			if(g_zb3_menu_zb[i-1])
			{
						
			char p[3];
			sprintf(p,"%d.",i%10);
			Fonts_SetSize(15,15);
			Fonts_Draw(UTF8ToUnicode(p),iX+4,iY+15,100,100);

			MH_DrawTGAFunction(g_Texture[g_zb3_menu_zb[i-1]].iTexture,255,255,255,255,iX,iY,1.0);

			/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_menu_zb[i-1]].texid);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY+iHeight,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iX+iWidth,iY+iHeight,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iX+iWidth,iY,0);
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
			gEngfuncs.pTriAPI->End();*/
			}
		}
		}

	}
	else
	{		
		if(g_isShowingZbMenu) g_Menu_Drawing = 0;
		g_isShowingZbMenu = 0;
	}// if(zb3_hBink) BinkClose(zb3_hBink);
	// 上方技能栏
	Tri_Enable(GL_TEXTURE_2D);
	Tri_Enable(GL_BLEND);
	Tri_BlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

	if(g_zb3_class == CLASS_HM || g_zb3_class == CLASS_HERO)
	{
		int iX,iY;
		iY = max(g_sScreenInfo.iHeight * 0.0716, 50);
		iX = g_sScreenInfo.iWidth/2 - g_Texture[g_zb3_tga_skullslot_bg].iWidth/2;
		MH_DrawTGAFunction(g_Texture[g_zb3_tga_skullslot_bg].iTexture,255,255,255,255,iX,iY,1.0);
		/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_tga_skullslot_bg].texid);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[g_zb3_tga_skullslot_bg].height,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_skullslot_bg].width,iY+g_MHTga[g_zb3_tga_skullslot_bg].height,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_skullslot_bg].width,iY,0);
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
		gEngfuncs.pTriAPI->End();*/

		for(int i=1;i<5;i++)
		{			
			int r = UISlot[i].r;
			int g = UISlot[i].g;
			int b = UISlot[i].b;
			int a = UISlot[i].a;

			if(UISlot[i].iType == 1 || UISlot[i].iType == 4)
			{
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[UISlot[i].iMH].texid);
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY,0);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
				gEngfuncs.pTriAPI->End();
			}
			else if(UISlot[i].iType == 2)
			{
				float fSubTime = UISlot[i].flEndDisplayTime-g_flTime;
				if(fSubTime<0)
				{
					UISlot[i].iType = 1;
					continue;
				}
				fSubTime -=(int)fSubTime;
				fSubTime -= 0.5;
				fSubTime=fabsf(fSubTime);
				a = fSubTime * 510;
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[UISlot[i].iMH].texid);
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY,0);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
				gEngfuncs.pTriAPI->End();
			}
			else if(UISlot[i].iType == 3)
			{
				float NeedDisplay = UISlot[i].flEndDisplayTime-UISlot[i].flStartDisplayTime;
				float Displayed = g_flTime - UISlot[i].flStartDisplayTime;
				float fPercent = Displayed / NeedDisplay;
				if(fPercent>1.0)
				{
					UISlot[i].flEndDisplayTime = g_flTime + 3.0;
					UISlot[i].flStartDisplayTime = g_flTime;
					UISlot[i].iType = 2;
					continue;
				}
				r = 255;
				g = b = 0;
				a = 255;
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[UISlot[i].iMH].texid);
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
				gEngfuncs.pTriAPI->TexCoord2f(0,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);

				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY,0);
				gEngfuncs.pTriAPI->End();
				r = 255;
				g = 255;
				b = 191; 
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);
				gEngfuncs.pTriAPI->End();
			}
			//
			iY-=3;
			iX -= 2;
			MH_DrawTGAFunction(g_Texture[g_zb3_tga_keyslot_bg].iTexture,255,255,255,255,iX,iY,1.0);
			/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_tga_keyslot_bg].texid);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[g_zb3_tga_keyslot_bg].height,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_keyslot_bg].width,iY+g_MHTga[g_zb3_tga_keyslot_bg].height,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_keyslot_bg].width,iY,0);
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
			gEngfuncs.pTriAPI->End();*/
			iY+=3;
			iX += 2;
			char p[2];
			sprintf(p,"%d",i+4);
			Fonts_SetColor(255,255,255,140);
			Fonts_SetSize(14,14);
			Fonts_Draw(UTF8ToUnicode(p),iX+7,iY+10,100,100);
			iX = iX + g_MHTga[g_zb3_tga_hs[i]].width + 4;
		}
	}
	else if(g_zb3_class == CLASS_ZB)
	{
		int iX,iY;
		iY = 55;
		iX = g_sScreenInfo.iWidth/2 - g_Texture[g_zb3_tga_skullslot_bg].iWidth/2;
		iX -= 35; // from pic size
		//先画头像
		MH_DrawTGAFunction(g_Texture[g_zb3_zombietga_index].iTexture,255,255,255,255,iX,iY,1.0);
		/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_zombietga_index].texid);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[g_zb3_zombietga_index].height,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_zombietga_index].width,iY+g_MHTga[g_zb3_zombietga_index].height,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_zombietga_index].width,iY,0);
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
		gEngfuncs.pTriAPI->End();*/
		iX += 70;
		// 再画按键
		MH_DrawTGAFunction(g_Texture[g_zb3_tga_skullslot_bg].iTexture,255,255,255,255,iX,iY,1.0);
		/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_tga_skullslot_bg].texid);
		gEngfuncs.pTriAPI->Begin(TRI_QUADS);
		gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
		gEngfuncs.pTriAPI->TexCoord2f(0,1);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[g_zb3_tga_skullslot_bg].height,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,1);
		gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_skullslot_bg].width,iY+g_MHTga[g_zb3_tga_skullslot_bg].height,0);
		gEngfuncs.pTriAPI->TexCoord2f(1,0);
		gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_skullslot_bg].width,iY,0);
		gEngfuncs.pTriAPI->TexCoord2f(0,0);
		gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
		gEngfuncs.pTriAPI->End();*/
		for(int i=1;i<5;i++)
		{
			int r = UISlot[i].r;
			int g = UISlot[i].g;
			int b = UISlot[i].b;
			int a = UISlot[i].a;

			if(UISlot[i].iType == 1 || UISlot[i].iType == 4)
			{
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[UISlot[i].iMH].texid);
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY,0);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
				gEngfuncs.pTriAPI->End();
			}
			else if(UISlot[i].iType == 2)
			{
				float fSubTime = UISlot[i].flEndDisplayTime-g_flTime;
				if(fSubTime<0)
				{
					UISlot[i].iType = 1;
					continue;
				}
				fSubTime -=(int)fSubTime;
				fSubTime -= 0.5;
				fSubTime=fabsf(fSubTime);
				a = fSubTime * 510;
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[UISlot[i].iMH].texid);
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY,0);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
				gEngfuncs.pTriAPI->End();
			}
			else if(UISlot[i].iType == 3)
			{
				float NeedDisplay = UISlot[i].flEndDisplayTime-UISlot[i].flStartDisplayTime;
				float Displayed = g_flTime - UISlot[i].flStartDisplayTime;
				float fPercent = Displayed / NeedDisplay;
				if(fPercent>1.0)
				{
					UISlot[i].flEndDisplayTime = g_flTime + 3.0;
					UISlot[i].flStartDisplayTime = g_flTime;
					UISlot[i].iType = 2;
					continue;
				}
				r = 207;
				g = 168;
				b = 173;
				a = 255;
				Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[UISlot[i].iMH].texid);
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,0);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
				gEngfuncs.pTriAPI->TexCoord2f(0,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);

				gEngfuncs.pTriAPI->TexCoord2f(1,0);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY,0);
				gEngfuncs.pTriAPI->End();
				r = 255;
				g = 255;
				b = 191; 
				if(g_iVideoMode) glColor4ub(r,g,b,a);
				else gEngfuncs.pTriAPI->Color4ub(r,g,b,a);
				gEngfuncs.pTriAPI->Begin(TRI_QUADS);
				gEngfuncs.pTriAPI->TexCoord2f(0,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);
				gEngfuncs.pTriAPI->TexCoord2f(0,1);
				gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height,0);
				gEngfuncs.pTriAPI->TexCoord2f(1,1-fPercent);
				gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[UISlot[i].iMH].width,iY+g_MHTga[UISlot[i].iMH].height* (1.0-fPercent),0);
				gEngfuncs.pTriAPI->End();
			}
			//
			iY-=3;
			iX -= 2;
			MH_DrawTGAFunction(g_Texture[g_zb3_tga_keyslot_bg].iTexture,255,255,255,255,iX,iY,1.0);
			/*Tri_BindTexture(GL_TEXTURE_2D, g_MHTga[g_zb3_tga_keyslot_bg].texid);
			gEngfuncs.pTriAPI->Begin(TRI_QUADS);
			gEngfuncs.pTriAPI->Color4ub(255,255,255,255);
			gEngfuncs.pTriAPI->TexCoord2f(0,1);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY+g_MHTga[g_zb3_tga_keyslot_bg].height,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,1);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_keyslot_bg].width,iY+g_MHTga[g_zb3_tga_keyslot_bg].height,0);
			gEngfuncs.pTriAPI->TexCoord2f(1,0);
			gEngfuncs.pTriAPI->Vertex3f(iX+g_MHTga[g_zb3_tga_keyslot_bg].width,iY,0);
			gEngfuncs.pTriAPI->TexCoord2f(0,0);
			gEngfuncs.pTriAPI->Vertex3f(iX,iY,0);
			gEngfuncs.pTriAPI->End();*/
			Fonts_SetColor(255,255,255,170);
			Fonts_SetSize(14,14);
			if(i == 1)
			{
				Fonts_Draw(L"G",iX+10,iY+12,100,140);
			}
			else if(i == 2)
			{
				Fonts_Draw(g_zb3_top_show_type?L"R":L"5",iX+10,iY+12,100,100);
			}
			else if(i == 3)
			{
				Fonts_Draw(L"6",iX+10,iY+12,100,100);
			}
			else if(i == 4)
			{
				Fonts_Draw(L"7",iX+10,iY+12,100,100);
			}
			iY+=3;
			iX += 2;
			iX = iX + g_MHTga[g_zb3_tga_hs[i]].width + 4;
		}
	}
}
