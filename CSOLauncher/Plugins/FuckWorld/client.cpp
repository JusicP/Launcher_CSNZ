#include "base.h"
#include "BaseUI.h"
#include "r_efx.h"
#include "studio_event.h"
#include "studio.h"

int g_iButton = 0;
int g_iBTEWeapon = 0;
char g_szCurWeapon[32];
wchar_t g_szCurWeapon2[64];
int g_iCurWeapon;
int g_iWeaponStat = 0;
int g_iBl3Muzz = 10;
int g_iSpoce = 0;

PlayerInfo vPlayer[36];
extra_player_info_t  g_PlayerExtraInfo[MAX_PLAYERS+1];

char g_szLocation[2048];
bool g_bAlive;
int g_iWeapon, g_iWeaponBit, g_iHideWeapon;
SCREENINFO g_sScreenInfo;
Vector g_vecOrigin, g_vecAngles, g_vecEyePos,g_vecVAngles;
Vector g_vecEye;
Vector g_vecEndPos;
int g_iViewEntityBody, g_iViewEntityRenderMode, g_iViewEntityRenderFX, g_iViewEntityRenderAmout;
color24 g_byViewEntityRenderColor;
cvar_t *pCvar_TipIcon,*pCvar_Blood,*pCvar_Name,*pCvar_DrawBink,*pCvar_DrawPanel,*pCvar_DrawScope,*pCvar_ScoreBoard,*pCvar_DrawMenu,*pCvar_ZombieMenu;
cvar_t *cl_righthand;
cvar_t *cl_dynamiccrosshair;
cvar_t *cl_crosshair_color;
cvar_t *cl_crosshair_size;
cvar_t *cl_crosshair_translucent;
cvar_t *cl_crosshair_type;
cvar_t *cl_gunsmoke;
char g_sTattoo[128];
int g_iTattooTex[2][3];
int g_iTattooSet_f;
int g_iTattooSet_m;
char g_sTattooSmall[128];
int g_iTattooSmallTex[2][3];
int g_iTattooSmallEnable = 0;
int g_iCountBg;
float g_fMuzzleTime;
char g_szWeaponSkin[20][20];
int g_iWeaponSkin[20][2];
int g_iSetupSkin = 0;
int g_tga_Scope = 0;
int g_tga_Scope_Target = 0;
int g_tga_custom_scope = 0;
int g_tga_custom_scope_m200 = 0;

char texture[512];
void LoadTattoo(void)
{
	char name[128];
	char *sex[6] = { "male", "female"};
	char *type[3] = {"long","short"};
	for(int i=0;i<2;i++)
	{
		for(int j=0;j<2;j++)
		{
			sprintf(name,"tattoo\\%s_%s_%s",g_sTattoo,sex[i],type[j]);
			
			g_iTattooTex[i][j] = DrawTgaGetID(name);
			if(g_sTattooSmall[0])
			{
				sprintf(name,"tattoo\\%s_%s_%s",g_sTattooSmall,sex[i],type[j]);
				g_iTattooSmallTex[i][j] = DrawTgaGetID(name);
			}
		}
	}
	sprintf(name,"tattoo\\%s_%s_%s",g_sTattoo,"male","origin");
	g_iTattooTex[SEX_MALE][HAND_ORIGIN] = DrawTgaGetID(name);
	sprintf(name,"tattoo\\%s_%s_%s",g_sTattooSmall,"male","origin");
	g_iTattooSmallTex[SEX_MALE][HAND_ORIGIN] = DrawTgaGetID(name);	
}
void RebuildTattoo(model_t *pModel)
{
	// Rebuild Skin
	int iCheck = 0;
	if(pModel && pModel->name)
	{
		for(int i =1;i<21;i++)
		{
			if(strlen(g_szWeaponSkin[i]) && strstr(pModel->name,g_szWeaponSkin[i]))
			{
				/*if(g_iWeaponSkin[i][0])
				{
					iCheck = 1;
					break;
				}
				else if(g_iWeaponSkin[i][1])
				{
					iCheck = 2;
					break;
				}
				else if(g_iWeaponSkin[i][2])
				{
					iCheck = 0;
					break;
				}*/
				iCheck = g_iWeaponSkin[i][1];
			}
		}
	}
	g_iSetupSkin = iCheck;
	if(pModel)
	{ 
		studiohdr_t	*pstudio;
		mstudiotexture_t	*ptexture;
		pstudio = (studiohdr_t*)IEngineStudio.Mod_Extradata(pModel);
		if( !pstudio ) return ;
		ptexture = (mstudiotexture_t *)(((byte *)pstudio) + pstudio->textureindex);	
		for(int i = 0; i < pstudio->numtextures; i++ )
		{		
			
			if(ptexture[i].name[0] == '@')
			{
				sprintf(texture,"texture\\%s",ptexture[i].name);
				int tid = DrawTgaGetID(texture);
				if (tid ==0) continue;
				ptexture[i].index = g_MHTga[tid].texid;
				ptexture[i].height = g_MHTga[tid].height;
				ptexture[i].width = g_MHTga[tid].width;
			}

			
			if(ptexture[i].name[0] == '#' && ptexture[i].name[1] == 'F')
			{
				switch (ptexture[i].name[3])
				{
					case 'S' : 
					{
						ptexture[i].index = g_MHTga[g_iTattooTex[SEX_FEMALE][HAND_SHORT]].texid;
						ptexture[i].height = 512;
						ptexture[i].width = 512;

						if(g_iTattooSmallEnable && g_iVideoMode)
						{
							int g_iTattooTest = g_iTattooSmallTex[SEX_FEMALE][HAND_SHORT];
							glEnable(GL_TEXTURE_2D);
							glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
							glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
						}
						break;
					}
					case 'L' : 
					{
						ptexture[i].index =g_MHTga[g_iTattooTex[SEX_FEMALE][HAND_LONG]].texid;
						ptexture[i].height = 512;
						ptexture[i].width = 512;
						if(g_iTattooSmallEnable && g_iVideoMode)
						{
							int g_iTattooTest = g_iTattooSmallTex[SEX_FEMALE][HAND_LONG];
							glEnable(GL_TEXTURE_2D);
							glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
							glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
						}
						break;
					}					
					default :
					{
						LogToFile("[纹身管理]:错误的纹理 %s(未知的类型)",ptexture[i].name[2]);
						break;
					}
				}
			}
			else if(ptexture[i].name[0] == '#' && ptexture[i].name[1] == 'M')
			{
				switch (ptexture[i].name[3])
				{
					case 'S' : 
					{
						ptexture[i].index = g_MHTga[g_iTattooTex[SEX_MALE][HAND_SHORT]].texid;
						ptexture[i].height = 512;
						ptexture[i].width = 512;
						if(g_iTattooSmallEnable && g_iVideoMode)
						{
							int g_iTattooTest = g_iTattooSmallTex[SEX_MALE][HAND_SHORT];
							glEnable(GL_TEXTURE_2D);
							glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
							glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
						}
						break;
					}
					case 'L' : 
					{
						ptexture[i].index = g_MHTga[g_iTattooTex[SEX_MALE][HAND_LONG]].texid;
						ptexture[i].height = 512;
						ptexture[i].width = 512;
						if(g_iTattooSmallEnable && g_iVideoMode)
						{
							int g_iTattooTest = g_iTattooSmallTex[SEX_MALE][HAND_LONG];
							glEnable(GL_TEXTURE_2D);
							glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
							glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
						}
						break;
					}					
					case 'O' : 
					{
						ptexture[i].index = g_MHTga[g_iTattooTex[SEX_MALE][HAND_ORIGIN]].texid;
						ptexture[i].height = 512;
						ptexture[i].width = 512;
						if(g_iTattooSmallEnable && g_iVideoMode)
						{
							int g_iTattooTest = g_iTattooSmallTex[SEX_MALE][HAND_ORIGIN];
							glEnable(GL_TEXTURE_2D);
							glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
							glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
						}
						break;
					}
					default :
					{
						LogToFile("[纹身管理]:错误的纹理 %s(未知的类型)",ptexture[i].name[2]);
						break;
					}
				}
			}
			else if(ptexture[i].name[0] == '#' && ptexture[i].name[1] == '5' && ptexture[i].name[11] == 'H')
			{
				ptexture[i].index = g_MHTga[g_iTattooTex[SEX_MALE][ptexture[i].name[31]?HAND_LONG:HAND_SHORT]].texid;
				ptexture[i].height = 512;
				ptexture[i].width = 512;
				if(g_iTattooSmallEnable && g_iVideoMode)
				{
					int g_iTattooTest = g_iTattooSmallTex[SEX_MALE][ptexture[i].name[31]?HAND_LONG:HAND_SHORT];
					glEnable(GL_TEXTURE_2D);
					glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
					glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
				}
			}
			else if(ptexture[i].name[0] == '#' && ptexture[i].name[1] == '5' && ptexture[i].name[11] == 'G')
			{
				ptexture[i].index = g_MHTga[g_iTattooTex[SEX_FEMALE][ptexture[i].name[28]?HAND_LONG:HAND_SHORT]].texid;
				ptexture[i].height = 512;
				ptexture[i].width = 512;
				if(g_iTattooSmallEnable && g_iVideoMode)
				{
					int g_iTattooTest = g_iTattooSmallTex[SEX_FEMALE][ptexture[i].name[28]?HAND_LONG:HAND_SHORT];
					glEnable(GL_TEXTURE_2D);
					glBindTexture(GL_TEXTURE_2D,ptexture[i].index);
					glTexSubImage2D(GL_TEXTURE_2D,0,0,508-g_MHTga[g_iTattooTest].height,g_MHTga[g_iTattooTest].width,g_MHTga[g_iTattooTest].height,GL_RGBA,GL_UNSIGNED_BYTE,g_MHTga[g_iTattooTest].data);
				}
			}
		}
	}
}
void CheckViewEntity(void)
{
	cl_entity_t *viewent;
	viewent = gEngfuncs.GetViewModel();
	//gEngfuncs.SetViewAngles();
	if (viewent)
	{
		if(viewent->model->name)
		{
			g_iCurWeapon = 0;
			
			strcpy(g_szCurWeapon, viewent->model->name + 9);
			g_szCurWeapon[strlen(g_szCurWeapon) - 4] = 0;

			if(strstr(g_szCurWeapon, "_2"))
			{
				g_szCurWeapon[strlen(g_szCurWeapon) - 2] = 0;
			}
			else
			{
				g_iShowCustomCrosshair = 0;
				g_iHideWeapon &= ~HIDEWEAPON_CROSSHAIR;
				g_fExtraAmmmoNextCanDraw = g_flTime + 0.1f;
			}

			char find[64];
			sprintf(find, "CSBTE_%s", g_szCurWeapon);
			wcscpy(g_szCurWeapon2, GetLangUni(find));

			g_iCurWeapon = FindWeaponData(g_szCurWeapon);
			g_ExtraAmmo_Draw = g_WeaponData[g_iCurWeapon].iAmmoDisplay;			
			
			if(strstr(viewent->model->name,"infinityex"))
			{
				g_iBTEWeapon = WPN_INFINITYEX;
			}
			else if(strstr(viewent->model->name,"m2.mdl"))
			{
				g_iBTEWeapon = 8;
			}
			else if(strstr(viewent->model->name,"sfmg"))
			{
				g_iBTEWeapon = WPN_SFMG;
			}
			else if(strstr(viewent->model->name,"sfsniper")) 
			{	
				g_iBTEWeapon = WPN_SFSNIPER;
			}
			else if(strstr(viewent->model->name,"cheytaclrrs"))
			{
				g_iBTEWeapon = WPN_M200;
			}
			else if(strstr(viewent->model->name,"janusmk5"))
			{
				g_iBTEWeapon = WPN_JANUS5;
			}
			else if(strstr(viewent->model->name,"janus3"))
			{
				g_iBTEWeapon = WPN_JANUS3;
			}
			else if(strstr(viewent->model->name,"janus11"))
			{
				g_iBTEWeapon = WPN_JANUS11;
			}
			else if(strstr(viewent->model->name,"janus7"))
			{
				g_iBTEWeapon = WPN_JANUS7;
			}
			else if(strstr(viewent->model->name,"janus"))
			{
				g_iBTEWeapon = WPN_JANUS;
			}
			else g_iBTEWeapon = 0;

		}		
	}		
}

