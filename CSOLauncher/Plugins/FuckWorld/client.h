#ifndef DLLAPI_H
#define DLLAPI_H

#define MAX_PLAYERS	32
#define WPN_INFINITYEX	1
#define WPN_SFMG 2
#define WPN_SFSNIPER 3
#define WPN_M200 4
#define WPN_JANUS5 5
#define WPN_BOW 6
#define WPN_JANUS7 7
#define WPN_JANUS 8
#define WPN_JANUS3 9
#define WPN_JANUS11 10
#define WPN_RAILCANON 11

extern int g_iBTEWeapon,g_iButton;
extern char g_szCurWeapon[32];
extern wchar_t g_szCurWeapon2[64];
extern int g_iCurWeapon;
extern int g_iAnim;
extern int g_iTattooSmallEnable;
extern char g_szWeaponSkin[20][20];
extern int g_iWeaponSkin[20][2],g_iSetupSkin;
extern int g_iWeaponStat,g_iButton;
extern int g_iWeaponStat,g_iButton,g_iBl3Muzz;
extern int g_iSpoce;


struct PlayerInfo
{
	int alive;
	cl_entity_s* info;
	float killtime;
	int team;
	float fZBTime;
	Vector vLastPos;
	int iHero;
	float fAudioTime;
	float fDeathTime;
	float fInfectTime;
};
struct extra_player_info_t 
{
	short frags;
	short deaths;
	int iFlag;
	int iFake;
};

extern cvar_t *pCvar_TipIcon,*pCvar_Name,*pCvar_Blood,*pCvar_DrawBink,*pCvar_DrawPanel,*pCvar_DrawScope,*pCvar_ScoreBoard,*pCvar_DrawMenu,*pCvar_ZombieMenu;
extern cvar_t *cl_righthand;
extern cvar_t *cl_dynamiccrosshair;
extern cvar_t *cl_crosshair_color;
extern cvar_t *cl_crosshair_size;
extern cvar_t *cl_crosshair_translucent;
extern cvar_t *cl_crosshair_type;
extern cvar_t *cl_gunsmoke;
extern PlayerInfo vPlayer[36];
extern extra_player_info_t  g_PlayerExtraInfo[MAX_PLAYERS+1];
extern char g_szLocation[2048];
extern bool g_bAlive;
extern int g_iWeapon, g_iWeaponBit, g_iHideWeapon;
extern SCREENINFO g_sScreenInfo;
extern Vector g_vecOrigin, g_vecAngles, g_vecEyePos,g_vecEye,g_vecEndPos,g_vecVAngles;
extern int g_tga_Scope,g_tga_Scope_Target,g_tga_custom_scope,g_tga_custom_scope_m200;

extern int g_iViewEntityBody, g_iViewEntityRenderMode, g_iViewEntityRenderFX, g_iViewEntityRenderAmout;
extern color24 g_byViewEntityRenderColor;

//ExtraAmmo
extern int g_ExtraAmmo,g_ExtraAmmoIndex;
extern HSPRITE g_ExtraAmmoHsprite;
extern float g_fMuzzleTime;

#define FLAG_HAND	(1<<31)
#define FLAG_MALE	(1<<30)
#define FLAG_FEMALE	(1<<29)

#define FLAG_SHORT	(1<<28)
#define FLAG_LONG	(1<<27)
#define FLAG_ORIGIN	(1<<26)

#define FLAG_UNCHANGE (1<<25)

#define SEX_MALE	0
#define SEX_FEMALE	1

#define HAND_LONG	0
#define HAND_SHORT	1
#define HAND_ORIGIN	2
extern char g_sTattoo[128];
extern char g_sTattooSmall[128];
void CheckViewEntity(void);
void RebuildTattoo(model_t *pModel);
void LoadTattoo(void);



#endif