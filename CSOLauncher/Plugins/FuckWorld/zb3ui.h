#ifndef _ZB3UI
#define _ZB3UI

void ZombieMod3UIInit(void);
void ZombieMod3UIRedraw(void);
void ZombieMod3UICheckTeam(int team);
void Zombie3UIParseData(int DataType, int iData);
void ZombieMod3UIParseIcon(char *pszName,int iSlot,int iType,int iData);
void ZombieMod3RetinaRedraw(void);
struct UIElement
{
	int r,g,b,a;
	float flStartDisplayTime;
	float flEndDisplayTime;
	int iType;
	int  iMH;
};
extern int g_zb3_tga_icon_supply,g_zb3_tga_icon_trap,g_zb3_spr_supply,g_isShowingZbMenu,g_zb3_menu_zb[10],g_zb_nvg;
extern float g_zb3_menu_time;
#endif